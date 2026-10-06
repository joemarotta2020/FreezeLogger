#include "PCH.h"
#include "SiteARenderBreaker.h"

#include "Config.h"
#include "RecoveryPolicy.h"
#include "SkyrimAnchors.h"
#include "Stats.h"

#include <TlHelp32.h>

namespace WorkerSpinLockFix::SiteARenderBreaker {

    namespace {
        constexpr std::uintptr_t kOffWake   = 0x58;
        constexpr std::uintptr_t kOffAck    = 0x60;
        constexpr std::uintptr_t kOffWorkId = 0x68;

        constexpr std::uint32_t kMaxDeepSignals = 12;
        constexpr std::uint64_t kMaxDeepRecoveryMs = 6000;
        constexpr std::uint32_t kVerifyMs = 500;
        constexpr std::uint32_t kVerifyStepMs = 25;
        constexpr std::uint32_t kUnwindGraceMs = 250;

        SafetyHookInline g_hook{};

        std::atomic<DWORD>          g_worker_tid{ 0 };
        std::atomic<bool>           g_in_wait{ false };
        std::atomic<std::uint64_t>  g_episode_seq{ 0 };
        std::atomic<std::uint64_t>  g_episode_start_ms{ 0 };
        std::atomic<std::uintptr_t> g_episode_singleton{ 0 };
        std::atomic<std::uintptr_t> g_episode_ack{ 0 };
        std::atomic<std::uint32_t>  g_episode_workid{ 0 };
        std::atomic<std::uintptr_t> g_episode_arg2{ 0 };
        std::atomic<std::uintptr_t> g_episode_arg3{ 0 };
        std::atomic<std::uintptr_t> g_episode_arg4{ 0 };

        std::thread       g_watchdog;
        std::atomic<bool> g_running{ false };

        bool          g_detect_only{ true };
        bool          g_diag{ false };
        std::uint32_t g_dwell_ms{ 5000 };
        std::uint32_t g_poll_ms{ 1000 };
        std::uint32_t g_recheck_ms{ 1500 };

        thread_local int tl_depth{ 0 };

        std::uint64_t NowMs() noexcept { return ::GetTickCount64(); }

        struct EVENT_BASIC_INFORMATION_ {
            LONG EventType;
            LONG EventState;
        };
        using NtQueryEventFn = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

        NtQueryEventFn LoadNtQueryEvent() noexcept {
            const HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
            if (!ntdll) return nullptr;
            return reinterpret_cast<NtQueryEventFn>(
                ::GetProcAddress(ntdll, "NtQueryEvent"));
        }

        int QueryEventState(std::uintptr_t a_handle) noexcept {
            if (a_handle == 0) return -1;
            static const auto pNtQueryEvent = LoadNtQueryEvent();
            if (!pNtQueryEvent) return -1;
            EVENT_BASIC_INFORMATION_ info{};
            ULONG returned = 0;
            const auto status = pNtQueryEvent(
                reinterpret_cast<HANDLE>(a_handle), 0,
                &info, sizeof(info), &returned);
            if (status != 0) return -1;
            return info.EventState ? 1 : 0;
        }

        struct SiteASnap {
            bool ok{ false };
            std::uintptr_t ack{ 0 };
            std::uintptr_t wake{ 0 };
            std::uint32_t workid{ 0 };
        };

        SiteASnap ReadSiteA(std::uintptr_t a_singleton) noexcept {
            SiteASnap s{};
            if (a_singleton == 0) return s;
            __try {
                s.wake = *reinterpret_cast<volatile std::uintptr_t*>(
                    a_singleton + kOffWake);
                s.ack = *reinterpret_cast<volatile std::uintptr_t*>(
                    a_singleton + kOffAck);
                s.workid = *reinterpret_cast<volatile std::uint32_t*>(
                    a_singleton + kOffWorkId);
                s.ok = true;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                s.ok = false;
            }
            return s;
        }

        struct ThreadSnap {
            bool ok{ false };
            DWORD tid{ 0 };
            std::uintptr_t rip{ 0 };
            std::uintptr_t rsp{ 0 };
            std::uintptr_t rbp{ 0 };
            std::uintptr_t rbx{ 0 };
            std::uintptr_t rsi{ 0 };
            std::uintptr_t rdi{ 0 };
            std::uintptr_t r12{ 0 };
            std::uintptr_t r13{ 0 };
            std::uintptr_t r14{ 0 };
            std::uintptr_t r15{ 0 };
            std::array<std::uintptr_t, 96> stack{};
            std::size_t stackCount{ 0 };
        };

        bool CaptureThread(DWORD a_tid, ThreadSnap& a_out) noexcept {
            a_out = {};
            a_out.tid = a_tid;
            if (a_tid == 0 || a_tid == ::GetCurrentThreadId()) return false;

            const HANDLE h = ::OpenThread(
                THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME |
                THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION,
                FALSE, a_tid);
            if (!h) return false;

            const DWORD previous = ::SuspendThread(h);
            if (previous == static_cast<DWORD>(-1)) {
                ::CloseHandle(h);
                return false;
            }

            CONTEXT ctx{};
            ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
            if (::GetThreadContext(h, &ctx)) {
                a_out.rip = static_cast<std::uintptr_t>(ctx.Rip);
                a_out.rsp = static_cast<std::uintptr_t>(ctx.Rsp);
                a_out.rbp = static_cast<std::uintptr_t>(ctx.Rbp);
                a_out.rbx = static_cast<std::uintptr_t>(ctx.Rbx);
                a_out.rsi = static_cast<std::uintptr_t>(ctx.Rsi);
                a_out.rdi = static_cast<std::uintptr_t>(ctx.Rdi);
                a_out.r12 = static_cast<std::uintptr_t>(ctx.R12);
                a_out.r13 = static_cast<std::uintptr_t>(ctx.R13);
                a_out.r14 = static_cast<std::uintptr_t>(ctx.R14);
                a_out.r15 = static_cast<std::uintptr_t>(ctx.R15);

                SIZE_T bytesRead = 0;
                if (a_out.rsp != 0 && ::ReadProcessMemory(
                        ::GetCurrentProcess(),
                        reinterpret_cast<const void*>(a_out.rsp),
                        a_out.stack.data(), sizeof(a_out.stack), &bytesRead))
                {
                    a_out.stackCount = static_cast<std::size_t>(
                        bytesRead / sizeof(std::uintptr_t));
                }
                a_out.ok = true;
            }

            ::ResumeThread(h);
            ::CloseHandle(h);
            return a_out.ok;
        }

        std::string ModuleName(std::uintptr_t a_address) {
            HMODULE module = nullptr;
            constexpr DWORD flags =
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT;
            if (!a_address || !::GetModuleHandleExW(
                    flags, reinterpret_cast<LPCWSTR>(a_address), &module) || !module)
            {
                return "<unmapped>";
            }
            std::array<char, MAX_PATH> path{};
            const DWORD n = ::GetModuleFileNameA(
                module, path.data(), static_cast<DWORD>(path.size()));
            if (!n) return "<module>";
            std::string name(path.data(), n);
            const auto slash = name.find_last_of("\\/");
            if (slash != std::string::npos) name.erase(0, slash + 1);
            return name;
        }

        bool IsInsideRenderTaskJoin(const ThreadSnap& a_s) noexcept {
            if (!a_s.ok) return false;
            const auto& anchors = SkyrimAnchors::Get();
            constexpr std::uintptr_t kRenderTaskSpan = 0xED;
            for (std::size_t i = 0; i < a_s.stackCount; ++i) {
                const auto ret = a_s.stack[i];
                if (ret >= anchors.renderTaskFn &&
                    ret < anchors.renderTaskFn + kRenderTaskSpan)
                {
                    return true;
                }
            }
            return false;
        }

        bool ReferencesHandle(const ThreadSnap& a_s, std::uintptr_t a_handle) noexcept {
            if (!a_s.ok || a_handle == 0) return false;
            if (a_s.rbx == a_handle || a_s.rsi == a_handle ||
                a_s.rdi == a_handle || a_s.r12 == a_handle ||
                a_s.r13 == a_handle || a_s.r14 == a_handle ||
                a_s.r15 == a_handle)
            {
                return true;
            }
            for (std::size_t i = 0; i < a_s.stackCount; ++i) {
                if (a_s.stack[i] == a_handle) return true;
            }
            return false;
        }

        void LogHandleReferences(
            std::string_view a_phase,
            std::uintptr_t a_handle,
            DWORD a_renderTid)
        {
            if (!g_diag || a_handle == 0) return;

            DWORD processHandles = 0;
            ::GetProcessHandleCount(::GetCurrentProcess(), &processHandles);
            logs::warn(
                "[SiteARenderBreaker.forensics] {} event=0x{:x} state={} "
                "process_handles={} -- scanning thread register/stack references",
                a_phase, a_handle, QueryEventState(a_handle), processHandles);

            const HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (snapshot == INVALID_HANDLE_VALUE) return;

            THREADENTRY32 te{};
            te.dwSize = sizeof(te);
            const DWORD pid = ::GetCurrentProcessId();
            const DWORD self = ::GetCurrentThreadId();
            std::uint32_t refs = 0;
            std::uint32_t captured = 0;

            if (::Thread32First(snapshot, &te)) {
                do {
                    if (te.th32OwnerProcessID != pid || te.th32ThreadID == self) {
                        te.dwSize = sizeof(te);
                        continue;
                    }
                    if (captured++ >= 256) break;

                    ThreadSnap s{};
                    if (CaptureThread(te.th32ThreadID, s) && ReferencesHandle(s, a_handle)) {
                        ++refs;
                        logs::warn(
                            "[SiteARenderBreaker.forensics] {} event 0x{:x} "
                            "referenced by TID={}{} RIP=0x{:x} ({}) "
                            "RDI=0x{:x} R14=0x{:x}",
                            a_phase, a_handle, s.tid,
                            s.tid == a_renderTid ? " [render]" : "",
                            s.rip, ModuleName(s.rip), s.rdi, s.r14);
                        if (refs >= 16) break;
                    }
                    te.dwSize = sizeof(te);
                } while (::Thread32Next(snapshot, &te));
            }
            ::CloseHandle(snapshot);

            logs::warn(
                "[SiteARenderBreaker.forensics] {} event=0x{:x} reference_scan "
                "matches={} threads_examined={}",
                a_phase, a_handle, refs, captured);
        }

        bool SeenHandle(
            const std::array<std::uintptr_t, kMaxDeepSignals>& a_seen,
            std::uint32_t a_count,
            std::uintptr_t a_handle) noexcept
        {
            for (std::uint32_t i = 0; i < a_count; ++i) {
                if (a_seen[i] == a_handle) return true;
            }
            return false;
        }

        const char* DecisionName(RecoveryPolicy::Decision a_d) noexcept {
            switch (a_d) {
            case RecoveryPolicy::Decision::Complete: return "complete";
            case RecoveryPolicy::Decision::Continue: return "continue";
            case RecoveryPolicy::Decision::AbortNoProgress: return "no-progress";
            case RecoveryPolicy::Decision::AbortRepeatedHandle: return "repeated-handle";
            case RecoveryPolicy::Decision::AbortProtocolChanged: return "protocol-changed";
            }
            return "unknown";
        }

        bool TryRecoverDeepSubtaskWait(
            std::uint64_t a_seq,
            std::uintptr_t a_ackEntry,
            std::uint32_t a_workIdEntry)
        {
            if (REL::Module::GetRuntime() != REL::Module::Runtime::SE) {
                logs::error(
                    "[SiteARenderBreaker] deep recovery is field-validated only "
                    "for SE 1.5.97; refusing active deep SetEvent on this runtime.");
                return false;
            }

            const auto recoveryStart = NowMs();
            std::array<std::uintptr_t, kMaxDeepSignals> seen{};
            std::uint32_t signalCount = 0;
            const DWORD renderTid = g_worker_tid.load(std::memory_order_relaxed);

            while (RecoveryPolicy::WithinBudget(
                signalCount, NowMs() - recoveryStart,
                kMaxDeepSignals, kMaxDeepRecoveryMs))
            {
                if (!g_in_wait.load(std::memory_order_acquire) ||
                    g_episode_seq.load(std::memory_order_relaxed) != a_seq)
                {
                    return true;
                }

                ThreadSnap beforeSnap{};
                if (!CaptureThread(renderTid, beforeSnap) ||
                    !IsInsideRenderTaskJoin(beforeSnap))
                {
                    logs::error(
                        "[SiteARenderBreaker] DEEP RECOVERY ABORTED: render thread "
                        "is no longer at the validated id-34557 wait shape "
                        "(episode={}).", a_seq);
                    return false;
                }

                const auto deepHandle = beforeSnap.rdi;
                if (deepHandle == 0 || beforeSnap.r14 != deepHandle) {
                    logs::error(
                        "[SiteARenderBreaker] DEEP RECOVERY ABORTED: RDI/R14 do "
                        "not identify one stable wait event (RDI=0x{:x}, "
                        "R14=0x{:x}, episode={}).",
                        beforeSnap.rdi, beforeSnap.r14, a_seq);
                    return false;
                }

                const auto singleton =
                    g_episode_singleton.load(std::memory_order_relaxed);
                const auto protocol = ReadSiteA(singleton);
                if (!protocol.ok || protocol.workid != a_workIdEntry ||
                    protocol.ack != a_ackEntry)
                {
                    logs::error(
                        "[SiteARenderBreaker] DEEP RECOVERY ABORTED: Singleton-A "
                        "protocol changed before signal (entry workid={}, now={}, "
                        "entry ack=0x{:x}, now=0x{:x}, episode={}).",
                        a_workIdEntry, protocol.workid,
                        a_ackEntry, protocol.ack, a_seq);
                    return false;
                }

                if (deepHandle == a_ackEntry || deepHandle == protocol.wake ||
                    QueryEventState(deepHandle) != 0 ||
                    SeenHandle(seen, signalCount, deepHandle))
                {
                    logs::error(
                        "[SiteARenderBreaker] DEEP RECOVERY ABORTED: candidate "
                        "0x{:x} failed safety gate (ack=0x{:x}, wake=0x{:x}, "
                        "state={}, seen={}, episode={}).",
                        deepHandle, a_ackEntry, protocol.wake,
                        QueryEventState(deepHandle),
                        SeenHandle(seen, signalCount, deepHandle), a_seq);
                    return false;
                }

                if (g_diag) {
                    logs::warn(
                        "[SiteARenderBreaker.forensics] PRE-SIGNAL episode={} "
                        "attempt={} workid={} deep=0x{:x} render_RIP=0x{:x} ({})",
                        a_seq, signalCount + 1, a_workIdEntry, deepHandle,
                        beforeSnap.rip, ModuleName(beforeSnap.rip));
                    LogHandleReferences("PRE-SIGNAL", deepHandle, renderTid);
                }

                logs::warn(
                    "[SiteARenderBreaker] DEEP RECOVERY attempt {}/{}: validated "
                    "sub-task event 0x{:x}; signaling it (episode={}, elapsed={} ms).",
                    signalCount + 1, kMaxDeepSignals, deepHandle,
                    a_seq, NowMs() - recoveryStart);

                if (!::SetEvent(reinterpret_cast<HANDLE>(deepHandle))) {
                    logs::error(
                        "[SiteARenderBreaker] DEEP RECOVERY FAILED: SetEvent(0x{:x}) "
                        "returned false (GetLastError={}, episode={}).",
                        deepHandle, ::GetLastError(), a_seq);
                    return false;
                }
                seen[signalCount++] = deepHandle;

                bool episodeEnded = false;
                for (std::uint32_t waited = 0;
                     waited < kVerifyMs && g_running.load(std::memory_order_relaxed);
                     waited += kVerifyStepMs)
                {
                    std::this_thread::sleep_for(
                        std::chrono::milliseconds(kVerifyStepMs));
                    if (!g_in_wait.load(std::memory_order_acquire) ||
                        g_episode_seq.load(std::memory_order_relaxed) != a_seq)
                    {
                        episodeEnded = true;
                        break;
                    }
                }

                if (episodeEnded) {
                    logs::warn(
                        "[SiteARenderBreaker] VERIFIED DEEP RELEASE: id 34557 "
                        "returned after {} progress-gated signal(s), last=0x{:x}, "
                        "elapsed={} ms (episode={}).",
                        signalCount, deepHandle,
                        NowMs() - recoveryStart, a_seq);
                    return true;
                }

                ThreadSnap afterSnap{};
                if (!CaptureThread(renderTid, afterSnap)) {
                    logs::error(
                        "[SiteARenderBreaker] DEEP RECOVERY FAILED: same episode "
                        "remains active but post-signal render context is unavailable.");
                    return false;
                }

                if (!IsInsideRenderTaskJoin(afterSnap)) {
                    for (std::uint32_t waited = 0;
                         waited < kUnwindGraceMs &&
                         g_running.load(std::memory_order_relaxed);
                         waited += kVerifyStepMs)
                    {
                        std::this_thread::sleep_for(
                            std::chrono::milliseconds(kVerifyStepMs));
                        if (!g_in_wait.load(std::memory_order_acquire) ||
                            g_episode_seq.load(std::memory_order_relaxed) != a_seq)
                        {
                            logs::warn(
                                "[SiteARenderBreaker] VERIFIED DEEP RELEASE after "
                                "unwind grace; signals={} episode={}",
                                signalCount, a_seq);
                            return true;
                        }
                    }
                    logs::error(
                        "[SiteARenderBreaker] DEEP RECOVERY ABORTED: episode {} is "
                        "still marked active but render left the validated join "
                        "shape; refusing another signal.", a_seq);
                    return false;
                }

                const auto afterProtocol = ReadSiteA(singleton);
                RecoveryPolicy::DeepProgress before{
                    true, a_seq, a_workIdEntry, a_ackEntry, deepHandle };
                RecoveryPolicy::DeepProgress after{
                    g_in_wait.load(std::memory_order_acquire),
                    g_episode_seq.load(std::memory_order_relaxed),
                    afterProtocol.ok ? afterProtocol.workid : 0xffffffffu,
                    afterProtocol.ok ? afterProtocol.ack : 0,
                    afterSnap.rdi };

                const bool nextSeen = SeenHandle(
                    seen, signalCount, after.deep_handle);
                const auto decision = RecoveryPolicy::Evaluate(
                    before, after, nextSeen);

                if (decision == RecoveryPolicy::Decision::Complete) {
                    return true;
                }
                if (decision != RecoveryPolicy::Decision::Continue) {
                    logs::error(
                        "[SiteARenderBreaker] DEEP RECOVERY ABORTED by progress "
                        "gate: reason={} old=0x{:x} new=0x{:x} workid {}->{} "
                        "ack 0x{:x}->0x{:x} episode={}",
                        DecisionName(decision), deepHandle, after.deep_handle,
                        a_workIdEntry, after.workid,
                        a_ackEntry, after.outer_ack, a_seq);
                    return false;
                }

                logs::warn(
                    "[SiteARenderBreaker] PROGRESS VERIFIED: signal 0x{:x} moved "
                    "render join to new unsignaled candidate 0x{:x}; protocol is "
                    "unchanged, continuing within bounded budget (episode={}).",
                    deepHandle, after.deep_handle, a_seq);

                if (g_diag) {
                    LogHandleReferences("NEXT-CANDIDATE", after.deep_handle, renderTid);
                }
            }

            logs::error(
                "[SiteARenderBreaker] DEEP RECOVERY STOPPED AT SAFETY BUDGET: "
                "signals={} max_signals={} elapsed={} ms max_ms={} while episode "
                "{} remained active. Refusing further forced completions.",
                signalCount, kMaxDeepSignals, NowMs() - recoveryStart,
                kMaxDeepRecoveryMs, a_seq);
            return false;
        }

        std::uintptr_t __fastcall Detour_RenderTask(
            std::uintptr_t a1, std::uintptr_t a2,
            std::uintptr_t a3, std::uintptr_t a4)
        {
            const DWORD tid = ::GetCurrentThreadId();
            DWORD expected = 0;
            g_worker_tid.compare_exchange_strong(
                expected, tid, std::memory_order_relaxed);
            const bool isWorker =
                tid == g_worker_tid.load(std::memory_order_relaxed);

            if (isWorker && tl_depth++ == 0) {
                const auto snap = ReadSiteA(a1);
                if (snap.ok && snap.ack != 0) {
                    g_episode_singleton.store(a1, std::memory_order_relaxed);
                    g_episode_ack.store(snap.ack, std::memory_order_relaxed);
                    g_episode_workid.store(snap.workid, std::memory_order_relaxed);
                    g_episode_arg2.store(a2, std::memory_order_relaxed);
                    g_episode_arg3.store(a3, std::memory_order_relaxed);
                    g_episode_arg4.store(a4, std::memory_order_relaxed);
                    g_episode_start_ms.store(NowMs(), std::memory_order_relaxed);
                    g_episode_seq.fetch_add(1, std::memory_order_relaxed);
                    g_in_wait.store(true, std::memory_order_release);
                }
            }

            const auto ret =
                g_hook.unsafe_call<std::uintptr_t>(a1, a2, a3, a4);

            if (isWorker && --tl_depth == 0) {
                g_in_wait.store(false, std::memory_order_release);
            }
            return ret;
        }

        void WatchdogLoop() {
            std::uint64_t lastHandledSeq = 0;

            while (g_running.load(std::memory_order_relaxed)) {
                std::this_thread::sleep_for(std::chrono::milliseconds(g_poll_ms));
                if (!g_running.load(std::memory_order_relaxed)) break;
                if (!g_in_wait.load(std::memory_order_acquire)) continue;

                const auto seq = g_episode_seq.load(std::memory_order_relaxed);
                const auto start =
                    g_episode_start_ms.load(std::memory_order_relaxed);
                const auto singleton =
                    g_episode_singleton.load(std::memory_order_relaxed);
                const auto ackEntry =
                    g_episode_ack.load(std::memory_order_relaxed);
                const auto workIdEntry =
                    g_episode_workid.load(std::memory_order_relaxed);

                if (seq == lastHandledSeq || NowMs() - start < g_dwell_ms) continue;
                if (!g_in_wait.load(std::memory_order_acquire) ||
                    g_episode_seq.load(std::memory_order_relaxed) != seq)
                    continue;

                const auto s1 = ReadSiteA(singleton);
                if (!s1.ok) continue;

                std::this_thread::sleep_for(
                    std::chrono::milliseconds(g_recheck_ms));
                if (!g_running.load(std::memory_order_relaxed)) break;
                if (!g_in_wait.load(std::memory_order_acquire) ||
                    g_episode_seq.load(std::memory_order_relaxed) != seq)
                    continue;

                const auto s2 = ReadSiteA(singleton);
                if (!s2.ok) continue;

                const bool zeroProgress =
                    s1.workid == s2.workid && s1.ack == s2.ack &&
                    s2.workid == workIdEntry && s2.ack == ackEntry;
                if (!zeroProgress) {
                    if (g_diag) {
                        logs::info(
                            "[SiteARenderBreaker.diag] join parked {} ms but "
                            "Singleton-A changed; standing down.", NowMs() - start);
                    }
                    continue;
                }

                const int ackState = QueryEventState(ackEntry);
                if (ackState == 1) {
                    if (g_diag) {
                        logs::info(
                            "[SiteARenderBreaker.diag] outer ack already signaled; "
                            "refusing deep recovery for episode {}.", seq);
                    }
                    continue;
                }

                lastHandledSeq = seq;
                Stats::OnSiteARenderStuck();
                const auto dwell = NowMs() - start;

                DWORD processHandles = 0;
                ::GetProcessHandleCount(::GetCurrentProcess(), &processHandles);
                logs::warn(
                    "[SiteARenderBreaker] STUCK episode={} dwell={} ms workid={} "
                    "outer_ack=0x{:x}(state={}) process_handles={}.",
                    seq, dwell, workIdEntry, ackEntry, ackState, processHandles);

                if (g_diag) {
                    logs::warn(
                        "[SiteARenderBreaker.forensics] entry singleton=0x{:x} "
                        "arg2=0x{:x} arg3=0x{:x} arg4=0x{:x} render_tid={}",
                        singleton,
                        g_episode_arg2.load(std::memory_order_relaxed),
                        g_episode_arg3.load(std::memory_order_relaxed),
                        g_episode_arg4.load(std::memory_order_relaxed),
                        g_worker_tid.load(std::memory_order_relaxed));
                }

                if (g_detect_only) {
                    logs::warn(
                        "[SiteARenderBreaker] detect_only: WOULD attempt "
                        "progress-gated deep recovery (max {} signals / {} ms).",
                        kMaxDeepSignals, kMaxDeepRecoveryMs);
                    continue;
                }

                const bool released = TryRecoverDeepSubtaskWait(
                    seq, ackEntry, workIdEntry);
                if (released) {
                    Stats::OnSiteARenderReleased();
                } else {
                    Stats::OnSiteARenderReleaseFailed();
                    logs::error(
                        "[SiteARenderBreaker] RECOVERY FAILED/ABORTED for episode "
                        "{}; safety gates prevented any unverified continuation.",
                        seq);
                }
            }
        }
    }

    bool Install() {
        const auto& cfg = Config::Get();
        if (!cfg.sar_enabled) {
            logs::info("[SiteARenderBreaker] disabled by config.");
            return false;
        }
        if (!SkyrimAnchors::AvailableSiteARender()) {
            logs::warn(
                "[SiteARenderBreaker] id-34557 anchor unavailable; module not armed.");
            return false;
        }

        const auto& a = SkyrimAnchors::Get();
        g_detect_only = cfg.sar_detect_only;
        g_diag = cfg.sar_diagnostic_logging;
        g_dwell_ms = cfg.sar_dwell_threshold_ms;
        g_poll_ms = cfg.sar_poll_interval_ms == 0
            ? 1000 : cfg.sar_poll_interval_ms;
        g_recheck_ms = cfg.sar_recheck_window_ms;

        try {
            auto hook = safetyhook::create_inline(
                reinterpret_cast<void*>(a.renderTaskFn),
                reinterpret_cast<void*>(&Detour_RenderTask));
            if (!hook) {
                logs::critical(
                    "[SiteARenderBreaker] safetyhook install failed at 0x{:x}.",
                    a.renderTaskFn);
                return false;
            }
            g_hook = std::move(hook);
        } catch (const std::exception& e) {
            logs::critical("[SiteARenderBreaker] install threw: {}", e.what());
            return false;
        }

        g_running.store(true, std::memory_order_relaxed);
        g_watchdog = std::thread(WatchdogLoop);
        g_watchdog.detach();

        logs::info(
            "[SiteARenderBreaker] armed v2.6.4. id34557 @0x{:x} (+0x{:x}), "
            "mode={}, dwell_ms={}, poll_ms={}, recheck_ms={}, deep_budget={} "
            "signals/{} ms, diag={}.",
            a.renderTaskFn, a.renderTaskFnRVA,
            g_detect_only ? "DETECT-ONLY" : "ACTIVE+PROGRESS-GATE",
            g_dwell_ms, g_poll_ms, g_recheck_ms,
            kMaxDeepSignals, kMaxDeepRecoveryMs,
            g_diag ? "ON" : "OFF");
        return true;
    }

    void Stop() {
        g_running.store(false, std::memory_order_relaxed);
    }

}
