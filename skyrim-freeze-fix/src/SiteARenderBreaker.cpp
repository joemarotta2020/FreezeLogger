#include "PCH.h"
#include "SiteARenderBreaker.h"

#include "Config.h"
#include "SkyrimAnchors.h"
#include "Stats.h"

#include <TlHelp32.h>

namespace WorkerSpinLockFix::SiteARenderBreaker {

    namespace {

        // ----- Singleton-A field offsets (SE 1.5.97) ----------------------
        // Identical layout to the main-side Site-A: id 34567 (the render
        // worker loop that owns this singleton) reads [+0x58] worker-wake,
        // [+0x60] worker-ack, [+0x6c] pending, exactly like id 34554.
        constexpr std::uintptr_t kOffWake   = 0x58;  // worker-wake (auto)
        constexpr std::uintptr_t kOffAck    = 0x60;  // worker-ack  (manual)
        constexpr std::uintptr_t kOffWorkId = 0x68;  // work-id

        // ----- hook ---------------------------------------------------------
        // id 34557: the per-task cloth-join function. It receives the
        // Singleton-A instance in rcx (first arg) and `mov rbp,rcx` at entry.
        // We forward the first four integer registers verbatim so the wrap is
        // transparent regardless of the engine's true arity, and forward rax
        // back to the caller.
        SafetyHookInline g_hook{};

        // ----- episode state (single-producer: the render/worker thread) ---
        std::atomic<DWORD>          g_worker_tid{ 0 };
        std::atomic<bool>           g_in_wait{ false };
        std::atomic<std::uint64_t>  g_episode_seq{ 0 };       // ++ per outer entry
        std::atomic<std::uint64_t>  g_episode_start_ms{ 0 };
        std::atomic<std::uintptr_t> g_episode_singleton{ 0 }; // Singleton-A inst
        std::atomic<std::uintptr_t> g_episode_ack{ 0 };       // worker-ack handle
        std::atomic<std::uint32_t>  g_episode_workid{ 0 };
        std::atomic<std::uintptr_t> g_episode_arg2{ 0 };
        std::atomic<std::uintptr_t> g_episode_arg3{ 0 };
        std::atomic<std::uintptr_t> g_episode_arg4{ 0 };

        // ----- watchdog -----------------------------------------------------
        std::thread       g_watchdog;
        std::atomic<bool> g_running{ false };

        // ----- config snapshot ----------------------------------------------
        bool          g_detect_only{ true };
        bool          g_diag{ false };
        std::uint32_t g_dwell_ms{ 5000 };
        std::uint32_t g_poll_ms{ 1000 };
        std::uint32_t g_recheck_ms{ 1500 };

        // id 34557 reentrancy depth on the worker thread. Only the pinned
        // worker ever touches this (the wrap guards on tid), so a
        // thread_local int is race-free and keeps nested calls in one episode.
        thread_local int tl_depth{ 0 };

        std::uint64_t NowMs() noexcept { return ::GetTickCount64(); }

        // ----- ntdll!NtQueryEvent (read-only event-state probe) ------------
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

        // -1 = unknown / not an event, 0 = not signaled, 1 = signaled.
        int QueryEventState(std::uintptr_t a_handle) noexcept {
            if (a_handle == 0) return -1;
            static const auto pNtQueryEvent = LoadNtQueryEvent();
            if (!pNtQueryEvent) return -1;
            EVENT_BASIC_INFORMATION_ info{};
            ULONG returned = 0;
            const auto status = pNtQueryEvent(
                reinterpret_cast<HANDLE>(a_handle), /*EventBasicInformation=*/0,
                &info, sizeof(info), &returned);
            if (status != 0) return -1;
            return info.EventState ? 1 : 0;
        }

        // ----- SEH-guarded Singleton-A snapshot ----------------------------
        // POD-only so the noexcept SEH frame holds no objects with
        // destructors. On any fault, ok stays false and the watchdog stands
        // down (never act on memory we could not read). Reads from the
        // singleton instance captured at episode entry.
        struct SiteASnap {
            bool           ok;
            std::uintptr_t ack;
            std::uintptr_t wake;
            std::uint32_t  workid;
        };

        SiteASnap ReadSiteA(std::uintptr_t a_singleton) noexcept {
            SiteASnap s{};
            if (a_singleton == 0) return s;  // ok == false
            __try {
                s.wake   = *reinterpret_cast<volatile std::uintptr_t*>(a_singleton + kOffWake);
                s.ack    = *reinterpret_cast<volatile std::uintptr_t*>(a_singleton + kOffAck);
                s.workid = *reinterpret_cast<volatile std::uint32_t*>(a_singleton + kOffWorkId);
                s.ok = true;
                return s;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                s.ok = false;
                return s;
            }
        }

        // ----- stuck-episode forensics --------------------------------------
        // Diagnostic-only. These helpers run only AFTER the normal dwell +
        // zero-progress gate has proven a Site-A render join is stuck, and
        // only when site_a_render_breaker.diagnostic_logging=true.
        //
        // We deliberately avoid DbgHelp here. Instead we capture each thread's
        // register context plus a bounded slice of its stack and identify
        // executable return-address candidates by module. This keeps the
        // diagnostic build self-contained while still exposing which worker /
        // plugin code is present behind the stuck join.
        struct ThreadForensicSnap {
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
            std::array<std::uintptr_t, 96> stackWords{};
            std::size_t stackWordCount{ 0 };
        };

        bool CaptureThreadForensics(DWORD a_tid, ThreadForensicSnap& a_out) noexcept {
            a_out = {};
            a_out.tid = a_tid;
            if (a_tid == 0 || a_tid == ::GetCurrentThreadId()) return false;

            const HANDLE h = ::OpenThread(
                THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME |
                    THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION,
                FALSE, a_tid);
            if (!h) return false;

            const DWORD prev = ::SuspendThread(h);
            if (prev == static_cast<DWORD>(-1)) {
                ::CloseHandle(h);
                return false;
            }

            CONTEXT ctx{};
            ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
            const bool gotContext = ::GetThreadContext(h, &ctx) != 0;
            if (gotContext) {
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
                if (a_out.rsp != 0 &&
                    ::ReadProcessMemory(
                        ::GetCurrentProcess(),
                        reinterpret_cast<const void*>(a_out.rsp),
                        a_out.stackWords.data(),
                        sizeof(a_out.stackWords),
                        &bytesRead))
                {
                    a_out.stackWordCount =
                        static_cast<std::size_t>(bytesRead / sizeof(std::uintptr_t));
                }
                a_out.ok = true;
            }

            ::ResumeThread(h);
            ::CloseHandle(h);
            return a_out.ok;
        }

        bool IsExecutableAddress(std::uintptr_t a_addr) noexcept {
            if (a_addr == 0) return false;
            MEMORY_BASIC_INFORMATION mbi{};
            if (::VirtualQuery(
                    reinterpret_cast<const void*>(a_addr), &mbi, sizeof(mbi)) !=
                sizeof(mbi))
            {
                return false;
            }
            if (mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_GUARD) != 0 ||
                (mbi.Protect & PAGE_NOACCESS) != 0)
            {
                return false;
            }
            const DWORD p = mbi.Protect & 0xffu;
            return p == PAGE_EXECUTE ||
                   p == PAGE_EXECUTE_READ ||
                   p == PAGE_EXECUTE_READWRITE ||
                   p == PAGE_EXECUTE_WRITECOPY;
        }

        std::string ModuleNameForAddress(
            std::uintptr_t a_addr, std::uintptr_t& a_base)
        {
            a_base = 0;
            if (a_addr == 0) return "<null>";

            HMODULE mod = nullptr;
            constexpr DWORD flags =
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT;
            if (!::GetModuleHandleExW(
                    flags,
                    reinterpret_cast<LPCWSTR>(a_addr),
                    &mod) || !mod)
            {
                return "<unmapped>";
            }

            a_base = reinterpret_cast<std::uintptr_t>(mod);
            std::array<char, MAX_PATH> path{};
            const DWORD n = ::GetModuleFileNameA(
                mod, path.data(), static_cast<DWORD>(path.size()));
            if (n == 0) return "<module>";

            std::string name(path.data(), n);
            const auto slash = name.find_last_of("\\/");
            if (slash != std::string::npos) name.erase(0, slash + 1);
            return name;
        }

        void LogPointerWindow(
            std::string_view a_label, std::uintptr_t a_addr)
        {
            if (a_addr < 0x10000) return;

            std::array<std::uintptr_t, 12> q{};
            SIZE_T bytesRead = 0;
            if (!::ReadProcessMemory(
                    ::GetCurrentProcess(),
                    reinterpret_cast<const void*>(a_addr),
                    q.data(), sizeof(q), &bytesRead) ||
                bytesRead < sizeof(std::uintptr_t))
            {
                return;
            }

            const auto n = static_cast<std::size_t>(
                bytesRead / sizeof(std::uintptr_t));
            logs::warn(
                "[SiteARenderBreaker.forensics] {} @0x{:x}: "
                "q0=0x{:x} q1=0x{:x} q2=0x{:x} q3=0x{:x} "
                "q4=0x{:x} q5=0x{:x} q6=0x{:x} q7=0x{:x} "
                "q8=0x{:x} q9=0x{:x} q10=0x{:x} q11=0x{:x} "
                "(read {} qwords)",
                a_label, a_addr,
                q[0], q[1], q[2], q[3], q[4], q[5],
                q[6], q[7], q[8], q[9], q[10], q[11], n);
        }

        void LogThreadForensics(
            std::string_view a_phase, const ThreadForensicSnap& a_s,
            bool a_logStack)
        {
            if (!a_s.ok) {
                logs::warn(
                    "[SiteARenderBreaker.forensics] {} TID={} "
                    "<context capture failed>",
                    a_phase, a_s.tid);
                return;
            }

            std::uintptr_t base = 0;
            const auto module = ModuleNameForAddress(a_s.rip, base);
            logs::warn(
                "[SiteARenderBreaker.forensics] {} TID={} "
                "RIP=0x{:x} ({}+0x{:x}) RSP=0x{:x} RBP=0x{:x}",
                a_phase, a_s.tid, a_s.rip, module,
                base ? (a_s.rip - base) : 0, a_s.rsp, a_s.rbp);
            logs::warn(
                "[SiteARenderBreaker.forensics] {} TID={} "
                "RBX=0x{:x} RSI=0x{:x} RDI=0x{:x} "
                "R12=0x{:x} R13=0x{:x} R14=0x{:x} R15=0x{:x}",
                a_phase, a_s.tid, a_s.rbx, a_s.rsi, a_s.rdi,
                a_s.r12, a_s.r13, a_s.r14, a_s.r15);

            if (!a_logStack) return;

            std::size_t emitted = 0;
            std::uintptr_t last = 0;
            for (std::size_t i = 0;
                 i < a_s.stackWordCount && emitted < 12; ++i)
            {
                const auto candidate = a_s.stackWords[i];
                if (candidate == last || !IsExecutableAddress(candidate)) {
                    continue;
                }

                std::uintptr_t candBase = 0;
                const auto candModule =
                    ModuleNameForAddress(candidate, candBase);
                if (candBase == 0) continue;

                logs::warn(
                    "[SiteARenderBreaker.forensics] {} TID={} "
                    "stack+0x{:x} -> 0x{:x} ({}+0x{:x})",
                    a_phase, a_s.tid,
                    i * sizeof(std::uintptr_t), candidate,
                    candModule, candidate - candBase);
                last = candidate;
                ++emitted;
            }
        }

        void LogEventHandleCandidates(
            std::string_view a_phase, const ThreadForensicSnap& a_s)
        {
            if (!a_s.ok) return;

            struct Candidate {
                const char* name;
                std::uintptr_t value;
            };
            const std::array<Candidate, 7> regs{{
                { "RBX", a_s.rbx }, { "RSI", a_s.rsi },
                { "RDI", a_s.rdi }, { "R12", a_s.r12 },
                { "R13", a_s.r13 }, { "R14", a_s.r14 },
                { "R15", a_s.r15 }
            }};

            std::array<std::uintptr_t, 128> seen{};
            std::size_t seenCount = 0;
            const auto logCandidate = [&](std::string_view a_name,
                                          std::uintptr_t a_value) {
                if (a_value == 0) return;
                for (std::size_t i = 0; i < seenCount; ++i) {
                    if (seen[i] == a_value) return;
                }
                if (seenCount < seen.size()) {
                    seen[seenCount++] = a_value;
                }

                const int state = QueryEventState(a_value);
                if (state >= 0) {
                    logs::warn(
                        "[SiteARenderBreaker.forensics] {} event-handle "
                        "candidate {}=0x{:x} state={}",
                        a_phase, a_name, a_value, state);
                }
            };

            for (const auto& c : regs) {
                logCandidate(c.name, c.value);
            }

            for (std::size_t i = 0; i < a_s.stackWordCount; ++i) {
                const auto value = a_s.stackWords[i];
                const int state = QueryEventState(value);
                if (state < 0) continue;

                bool duplicate = false;
                for (std::size_t j = 0; j < seenCount; ++j) {
                    if (seen[j] == value) {
                        duplicate = true;
                        break;
                    }
                }
                if (duplicate) continue;
                if (seenCount < seen.size()) {
                    seen[seenCount++] = value;
                }

                logs::warn(
                    "[SiteARenderBreaker.forensics] {} event-handle "
                    "candidate stack+0x{:x}=0x{:x} state={}",
                    a_phase, i * sizeof(std::uintptr_t), value, state);
            }
        }

        void DumpAllThreadForensics(DWORD a_renderTid) {
            const HANDLE snap =
                ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (snap == INVALID_HANDLE_VALUE) {
                logs::warn(
                    "[SiteARenderBreaker.forensics] thread enumeration "
                    "failed: GetLastError={}", ::GetLastError());
                return;
            }

            THREADENTRY32 te{};
            te.dwSize = sizeof(te);
            std::uint32_t visited = 0;
            std::uint32_t captured = 0;
            const DWORD pid = ::GetCurrentProcessId();
            const DWORD selfTid = ::GetCurrentThreadId();

            if (::Thread32First(snap, &te)) {
                do {
                    if (te.th32OwnerProcessID != pid ||
                        te.th32ThreadID == selfTid)
                    {
                        te.dwSize = sizeof(te);
                        continue;
                    }
                    if (++visited > 256) break;

                    ThreadForensicSnap s{};
                    if (CaptureThreadForensics(te.th32ThreadID, s)) {
                        ++captured;
                        const bool isRender = te.th32ThreadID == a_renderTid;
                        LogThreadForensics(
                            isRender ? "PRE/render" : "PRE/thread",
                            s, true);
                    }
                    te.dwSize = sizeof(te);
                } while (::Thread32Next(snap, &te));
            }
            ::CloseHandle(snap);

            logs::warn(
                "[SiteARenderBreaker.forensics] PRE thread snapshot complete: "
                "visited={} captured={} render_tid={}",
                visited, captured, a_renderTid);
        }

        void DumpStuckEpisodeForensics(
            std::uint64_t a_seq,
            std::uintptr_t a_singleton,
            std::uintptr_t a_ack,
            std::uint32_t a_workid,
            std::uintptr_t a_arg2,
            std::uintptr_t a_arg3,
            std::uintptr_t a_arg4)
        {
            const DWORD renderTid =
                g_worker_tid.load(std::memory_order_relaxed);
            const auto singletonSnap = ReadSiteA(a_singleton);

            logs::warn(
                "[SiteARenderBreaker.forensics] ===== STUCK EPISODE {} =====",
                a_seq);
            logs::warn(
                "[SiteARenderBreaker.forensics] singleton=0x{:x} "
                "entry_ack=0x{:x} entry_workid={} "
                "arg2=0x{:x} arg3=0x{:x} arg4=0x{:x} render_tid={}",
                a_singleton, a_ack, a_workid,
                a_arg2, a_arg3, a_arg4, renderTid);

            if (singletonSnap.ok) {
                logs::warn(
                    "[SiteARenderBreaker.forensics] Singleton-A now: "
                    "wake=0x{:x}(state={}) ack=0x{:x}(state={}) workid={}",
                    singletonSnap.wake, QueryEventState(singletonSnap.wake),
                    singletonSnap.ack, QueryEventState(singletonSnap.ack),
                    singletonSnap.workid);
            }

            LogPointerWindow("Singleton-A", a_singleton);
            LogPointerWindow("arg2", a_arg2);
            LogPointerWindow("arg3", a_arg3);
            LogPointerWindow("arg4", a_arg4);

            ThreadForensicSnap render{};
            if (CaptureThreadForensics(renderTid, render)) {
                LogThreadForensics("PRE/render-focus", render, true);
                LogEventHandleCandidates("PRE/render-focus", render);
                LogPointerWindow("render.RBX", render.rbx);
                LogPointerWindow("render.RSI", render.rsi);
                LogPointerWindow("render.RDI", render.rdi);
                LogPointerWindow("render.R12", render.r12);
                LogPointerWindow("render.R13", render.r13);
                LogPointerWindow("render.R14", render.r14);
                LogPointerWindow("render.R15", render.r15);
            }

            DumpAllThreadForensics(renderTid);
            logs::warn(
                "[SiteARenderBreaker.forensics] ===== END PRE SNAPSHOT {} =====",
                a_seq);
        }

        void DumpPostRecoveryRender(std::uint64_t a_seq) {
            const DWORD renderTid =
                g_worker_tid.load(std::memory_order_relaxed);
            ThreadForensicSnap render{};
            if (CaptureThreadForensics(renderTid, render)) {
                LogThreadForensics("POST+verify/render", render, true);
                LogEventHandleCandidates("POST+verify/render", render);
            } else {
                logs::warn(
                    "[SiteARenderBreaker.forensics] POST+verify episode {}: "
                    "render context unavailable (tid={})",
                    a_seq, renderTid);
            }
        }

        // Field evidence from the 2026-10-02 v2.6.2 capture proved that
        // id 34557 does NOT block on Singleton-A's worker-ack.  While the
        // render thread is inside KERNELBASE/ntdll's WaitForSingleObjectEx,
        // the actual per-sub-task event HANDLE is preserved in both RDI and
        // R14; the return address on the stack points back inside id 34557.
        //
        // Active recovery therefore targets that deepest completion event,
        // not the outer worker-ack.  This is deliberately SE-1.5.97-only
        // until the same register/return-address shape is field-validated on
        // AE.  Every candidate must be a real, currently-unsignaled event and
        // must be observed while the same id-34557 episode is still active.
        bool IsInsideRenderTaskJoin(const ThreadForensicSnap& a_s) noexcept {
            if (!a_s.ok) return false;

            const auto& a = SkyrimAnchors::Get();
            constexpr std::uintptr_t kRenderTaskSpan = 0xED;  // SE id34557 body

            for (std::size_t i = 0; i < a_s.stackWordCount; ++i) {
                const auto ret = a_s.stackWords[i];
                if (ret >= a.renderTaskFn &&
                    ret < (a.renderTaskFn + kRenderTaskSpan))
                {
                    return true;
                }
            }
            return false;
        }

        bool TryRecoverDeepSubtaskWait(
            std::uint64_t a_seq,
            std::uintptr_t a_ackEntry)
        {
            if (REL::Module::GetRuntime() != REL::Module::Runtime::SE) {
                logs::warn(
                    "[SiteARenderBreaker] deeper per-sub-task recovery is "
                    "field-validated only on SE 1.5.97; refusing the deep "
                    "SetEvent path on this runtime.");
                return false;
            }

            constexpr std::uint32_t kMaxSignals = 4;
            constexpr std::uint32_t kVerifyMs = 500;
            constexpr std::uint32_t kVerifyStepMs = 25;

            std::array<std::uintptr_t, kMaxSignals> signaled{};
            std::uint32_t signaledCount = 0;

            for (std::uint32_t attempt = 0; attempt < kMaxSignals; ++attempt) {
                if (!g_in_wait.load(std::memory_order_acquire) ||
                    g_episode_seq.load(std::memory_order_relaxed) != a_seq)
                {
                    return true;
                }

                const DWORD renderTid =
                    g_worker_tid.load(std::memory_order_relaxed);
                ThreadForensicSnap render{};
                if (!CaptureThreadForensics(renderTid, render)) {
                    logs::error(
                        "[SiteARenderBreaker] DEEP RECOVERY ABORTED: could "
                        "not capture render-thread context (episode={}).",
                        a_seq);
                    return false;
                }

                if (!IsInsideRenderTaskJoin(render)) {
                    logs::error(
                        "[SiteARenderBreaker] DEEP RECOVERY ABORTED: render "
                        "thread no longer has a return frame inside id 34557 "
                        "while episode {} is still marked active.", a_seq);
                    return false;
                }

                const auto deepHandle = render.rdi;

                // In the field capture RDI and R14 independently preserved the
                // same live event HANDLE through the ntdll wait path. Requiring
                // both registers to agree makes this recovery fail closed if
                // the calling convention / wait implementation ever changes.
                if (deepHandle == 0 || render.r14 != deepHandle) {
                    logs::error(
                        "[SiteARenderBreaker] DEEP RECOVERY ABORTED: no "
                        "stable wait HANDLE in RDI/R14 (RDI=0x{:x}, "
                        "R14=0x{:x}, episode={}).",
                        render.rdi, render.r14, a_seq);
                    return false;
                }

                const auto singleton =
                    g_episode_singleton.load(std::memory_order_relaxed);
                const auto ss = ReadSiteA(singleton);
                if (deepHandle == a_ackEntry ||
                    (ss.ok && deepHandle == ss.wake))
                {
                    logs::error(
                        "[SiteARenderBreaker] DEEP RECOVERY ABORTED: "
                        "candidate 0x{:x} aliases a Singleton-A protocol "
                        "event (ack/wake), not a per-sub-task completion "
                        "event (episode={}).",
                        deepHandle, a_seq);
                    return false;
                }

                const int deepState = QueryEventState(deepHandle);
                if (deepState != 0) {
                    logs::error(
                        "[SiteARenderBreaker] DEEP RECOVERY ABORTED: "
                        "candidate 0x{:x} is not a valid unsignaled event "
                        "(state={}, episode={}).",
                        deepHandle, deepState, a_seq);
                    return false;
                }

                for (std::uint32_t i = 0; i < signaledCount; ++i) {
                    if (signaled[i] == deepHandle) {
                        logs::error(
                            "[SiteARenderBreaker] DEEP RECOVERY FAILED: "
                            "render thread returned to the same unsignaled "
                            "sub-task event 0x{:x} after it was already "
                            "signaled (episode={}).",
                            deepHandle, a_seq);
                        return false;
                    }
                }

                logs::warn(
                    "[SiteARenderBreaker] DEEP RECOVERY attempt {}/{}: "
                    "render is parked inside id 34557 on actual sub-task "
                    "event 0x{:x} (RDI==R14, state=0); signaling that event "
                    "instead of the outer worker-ack (episode={}).",
                    attempt + 1, kMaxSignals, deepHandle, a_seq);

                const HANDLE h = reinterpret_cast<HANDLE>(deepHandle);
                if (!::SetEvent(h)) {
                    logs::error(
                        "[SiteARenderBreaker] DEEP RECOVERY FAILED: "
                        "SetEvent(0x{:x}) returned false (GetLastError={}, "
                        "episode={}).",
                        deepHandle, ::GetLastError(), a_seq);
                    return false;
                }
                signaled[signaledCount++] = deepHandle;

                // Verify real forward progress.  id 34557 clears g_in_wait
                // only when the original function returns.  If it advances to
                // another per-sub-task wait, RDI/R14 will change and the next
                // bounded iteration may release that one too.
                for (std::uint32_t waited = 0;
                     waited < kVerifyMs &&
                     g_running.load(std::memory_order_relaxed);
                     waited += kVerifyStepMs)
                {
                    std::this_thread::sleep_for(
                        std::chrono::milliseconds(kVerifyStepMs));
                    if (!g_in_wait.load(std::memory_order_acquire) ||
                        g_episode_seq.load(std::memory_order_relaxed) != a_seq)
                    {
                        logs::warn(
                            "[SiteARenderBreaker] VERIFIED DEEP RELEASE: "
                            "id 34557 returned after signaling sub-task "
                            "event 0x{:x} (episode={}).",
                            deepHandle, a_seq);
                        return true;
                    }
                }

                ThreadForensicSnap after{};
                if (!CaptureThreadForensics(renderTid, after)) {
                    logs::error(
                        "[SiteARenderBreaker] DEEP RECOVERY FAILED: render "
                        "thread remained in episode {} and post-signal "
                        "context could not be captured.", a_seq);
                    return false;
                }

                if (!IsInsideRenderTaskJoin(after)) {
                    // It left the wait but has not yet unwound out of the
                    // wrapped function. Give it one short grace window before
                    // declaring failure.
                    for (std::uint32_t waited = 0;
                         waited < 250 &&
                         g_running.load(std::memory_order_relaxed);
                         waited += kVerifyStepMs)
                    {
                        std::this_thread::sleep_for(
                            std::chrono::milliseconds(kVerifyStepMs));
                        if (!g_in_wait.load(std::memory_order_acquire) ||
                            g_episode_seq.load(std::memory_order_relaxed) != a_seq)
                        {
                            logs::warn(
                                "[SiteARenderBreaker] VERIFIED DEEP RELEASE: "
                                "id 34557 unwound after signaling sub-task "
                                "event 0x{:x} (episode={}).",
                                deepHandle, a_seq);
                            return true;
                        }
                    }

                    logs::error(
                        "[SiteARenderBreaker] DEEP RECOVERY FAILED: episode "
                        "{} is still active but render is no longer parked "
                        "at the recognized id-34557 wait site; refusing "
                        "further forced signals.", a_seq);
                    return false;
                }

                if (after.rdi == deepHandle) {
                    logs::error(
                        "[SiteARenderBreaker] DEEP RECOVERY FAILED: "
                        "SetEvent(0x{:x}) did not move the render thread to "
                        "a different sub-task wait within {} ms "
                        "(episode={}).",
                        deepHandle, kVerifyMs, a_seq);
                    return false;
                }

                logs::warn(
                    "[SiteARenderBreaker] deep signal 0x{:x} advanced the "
                    "render join to another wait candidate RDI=0x{:x}; "
                    "continuing bounded recovery (episode={}).",
                    deepHandle, after.rdi, a_seq);
            }

            logs::error(
                "[SiteARenderBreaker] DEEP RECOVERY FAILED: reached the "
                "bounded limit of {} sub-task signals while id 34557 "
                "episode {} remained active.",
                kMaxSignals, a_seq);
            return false;
        }

        // ----- id 34557 wrap ------------------------------------------------
        std::uintptr_t __fastcall Detour_RenderTask(
            std::uintptr_t a1, std::uintptr_t a2,
            std::uintptr_t a3, std::uintptr_t a4)
        {
            const DWORD tid = ::GetCurrentThreadId();

            // id 34557 is the render-side cloth-join; the first thread we see
            // here is the render/worker thread. Pin it once. (Main reaches a
            // SEPARATE helper, id 34554, so this never fires off the worker
            // thread -- but the tid pin makes that explicit and keeps a stray
            // main-side call from opening a render episode.)
            DWORD expected = 0;
            g_worker_tid.compare_exchange_strong(expected, tid,
                std::memory_order_relaxed);

            const bool isWorker =
                (tid == g_worker_tid.load(std::memory_order_relaxed));

            if (isWorker && tl_depth++ == 0) {
                // Capture the Singleton-A instance (first arg = rcx) and its
                // worker-ack handle at entry, while the fields are coherent.
                // Every id 34557 entry is a real dispatched work item (the
                // loop only calls it after a worker-wake), so -- unlike the
                // render worker-wake wait -- there is no idle false-positive
                // to guard against; we open an episode whenever a non-null
                // ack handle is present. Ordered before the g_in_wait release
                // store so the watchdog always reads state for THIS episode.
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

            // unsafe_call (no mutex): the join blocks INFINITE on each
            // sub-task and call<>'s internal mutex would be held across that
            // wait, serialising every other hooked wait.
            const auto ret =
                g_hook.unsafe_call<std::uintptr_t>(a1, a2, a3, a4);

            if (isWorker && --tl_depth == 0) {
                g_in_wait.store(false, std::memory_order_release);
            }
            return ret;
        }

        // ----- watchdog -----------------------------------------------------
        void WatchdogLoop() {
            std::uint64_t lastHandledSeq = 0;

            while (g_running.load(std::memory_order_relaxed)) {
                std::this_thread::sleep_for(std::chrono::milliseconds(g_poll_ms));
                if (!g_running.load(std::memory_order_relaxed)) break;

                if (!g_in_wait.load(std::memory_order_acquire)) continue;

                const auto seq      = g_episode_seq.load(std::memory_order_relaxed);
                const auto start    = g_episode_start_ms.load(std::memory_order_relaxed);
                const auto singleton = g_episode_singleton.load(std::memory_order_relaxed);
                const auto ackEntry = g_episode_ack.load(std::memory_order_relaxed);
                const auto widEntry = g_episode_workid.load(std::memory_order_relaxed);
                const auto arg2Entry = g_episode_arg2.load(std::memory_order_relaxed);
                const auto arg3Entry = g_episode_arg3.load(std::memory_order_relaxed);
                const auto arg4Entry = g_episode_arg4.load(std::memory_order_relaxed);

                if (seq == lastHandledSeq) continue;          // already handled
                if (NowMs() - start < g_dwell_ms) continue;   // not parked long enough

                // First sample: still parked in the same episode.
                if (!g_in_wait.load(std::memory_order_acquire)) continue;
                if (g_episode_seq.load(std::memory_order_relaxed) != seq) continue;
                const auto s1 = ReadSiteA(singleton);
                if (!s1.ok) continue;             // unreadable: stand down

                // Confirmation window. To act we require ZERO progress: the
                // worker still in the SAME join episode (seq unchanged + still
                // parked) and the work-id + ack handle unchanged. id 34557
                // normally returns every frame, so a join still in the same
                // episode across this window is genuinely stuck.
                std::this_thread::sleep_for(std::chrono::milliseconds(g_recheck_ms));
                if (!g_running.load(std::memory_order_relaxed)) break;
                if (!g_in_wait.load(std::memory_order_acquire)) continue;
                if (g_episode_seq.load(std::memory_order_relaxed) != seq) continue;
                const auto s2 = ReadSiteA(singleton);
                if (!s2.ok) continue;

                const bool zeroProgress =
                    s1.workid == s2.workid &&
                    s1.ack    == s2.ack    &&
                    s2.ack    == ackEntry  &&
                    s2.workid == widEntry;
                if (!zeroProgress) {
                    if (g_diag) {
                        logs::info(
                            "[SiteARenderBreaker.diag] render worker parked in "
                            "id 34557 for {} ms but Singleton-A changed across "
                            "the window (workid {}->{}, ack 0x{:x}->0x{:x}); not "
                            "the stuck signature, standing by.",
                            NowMs() - start, s1.workid, s2.workid, s1.ack, s2.ack);
                    }
                    continue;
                }

                // Defensive: if the worker-ack just got signaled, the waiter
                // is about to wake on its own -- do not double-signal.
                const int ackState = QueryEventState(s2.ack);
                if (ackState == 1) {
                    if (g_diag) {
                        logs::info(
                            "[SiteARenderBreaker.diag] worker-ack 0x{:x} is "
                            "signaled while the render worker is still parked; "
                            "standing by.", s2.ack);
                    }
                    continue;
                }

                // ---- stuck render-side worker-ack join confirmed ----
                lastHandledSeq = seq;
                Stats::OnSiteARenderStuck();
                const auto dwell = NowMs() - start;

                if (g_diag) {
                    DumpStuckEpisodeForensics(
                        seq, singleton, ackEntry, widEntry,
                        arg2Entry, arg3Entry, arg4Entry);
                }

                if (g_detect_only) {
                    logs::warn(
                        "[SiteARenderBreaker] STUCK render-side Site-A join "
                        "detected (detect_only): the render worker has been "
                        "parked in id 34557 for {} ms (work-id={}) with the "
                        "Singleton-A worker-ack 0x{:x} NOT signaled (state={}) "
                        "and zero progress across the confirmation window. The "
                        "dispatched cloth sub-task is not completing -- this is "
                        "the case-study 29 §6 render-side freeze. WOULD SetEvent "
                        "the worker-ack here; set [site_a_render_breaker] "
                        "detect_only=false to actually recover.",
                        dwell, s2.workid, s2.ack, ackState);
                    continue;
                }

                // v2.6.2 field evidence established the real wait chain:
                // the render thread is blocked on a per-sub-task completion
                // event INSIDE id 34557.  Signaling Singleton-A's outer
                // worker-ack does not wake this wait and can publish completion
                // too early.  v2.6.3 therefore targets the actual live wait
                // HANDLE captured from the render thread (RDI==R14) and lets
                // id 34557 / id 34567 complete the normal ack path themselves.
                const bool released =
                    TryRecoverDeepSubtaskWait(seq, ackEntry);

                if (released) {
                    Stats::OnSiteARenderReleased();
                } else {
                    Stats::OnSiteARenderReleaseFailed();
                    logs::error(
                        "[SiteARenderBreaker] RECOVERY FAILED: the confirmed "
                        "render-side Site-A episode {} remained stuck after "
                        "bounded deep sub-task recovery (work-id={}, "
                        "outer-ack=0x{:x}, outer-ack-state={}).",
                        seq, s2.workid, ackEntry,
                        QueryEventState(ackEntry));
                }

                if (g_diag) {
                    DumpPostRecoveryRender(seq);
                }
            }
        }

    } // namespace

    bool Install() {
        const auto& cfg = Config::Get();
        if (!cfg.sar_enabled) {
            logs::info(
                "[SiteARenderBreaker] disabled by config "
                "(site_a_render_breaker.enabled = false).");
            return false;
        }

        if (!SkyrimAnchors::AvailableSiteARender()) {
            logs::warn(
                "[SiteARenderBreaker] render-side Site-A join (id 34557) "
                "anchor not resolved; module will NOT arm.");
            return false;
        }

        const auto& a = SkyrimAnchors::Get();

        g_detect_only = cfg.sar_detect_only;
        g_diag        = cfg.sar_diagnostic_logging;
        g_dwell_ms    = cfg.sar_dwell_threshold_ms;
        g_poll_ms     = (cfg.sar_poll_interval_ms == 0) ? 1000
                                                        : cfg.sar_poll_interval_ms;
        g_recheck_ms  = cfg.sar_recheck_window_ms;

        try {
            auto h = safetyhook::create_inline(
                reinterpret_cast<void*>(a.renderTaskFn),
                reinterpret_cast<void*>(&Detour_RenderTask));
            if (!h) {
                logs::critical(
                    "[SiteARenderBreaker] safetyhook::create_inline FAILED on "
                    "id 34557 at 0x{:x}; module not armed.",
                    a.renderTaskFn);
                return false;
            }
            g_hook = std::move(h);
        } catch (const std::exception& e) {
            logs::critical("[SiteARenderBreaker] install threw: {}", e.what());
            g_hook = {};
            return false;
        }

        g_running.store(true, std::memory_order_relaxed);
        g_watchdog = std::thread(WatchdogLoop);
        g_watchdog.detach();

        logs::info(
            "[SiteARenderBreaker] armed. id 34557 @0x{:x} (+0x{:x}), Singleton-A "
            "captured from arg0 at entry (ack@+0x60). mode={}, dwell_ms={}, "
            "poll_ms={}, recheck_ms={}, diag={}.",
            a.renderTaskFn, a.renderTaskFnRVA,
            g_detect_only ? "DETECT-ONLY" : "ACTIVE (will SetEvent)",
            g_dwell_ms, g_poll_ms, g_recheck_ms,
            g_diag ? "ON" : "OFF");
        if (g_diag) {
            logs::info(
                "[SiteARenderBreaker.forensics] stuck-episode forensic capture "
                "ENABLED: entry args + Singleton-A + render context + bounded "
                "process-thread context/stack scan will be logged only after "
                "the normal stuck signature is confirmed.");
        }
        return true;
    }

    void Stop() {
        g_running.store(false, std::memory_order_relaxed);
    }

}
