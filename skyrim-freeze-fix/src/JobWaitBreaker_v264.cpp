#include "PCH.h"
#include "JobWaitBreaker.h"

#include "Config.h"
#include "SkyrimAnchors.h"
#include "Stats.h"

namespace WorkerSpinLockFix::JobWaitBreaker {

    namespace {
        std::uintptr_t g_singleton_slot{ 0 };
        SafetyHookInline g_hook_wfjt{};

        std::atomic<DWORD>          g_main_tid{ 0 };
        std::atomic<bool>           g_in_job_wait{ false };
        std::atomic<std::uint64_t>  g_episode_seq{ 0 };
        std::atomic<std::uint64_t>  g_episode_start_ms{ 0 };
        std::atomic<std::uint32_t>  g_episode_idx{ 0 };
        std::atomic<std::uintptr_t> g_episode_handle{ 0 };

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
                reinterpret_cast<HANDLE>(a_handle), 0, &info, sizeof(info), &returned);
            if (status != 0) return -1;
            return info.EventState ? 1 : 0;
        }

        enum class ChainState {
            Error,
            TornDown,
            Resolved,
        };

        ChainState SampleChain(
            std::uint32_t a_idx,
            std::array<std::uintptr_t, 8>& a_out) noexcept
        {
            __try {
                const auto instance =
                    *reinterpret_cast<volatile std::uintptr_t*>(g_singleton_slot);
                if (instance == 0) return ChainState::TornDown;
                const auto subArray =
                    *reinterpret_cast<volatile std::uintptr_t*>(instance + 8);
                if (subArray == 0) return ChainState::TornDown;
                const auto element = *reinterpret_cast<volatile std::uintptr_t*>(
                    subArray + static_cast<std::uintptr_t>(a_idx) * 8);
                if (element == 0) return ChainState::TornDown;
                for (std::size_t i = 0; i < a_out.size(); ++i) {
                    a_out[i] = *reinterpret_cast<volatile std::uintptr_t*>(
                        element + i * 8);
                }
                return ChainState::Resolved;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                return ChainState::Error;
            }
        }

        std::uintptr_t DeriveWaitHandle(
            std::uint32_t a_idx0, std::uint32_t a_idx1) noexcept
        {
            __try {
                const auto instance =
                    *reinterpret_cast<volatile std::uintptr_t*>(g_singleton_slot);
                if (instance == 0) return 0;
                const auto subArray =
                    *reinterpret_cast<volatile std::uintptr_t*>(instance + 8);
                if (subArray == 0) return 0;
                const auto element = *reinterpret_cast<volatile std::uintptr_t*>(
                    subArray + static_cast<std::uintptr_t>(a_idx0) * 8);
                if (element == 0) return 0;
                const auto handleTable =
                    *reinterpret_cast<volatile std::uintptr_t*>(element);
                if (handleTable == 0) return 0;
                return *reinterpret_cast<volatile std::uintptr_t*>(
                    handleTable + static_cast<std::uintptr_t>(a_idx1) * 8);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                return 0;
            }
        }

        void LogFingerprint(
            std::string_view a_phase,
            ChainState a_state,
            const std::array<std::uintptr_t, 8>& a_fp,
            std::uintptr_t a_handle)
        {
            if (!g_diag) return;
            DWORD handles = 0;
            ::GetProcessHandleCount(::GetCurrentProcess(), &handles);
            logs::warn(
                "[JobWaitBreaker.diag] {} state={} handle=0x{:x}(event_state={}) "
                "process_handles={} fp=[{:x},{:x},{:x},{:x},{:x},{:x},{:x},{:x}]",
                a_phase, static_cast<int>(a_state), a_handle,
                QueryEventState(a_handle), handles,
                a_fp[0], a_fp[1], a_fp[2], a_fp[3],
                a_fp[4], a_fp[5], a_fp[6], a_fp[7]);
        }

        std::uintptr_t __fastcall Detour_WaitForJobTask(
            std::uint32_t a_idx0, std::uint32_t a_idx1)
        {
            const DWORD tid = ::GetCurrentThreadId();
            DWORD expected = 0;
            g_main_tid.compare_exchange_strong(
                expected, tid, std::memory_order_relaxed);
            const bool isMain =
                tid == g_main_tid.load(std::memory_order_relaxed);

            if (isMain && tl_depth++ == 0) {
                g_episode_idx.store(a_idx0, std::memory_order_relaxed);
                g_episode_handle.store(
                    DeriveWaitHandle(a_idx0, a_idx1), std::memory_order_relaxed);
                g_episode_start_ms.store(NowMs(), std::memory_order_relaxed);
                g_episode_seq.fetch_add(1, std::memory_order_relaxed);
                g_in_job_wait.store(true, std::memory_order_release);
            }

            const auto ret =
                g_hook_wfjt.unsafe_call<std::uintptr_t>(a_idx0, a_idx1);

            if (isMain && --tl_depth == 0) {
                g_in_job_wait.store(false, std::memory_order_release);
            }
            return ret;
        }

        bool VerifyWake(
            std::uint64_t a_seq,
            std::uint32_t a_idx,
            const std::array<std::uintptr_t, 8>& a_before,
            ChainState a_beforeState,
            std::uintptr_t a_handle)
        {
            constexpr std::uint32_t kVerifyMs = 750;
            constexpr std::uint32_t kStepMs = 25;

            for (std::uint32_t waited = 0;
                 waited < kVerifyMs && g_running.load(std::memory_order_relaxed);
                 waited += kStepMs)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(kStepMs));
                if (!g_in_job_wait.load(std::memory_order_acquire) ||
                    g_episode_seq.load(std::memory_order_relaxed) != a_seq)
                {
                    Stats::OnJobWaitReleased();
                    logs::warn(
                        "[JobWaitBreaker] VERIFIED RELEASE: WaitForJobTask episode {} "
                        "returned after SetEvent(0x{:x}).",
                        a_seq, a_handle);
                    return true;
                }
            }

            std::array<std::uintptr_t, 8> after{};
            const auto afterState = SampleChain(a_idx, after);
            LogFingerprint("POST-SIGNAL", afterState, after, a_handle);

            logs::error(
                "[JobWaitBreaker] RECOVERY FAILED: SetEvent(0x{:x}) succeeded but "
                "main remained in the same WaitForJobTask episode {} after {} ms "
                "(before_state={}, after_state={}, event_state={}). No second "
                "forced wake will be attempted for this episode.",
                a_handle, a_seq, kVerifyMs,
                static_cast<int>(a_beforeState),
                static_cast<int>(afterState), QueryEventState(a_handle));

            if (g_diag && a_beforeState == ChainState::Resolved &&
                afterState == ChainState::Resolved && a_before != after)
            {
                logs::warn(
                    "[JobWaitBreaker.diag] the job fingerprint changed after the "
                    "signal even though main did not return; treating this as a "
                    "different failure shape and standing down.");
            }
            return false;
        }

        void WatchdogLoop() {
            std::uint64_t lastHandledSeq = 0;

            while (g_running.load(std::memory_order_relaxed)) {
                std::this_thread::sleep_for(std::chrono::milliseconds(g_poll_ms));
                if (!g_running.load(std::memory_order_relaxed)) break;
                if (!g_in_job_wait.load(std::memory_order_acquire)) continue;

                const auto seq = g_episode_seq.load(std::memory_order_relaxed);
                const auto start =
                    g_episode_start_ms.load(std::memory_order_relaxed);
                const auto idx = g_episode_idx.load(std::memory_order_relaxed);
                const auto handle =
                    g_episode_handle.load(std::memory_order_relaxed);

                if (seq == lastHandledSeq) continue;
                if (NowMs() - start < g_dwell_ms) continue;
                if (!g_in_job_wait.load(std::memory_order_acquire) ||
                    g_episode_seq.load(std::memory_order_relaxed) != seq)
                    continue;

                std::array<std::uintptr_t, 8> fp1{};
                const auto s1 = SampleChain(idx, fp1);
                if (s1 == ChainState::Error) continue;

                std::this_thread::sleep_for(
                    std::chrono::milliseconds(g_recheck_ms));
                if (!g_running.load(std::memory_order_relaxed)) break;
                if (!g_in_job_wait.load(std::memory_order_acquire) ||
                    g_episode_seq.load(std::memory_order_relaxed) != seq)
                    continue;

                std::array<std::uintptr_t, 8> fp2{};
                const auto s2 = SampleChain(idx, fp2);
                if (s2 == ChainState::Error) continue;

                const bool tornDown =
                    s1 == ChainState::TornDown && s2 == ChainState::TornDown;
                const bool stalledIntact =
                    s1 == ChainState::Resolved &&
                    s2 == ChainState::Resolved && fp1 == fp2;
                if (!tornDown && !stalledIntact) {
                    if (g_diag) {
                        logs::info(
                            "[JobWaitBreaker.diag] idx={} parked {} ms but job "
                            "state changed across the recheck window; standing down.",
                            idx, NowMs() - start);
                    }
                    continue;
                }

                lastHandledSeq = seq;
                Stats::OnJobWaitStuck();
                const auto dwell = NowMs() - start;
                const char* kind = tornDown
                    ? "torn-down (chain->null)"
                    : "stalled-intact (zero progress)";
                LogFingerprint("CONFIRMED-STUCK", s2, fp2, handle);

                if (g_detect_only) {
                    logs::warn(
                        "[JobWaitBreaker] STUCK job-wait detected (detect_only): "
                        "idx={} parked {} ms [{}]. WOULD signal captured event "
                        "0x{:x}; active mode now verifies that the wait actually "
                        "returns before counting recovery.",
                        idx, dwell, kind, handle);
                    continue;
                }

                if (handle == 0 || QueryEventState(handle) < 0) {
                    logs::error(
                        "[JobWaitBreaker] RECOVERY ABORTED: confirmed stuck job "
                        "idx={} [{}] but captured handle 0x{:x} is not a readable "
                        "event.", idx, kind, handle);
                    continue;
                }

                if (QueryEventState(handle) == 1) {
                    logs::warn(
                        "[JobWaitBreaker] confirmed stuck episode {} has a signal "
                        "already pending on 0x{:x}; refusing a duplicate SetEvent.",
                        seq, handle);
                    continue;
                }

                logs::warn(
                    "[JobWaitBreaker] ACTIVE recovery: idx={} parked {} ms [{}], "
                    "zero progress confirmed; SetEvent(0x{:x}) then verify.",
                    idx, dwell, kind, handle);

                if (!::SetEvent(reinterpret_cast<HANDLE>(handle))) {
                    logs::error(
                        "[JobWaitBreaker] RECOVERY FAILED: SetEvent(0x{:x}) returned "
                        "false (GetLastError={}).",
                        handle, ::GetLastError());
                    continue;
                }

                VerifyWake(seq, idx, fp2, s2, handle);
            }
        }
    }

    bool Install() {
        const auto& cfg = Config::Get();
        if (!cfg.jwb_enabled) {
            logs::info("[JobWaitBreaker] disabled by config.");
            return false;
        }
        if (!SkyrimAnchors::Available()) {
            logs::warn(
                "[JobWaitBreaker] WaitForJobTask/Singleton-B anchors unavailable "
                "({}); module not armed.", SkyrimAnchors::DiagnosticString());
            return false;
        }

        const auto& a = SkyrimAnchors::Get();
        g_singleton_slot = a.singletonBSlot;
        g_detect_only = cfg.jwb_detect_only;
        g_diag = cfg.jwb_diagnostic_logging;
        g_dwell_ms = cfg.jwb_dwell_threshold_ms;
        g_poll_ms = cfg.jwb_poll_interval_ms == 0
            ? 1000 : cfg.jwb_poll_interval_ms;
        g_recheck_ms = cfg.jwb_recheck_window_ms;

        try {
            auto hook = safetyhook::create_inline(
                reinterpret_cast<void*>(a.waitForJobTask),
                reinterpret_cast<void*>(&Detour_WaitForJobTask));
            if (!hook) {
                logs::critical(
                    "[JobWaitBreaker] safetyhook install failed at 0x{:x}.",
                    a.waitForJobTask);
                return false;
            }
            g_hook_wfjt = std::move(hook);
        } catch (const std::exception& e) {
            logs::critical("[JobWaitBreaker] install threw: {}", e.what());
            return false;
        }

        g_running.store(true, std::memory_order_relaxed);
        g_watchdog = std::thread(WatchdogLoop);
        g_watchdog.detach();

        logs::info(
            "[JobWaitBreaker] armed v2.6.4. WaitForJobTask @0x{:x} (+0x{:x}), "
            "Singleton-B @0x{:x}. mode={}, dwell_ms={}, poll_ms={}, "
            "recheck_ms={}, post_signal_verify_ms=750, diag={}.",
            a.waitForJobTask, a.waitForJobTaskRVA, a.singletonBSlot,
            g_detect_only ? "DETECT-ONLY" : "ACTIVE+VERIFY",
            g_dwell_ms, g_poll_ms, g_recheck_ms, g_diag ? "ON" : "OFF");
        return true;
    }

    void Stop() {
        g_running.store(false, std::memory_order_relaxed);
    }

}
