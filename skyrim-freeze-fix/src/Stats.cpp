#include "PCH.h"
#include "Stats.h"
#include "Config.h"

namespace WorkerSpinLockFix::Stats {

    namespace {

        // Phase 4 structural defer
        std::atomic<std::uint64_t> g_p4_queued{ 0 };
        std::atomic<std::uint64_t> g_p4_drained{ 0 };
        std::atomic<std::uint64_t> g_p4_passthrough{ 0 };

        // JobWaitBreaker
        std::atomic<std::uint64_t> g_jw_stuck{ 0 };
        std::atomic<std::uint64_t> g_jw_released{ 0 };

        // SiteABreaker
        std::atomic<std::uint64_t> g_sa_stuck{ 0 };
        std::atomic<std::uint64_t> g_sa_released{ 0 };

        // SiteARenderBreaker
        std::atomic<std::uint64_t> g_sar_stuck{ 0 };
        std::atomic<std::uint64_t> g_sar_released{ 0 };
        std::atomic<std::uint64_t> g_sar_release_failed{ 0 };

        // LeakedSpinLockBreaker
        std::atomic<std::uint64_t> g_lsb_stuck{ 0 };
        std::atomic<std::uint64_t> g_lsb_released{ 0 };

        std::thread       g_dump_thread;
        std::atomic<bool> g_running{ false };
        std::atomic<bool> g_started{ false };

        void DumpOnce() {
            logs::info(
                "stats: phase4: queued={} drained={} passthrough={} | "
                "job_wait: stuck={} released={} | "
                "site_a: stuck={} released={} | "
                "site_a_render: stuck={} released={} failed={} | "
                "leaked_lock: stuck={} released={}",
                g_p4_queued.load(std::memory_order_relaxed),
                g_p4_drained.load(std::memory_order_relaxed),
                g_p4_passthrough.load(std::memory_order_relaxed),
                g_jw_stuck.load(std::memory_order_relaxed),
                g_jw_released.load(std::memory_order_relaxed),
                g_sa_stuck.load(std::memory_order_relaxed),
                g_sa_released.load(std::memory_order_relaxed),
                g_sar_stuck.load(std::memory_order_relaxed),
                g_sar_released.load(std::memory_order_relaxed),
                g_sar_release_failed.load(std::memory_order_relaxed),
                g_lsb_stuck.load(std::memory_order_relaxed),
                g_lsb_released.load(std::memory_order_relaxed));
        }

        void DumpLoop(std::chrono::seconds interval) {
            while (g_running.load(std::memory_order_relaxed)) {
                std::this_thread::sleep_for(interval);
                if (!g_running.load(std::memory_order_relaxed)) {
                    break;
                }
                DumpOnce();
            }
        }

    } // namespace

    void OnPhase4Queued() noexcept {
        g_p4_queued.fetch_add(1, std::memory_order_relaxed);
    }
    void OnPhase4Drained() noexcept {
        g_p4_drained.fetch_add(1, std::memory_order_relaxed);
    }
    void OnPhase4PassThrough() noexcept {
        g_p4_passthrough.fetch_add(1, std::memory_order_relaxed);
    }

    void OnJobWaitStuck() noexcept {
        g_jw_stuck.fetch_add(1, std::memory_order_relaxed);
    }
    void OnJobWaitReleased() noexcept {
        g_jw_released.fetch_add(1, std::memory_order_relaxed);
    }

    void OnSiteAStuck() noexcept {
        g_sa_stuck.fetch_add(1, std::memory_order_relaxed);
    }
    void OnSiteAReleased() noexcept {
        g_sa_released.fetch_add(1, std::memory_order_relaxed);
    }

    void OnSiteARenderStuck() noexcept {
        g_sar_stuck.fetch_add(1, std::memory_order_relaxed);
    }
    void OnSiteARenderReleased() noexcept {
        g_sar_released.fetch_add(1, std::memory_order_relaxed);
    }
    void OnSiteARenderReleaseFailed() noexcept {
        g_sar_release_failed.fetch_add(1, std::memory_order_relaxed);
    }

    void OnLeakedLockStuck() noexcept {
        g_lsb_stuck.fetch_add(1, std::memory_order_relaxed);
    }
    void OnLeakedLockReleased() noexcept {
        g_lsb_released.fetch_add(1, std::memory_order_relaxed);
    }

    void StartPeriodicDump() {
        if (g_started.exchange(true, std::memory_order_acq_rel)) {
            return;
        }

        const auto& s = Config::Get();
        if (s.stats_interval_s == 0) {
            logs::info("Periodic stats dump disabled (stats_interval_s=0).");
            return;
        }

        g_running.store(true, std::memory_order_relaxed);
        g_dump_thread = std::thread(
            DumpLoop, std::chrono::seconds(s.stats_interval_s));
        g_dump_thread.detach();

        logs::info("Periodic stats dump started (interval = {}s).",
            s.stats_interval_s);
    }

    void Stop() {
        g_running.store(false, std::memory_order_relaxed);
    }

}
