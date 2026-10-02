#pragma once

namespace WorkerSpinLockFix::Stats {

    // ---- Phase 4 structural defer (Phase4Defer.cpp) --------------------
    // A LockB-acquirer call (id 40333 or id 40334) was intercepted with
    // LockA already held by the current thread; the call was pushed
    // onto the thread-local deferred queue instead of being executed.
    void OnPhase4Queued() noexcept;
    // A queued LockB-acquirer call was executed during the drain that
    // runs when a thread's LockA depth returns to 0.
    void OnPhase4Drained() noexcept;
    // A LockB-acquirer call hit the gate without LockA held and was
    // tail-called through to the original (the common, no-deadlock
    // path). Counts the work the structural fix did NOT need to defer.
    void OnPhase4PassThrough() noexcept;

    // ---- JobWaitBreaker (WaitForJobTask lost-wakeup recovery) ----------
    // The lost-wakeup signature was confirmed (main parked in
    // WaitForJobTask past the dwell threshold on a torn-down job).
    void OnJobWaitStuck() noexcept;
    // Active mode delivered the missing signal (SetEvent) to release main.
    void OnJobWaitReleased() noexcept;

    // ---- SiteABreaker (Site-A worker-ack deadlock recovery) ------------
    // The worker-ack deadlock signature was confirmed (main parked in
    // id 34554 past the dwell threshold with zero progress, worker-ack
    // never signaled).
    void OnSiteAStuck() noexcept;
    // Active mode delivered the missing signal (SetEvent) to release main.
    void OnSiteAReleased() noexcept;

    // ---- SiteARenderBreaker (render-side Site-A worker-ack recovery) ---
    // The render-side deadlock signature was confirmed (the render/worker
    // thread parked in id 34557 past the dwell threshold with zero
    // progress, worker-ack never signaled).
    void OnSiteARenderStuck() noexcept;
    // Active mode delivered the missing worker-ack and id 34557 actually returned.
    void OnSiteARenderReleased() noexcept;
    // Recovery was attempted but id 34557 remained parked, or SetEvent failed.
    void OnSiteARenderReleaseFailed() noexcept;

    // ---- LeakedSpinLockBreaker (leaked BSSpinLock recovery) -----------
    // The leaked-lock signature was confirmed (a BSSpinLock held unchanged
    // by a parked owner past the dwell threshold while another thread
    // spins on it).
    void OnLeakedLockStuck() noexcept;
    // Active mode force-released the leaked lock.
    void OnLeakedLockReleased() noexcept;

    void StartPeriodicDump();
    void Stop();

}
