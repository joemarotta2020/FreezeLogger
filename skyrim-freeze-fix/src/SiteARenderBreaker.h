#pragma once

namespace WorkerSpinLockFix::SiteARenderBreaker {

    // Runtime recovery for the RENDER-side Site-A worker-ack deadlock -- the
    // render-thread counterpart of the main-side deadlock SiteABreaker
    // handles. See ../../docs/case-study/29-siteabreaker-plan.md §6 and the
    // capture freeze_2026-06-24_053440.
    //
    // Mechanism of the bug
    // --------------------
    // Faster HDT-SMP's per-frame parallel cloth dispatch runs a worker loop
    // (id 34567) on the render thread. Per work item it calls a per-task
    // join function (id 34557) which, for each dispatched sub-task, waits
    // INFINITE on that sub-task's completion before the loop signals
    // Singleton-A's manual-reset worker-ack [+0x60]. When one of those
    // sub-task workers is stuck or gone (the same "0 idle" HDT-SMP worker
    // pool that produces the main-side variant), the render thread parks
    // forever inside id 34557 and never reaches the ack SetEvent -- so any
    // consumer waiting on that ack (and, transitively, the main thread)
    // hangs. In freeze_2026-06-24_053440 the render thread was parked here
    // (RBP = the Singleton-A instance, frames id 34557+0x7d / id 34567+0x86)
    // while main spun on a heap BSSpinLock held by the same stuck worker
    // pool; FreezeLogger previously classified this as "Unrecognised".
    //
    // How this module recovers
    // ------------------------
    //   1. An inline wrap on id 34557 (resolved version-independently via
    //      SkyrimAnchors' render-task signature scan) marks "the render
    //      worker entered a Site-A join since T" and captures the Singleton-A
    //      instance from the first argument (rcx) -- and from it the
    //      worker-ack HANDLE [+0x60] -- at entry, while the fields are
    //      coherent. id 34557 takes the singleton in rcx (no rip-relative
    //      slot), unlike main's id 34554.
    //   2. A watchdog thread polls. id 34557 normally returns every frame
    //      (~16 ms); when the worker thread has been parked in the SAME join
    //      episode past a dwell threshold AND is still parked after a re-check
    //      window (zero progress: same episode, work-id + ack handle
    //      unchanged, ack event still NOT signaled), it is the render-side
    //      worker-ack deadlock signature.
    //   3. In detect-only mode (default) it only logs. In active mode it
    //      delivers the missing signal (SetEvent on the captured ack handle)
    //      so the ack the stuck join would have raised is published and the
    //      waiter resumes.
    //
    // Safety: the dwell + zero-progress re-check guarantees no healthy frame
    // is ever touched (a join that is going to complete does so in well under
    // the dwell threshold). The stuck work is HDT-SMP cloth/physics --
    // per-frame, visual, self-correcting -- so the worst case of releasing on
    // a half-written result is a one-frame cosmetic glitch versus a permanent
    // freeze + force-kill. SetEvent on the worker-ack does NOT itself unblock
    // the deepest per-sub-task wait inside id 34557; it publishes the
    // completion ack the join would have raised, which is what the case-study
    // 29 §6 capture needs validated -- hence this module ships detect-only by
    // default until a field capture (FreezeLogger v0.9.0's render-side probe)
    // confirms the release path. Production detection/recovery never suspends
    // an engine thread. In the JM diagnostic build, when diagnostic_logging is
    // enabled AND the stuck signature has already been confirmed, the watchdog
    // briefly suspends threads one-at-a-time to capture register/stack evidence,
    // then immediately resumes them before continuing recovery.
    //
    // Returns true if armed (render-task anchor resolved + id 34557 wrap
    // installed + watchdog started). Best-effort: any failure leaves the
    // engine unmodified and the plugin running.
    bool Install();

    void Stop();

}
