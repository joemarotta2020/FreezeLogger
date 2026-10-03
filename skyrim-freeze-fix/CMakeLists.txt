cmake_minimum_required(VERSION 3.26)

project(WorkerSpinLockFix
    VERSION       2.6.3
    DESCRIPTION   "SKSE plugin that fixes two distinct Skyrim hard-freeze classes; installs on Skyrim SE 1.5.97 and AE 1.6.x (VR refused). LAYER 1 -- Phase4Defer (the AB-BA spinlock prevention): an inline wrap on the LockA acquirer (SE id 19369 / AE id 19796) plus two surgical Trampoline::write_call<5> patches at the cycle-hub call sites (SE id 36016+0xdcb -> id 40334, SE id 19372+0x606 -> id 40333; AE id 36991+0xf6e, id 19799+0x634) defer LockB acquires while the current thread holds LockA, so the engine's AB-BA worker-dispatcher inversion structurally cannot form. All ids resolve through REL::RelocationID{se,ae} pairs and all call-site / struct offsets are runtime-selected, so the same DLL runs on both editions; VerifyCallSite() is fail-safe (a wrong offset aborts the patch cleanly rather than corrupting code). LAYER 2 (new in v2.3.0) -- JobWaitBreaker (the WaitForJobTask lost-wakeup recovery): the second, unrelated freeze class documented in case-study 27/28, where Main::Update parks in WaitForJobTask on a manual-reset job-completion event that a producer tore down WITHOUT signalling, leaving main asleep forever with no producer alive. An inline wrap on WaitForJobTask (located by a version-independent .text body signature, with the Singleton-B job-pool slot derived from its rip-relative load) marks when main is parked and on which job index; a watchdog thread detects the lost-wakeup signature (main parked past a dwell threshold on a job slot that has been torn down to null) and, in active mode, delivers the missing signal via SetEvent on the captured wait handle so main resumes -- the job is already gone, so this is equivalent to the signal that was lost. Ships detect-only by default (logs the signature, alters nothing) until the release path is field-validated. v2.3.0 removes the v1.0 runtime breaker (AcquireHook + WaitGraph + Breaker), the stale-owner reaper, and the synthetic test harness: Phase4Defer fully prevents the AB-BA cycle (validated in the field with cycles_observed=0), so the runtime breaker and its reaper backstop were redundant and have been retired to shrink the plugin's footprint to two focused, independent fixes. LAYER 3 (new in v2.4.0) -- SiteABreaker (the Site-A worker-ack deadlock recovery): a THIRD freeze class documented in case-study 29, where Main::Update parks in the id 34554 wait helper on Singleton-A's manual-reset worker-ack event (driven by Faster HDT-SMP's per-frame parallel dispatch via id 35565) after a worker consumed the wake but never signalled completion -- so main sleeps forever (observed on HDT-SMP 3.1.0.0 and 3.2.0.0, so it is version-independent). An inline wrap on id 34554 (located by an independent .text body signature, with the Singleton-A slot derived from its rip-relative load) marks when main entered a Site-A wait and captures the worker-ack HANDLE at entry; a watchdog thread confirms the deadlock signature (main still parked in the same episode past a dwell threshold with pending=1, work-id + ack handle unchanged, and the ack event still unsignalled across a re-check window) and, in active mode, delivers the missing signal via SetEvent on the captured ack handle. Like JobWaitBreaker it ships detect-only by default. LAYER 4 (new in v2.5.0) -- SiteARenderBreaker (the render-side Site-A worker-ack recovery): the render-thread counterpart of Layer 3, documented in case-study 29 §6 and first captured in freeze_2026-06-24_053440. Faster HDT-SMP's per-frame parallel cloth dispatch runs a worker loop (id 34567) on the render thread that, per work item, calls a per-task join function (id 34557) which waits INFINITE on each dispatched sub-task before signalling Singleton-A's worker-ack [+0x60]; when a sub-task worker is stuck/gone (the same '0 idle' worker pool that produces the main-side variant) the render thread parks forever inside id 34557 and never acks, so any consumer (transitively main, which was observed spinning on a heap BSSpinLock held by the same stuck pool) hangs. An inline wrap on id 34557 (located by a byte-unique .text entry signature; the Singleton-A instance is captured from the first argument since id 34557 receives it in rcx rather than via a rip-relative slot) marks when the render worker entered a join and captures the worker-ack HANDLE at entry; a watchdog confirms the deadlock signature (the worker still parked in the SAME join episode past a dwell threshold -- id 34557 normally returns every frame -- with work-id + ack handle unchanged and the ack still unsignalled across a re-check window) and, in active mode, SetEvents the captured ack. Ships detect-only by default until the release path is field-validated against a FreezeLogger v0.9.0 render-side capture. LAYER 5 (new in v2.6.0) -- LeakedSpinLockBreaker (the leaked BSSpinLock force-release): a FIFTH freeze class documented in case-study 30 and proven by FreezeLogger v0.11.1's parked-holder steady-state probe in freeze_2026-06-25_222116, where a thread (main, reached via the HDT-SMP cloth chain id 35565 -> BSSpinLock::Acquire id 12210) spins forever on a heap BSSpinLock whose [+0] owner is an idle-pool worker parked in a kernel wait (id 68058, on the pool Semaphore) that acquired the lock on an earlier task and went idle WITHOUT releasing it -- the unlock leaked, so this is a lock-ownership deadlock that no SetEvent (Layers 2-4) can break. A watchdog thread (no inline hook -- there is no single function to wrap) periodically scans suspended threads for one contending a BSSpinLock at a version-independent spin-retry signature (the `xor eax,eax` after the lock's yield call; only the call displacement is wildcarded), follows the lock's owner, and -- only once the owner is provably parked in a kernel wait and the lock's (owner,state) word plus the holder's RIP have stayed byte-for-byte UNCHANGED across the full dwell+recheck window -- force-releases the lock via an InterlockedCompareExchange64 that is a no-op if anything moved in the last instant. Force-releasing a PROVABLY-leaked lock is safe: its owner never reaches its own unlock, so the clear cannot race a legitimate release, and worst case it is a no-op if the victim was contending a different lock. Ships detect-only by default until the force-release path is field-validated. v2.6.3 replaces Layer 4's outer worker-ack SetEvent with field-validated SE 1.5.97 deep-wait recovery: after the 2026-10-02 v2.6.2 forensic capture proved id 34557 remained parked with the outer ack successfully signaled, the breaker now captures the render thread at the confirmed wait, requires a return frame inside id 34557 plus the same valid unsignaled event HANDLE in RDI and R14, signals that actual per-sub-task completion event, and verifies that id 34557 returns (or advances to another bounded sub-task wait) before counting recovery. This avoids falsely publishing the outer ack and directly targets the wait that is holding the render thread. v2.6.1 hardens the LeakedSpinLockBreaker watchdog against a load-time / teardown access-violation CTD (crash bucket CTD-7b4ecc21, faulting in TryReadQword): every harvested pointer is now validated with VirtualQuery (committed + readable, write path requires writable) BEFORE any dereference rather than relying on SEH alone (the exception dispatcher cannot reliably unwind a hardware fault during process teardown or a loader transition), and the watchdog stays fully idle -- no thread suspension, no memory probing -- until the SKSE kDataLoaded message arms it, so it never scans during the volatile load/menu phase where a half-built thread context yields wild pointers. No behavioural change to the steady-state leak detection or the force-release recovery."
    LANGUAGES     CXX
)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

find_package(CommonLibSSE  CONFIG REQUIRED)
find_package(tomlplusplus  CONFIG REQUIRED)
find_package(safetyhook    CONFIG REQUIRED)

set(SOURCES
    src/main.cpp
    src/Config.cpp
    src/Logger.cpp
    src/Hooks.cpp
    src/Stats.cpp
    src/Phase4Defer.cpp
    src/SkyrimAnchors.cpp
    src/JobWaitBreaker.cpp
    src/SiteABreaker.cpp
    src/SiteARenderBreaker.cpp
    src/LeakedSpinLockBreaker.cpp
)

set(HEADERS
    src/PCH.h
    src/Config.h
    src/Logger.h
    src/Hooks.h
    src/Stats.h
    src/Phase4Defer.h
    src/SkyrimAnchors.h
    src/JobWaitBreaker.h
    src/SiteABreaker.h
    src/SiteARenderBreaker.h
    src/LeakedSpinLockBreaker.h
)

add_commonlibsse_plugin(${PROJECT_NAME}
    SOURCES ${SOURCES} ${HEADERS}
)

target_include_directories(${PROJECT_NAME}
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_precompile_headers(${PROJECT_NAME}
    PRIVATE
        src/PCH.h
)

target_link_libraries(${PROJECT_NAME}
    PRIVATE
        tomlplusplus::tomlplusplus
        safetyhook::safetyhook
)

target_compile_definitions(${PROJECT_NAME}
    PRIVATE
        WSLF_VERSION_MAJOR=${PROJECT_VERSION_MAJOR}
        WSLF_VERSION_MINOR=${PROJECT_VERSION_MINOR}
        WSLF_VERSION_PATCH=${PROJECT_VERSION_PATCH}
        UNICODE _UNICODE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
)

if(MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE
        /W4
        /permissive-
        /Zc:preprocessor
        /Zc:__cplusplus
        /utf-8
        /EHsc
        /MP
        /Zi
        /wd4324  # struct padded due to alignment specifier (intentional)
    )
    target_link_options(${PROJECT_NAME} PRIVATE
        /DEBUG:FULL
        "$<$<CONFIG:Release>:/OPT:REF;/OPT:ICF>"
    )
endif()
