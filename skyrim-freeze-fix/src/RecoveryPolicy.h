#pragma once

#include <cstdint>

namespace WorkerSpinLockFix::RecoveryPolicy {

    struct DeepProgress {
        bool in_wait;
        std::uint64_t episode;
        std::uint32_t workid;
        std::uintptr_t outer_ack;
        std::uintptr_t deep_handle;
    };

    enum class Decision : std::uint8_t {
        Complete,
        Continue,
        AbortNoProgress,
        AbortRepeatedHandle,
        AbortProtocolChanged
    };

    constexpr Decision Evaluate(
        const DeepProgress& before,
        const DeepProgress& after,
        bool next_handle_seen) noexcept
    {
        if (!after.in_wait || after.episode != before.episode) {
            return Decision::Complete;
        }
        if (after.workid != before.workid ||
            after.outer_ack != before.outer_ack) {
            return Decision::AbortProtocolChanged;
        }
        if (after.deep_handle == before.deep_handle) {
            return Decision::AbortNoProgress;
        }
        if (next_handle_seen) {
            return Decision::AbortRepeatedHandle;
        }
        return Decision::Continue;
    }

    constexpr bool WithinBudget(
        std::uint32_t signals_already_sent,
        std::uint64_t elapsed_ms,
        std::uint32_t max_signals,
        std::uint64_t max_recovery_ms) noexcept
    {
        return signals_already_sent < max_signals && elapsed_ms < max_recovery_ms;
    }

    // Compile-time regression tests for the progress gate. These make the
    // safety contract part of every WorkerSpinLockFix build.
    namespace tests {
        constexpr DeepProgress before{ true, 7, 1, 0x100, 0x200 };

        static_assert(Evaluate(
            before, { true, 7, 1, 0x100, 0x201 }, false) == Decision::Continue);
        static_assert(Evaluate(
            before, { true, 7, 1, 0x100, 0x200 }, false) == Decision::AbortNoProgress);
        static_assert(Evaluate(
            before, { true, 7, 1, 0x100, 0x201 }, true) == Decision::AbortRepeatedHandle);
        static_assert(Evaluate(
            before, { false, 7, 1, 0x100, 0x200 }, false) == Decision::Complete);
        static_assert(Evaluate(
            before, { true, 8, 1, 0x100, 0x200 }, false) == Decision::Complete);
        static_assert(Evaluate(
            before, { true, 7, 2, 0x100, 0x201 }, false) == Decision::AbortProtocolChanged);
        static_assert(Evaluate(
            before, { true, 7, 1, 0x101, 0x201 }, false) == Decision::AbortProtocolChanged);

        static_assert(WithinBudget(4, 2000, 12, 6000));
        static_assert(!WithinBudget(12, 2000, 12, 6000));
        static_assert(!WithinBudget(4, 6000, 12, 6000));

        // v2.6.7: the hard-freeze rescue gets a 15 s absolute ceiling, while
        // verified forward progress refreshes a shorter inactivity window.
        static_assert(WithinProgressBudget(9, 6281, 400, 12, 15000, 2500));
        static_assert(!WithinProgressBudget(12, 6281, 400, 12, 15000, 2500));
        static_assert(!WithinProgressBudget(9, 15000, 400, 12, 15000, 2500));
        static_assert(!WithinProgressBudget(9, 7000, 2500, 12, 15000, 2500));

        // A newly observed zero deep handle after verified progress is not
        // itself a completion when work-id is still nonzero. It must be
        // re-probed briefly for either unwind or a new validated deep event.
        static_assert(ShouldReprobeZeroCandidate(
            { true, 7, 1, 0x100, 0x000 }, 9));
        static_assert(!ShouldReprobeZeroCandidate(
            { true, 7, 0, 0x100, 0x000 }, 9));
        static_assert(!ShouldReprobeZeroCandidate(
            { true, 7, 1, 0x100, 0x222 }, 9));
        static_assert(!ShouldReprobeZeroCandidate(
            { true, 7, 1, 0x100, 0x000 }, 0));
    }

}
