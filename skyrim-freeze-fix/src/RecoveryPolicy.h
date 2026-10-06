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

}
