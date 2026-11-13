#pragma once

#include <chrono>
#include <cstdint>

namespace apostol {

/// Lets one log line through per interval and counts the ones held back, so
/// an event any client can cause at will cannot fill the log.
///
/// pass() is asked before writing a line: true — write it, together with the
/// number of lines held back since the previous one; false — the line is
/// counted and dropped. flush() reports a count still held once the interval
/// has run out, so the tail of a burst is not lost from the log.
class LogGate
{
public:
    using clock = std::chrono::steady_clock;

    explicit LogGate(clock::duration interval) noexcept : interval_(interval) {}

    bool pass(clock::time_point now, std::uint64_t& held_back) noexcept
    {
        if (opened_ && now - last_ < interval_) {
            ++held_;
            return false;
        }
        opened_ = true;
        last_ = now;
        held_back = held_;
        held_ = 0;
        return true;
    }

    bool flush(clock::time_point now, std::uint64_t& held_back) noexcept
    {
        if (held_ == 0 || now - last_ < interval_)
            return false;
        last_ = now;
        held_back = held_;
        held_ = 0;
        return true;
    }

private:
    clock::duration   interval_;
    clock::time_point last_{};
    std::uint64_t     held_ = 0;
    bool              opened_ = false;
};

} // namespace apostol
