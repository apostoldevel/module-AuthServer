#pragma once

#include "apostol/event_loop.hpp"
#include "apostol/http.hpp"

#include <chrono>
#include <functional>
#include <memory>

namespace apostol {

/// A deferred OAuth response guarded by a single safety timer.
///
/// The OAuth callback path answers asynchronously: the token exchange, and for a
/// provider without an id_token the userinfo fetch it hands off to, and then the
/// `daemon.login` query — several awaited steps, each of which may end the request
/// from its own callback. One safety timer covers the whole chain and fires a
/// refusal only if none of those steps ever answers.
///
/// The earlier version armed that timer and left it to a guard —
/// `if (conn->closed() || conn->has_pending_writes()) return;` — on the belief that
/// "a deferred response carries Connection: close, so once any branch answers the
/// connection is closed". That belief is false. `close_after_send_` is set only
/// inside `if (!req.keep_alive())` (libapostol `http.cpp`), i.e. only when the
/// CLIENT asked to close. The OAuth callback arrives keep-alive by default, so a
/// deferred answer leaves the connection open, `closed()` stays false, and the
/// watchdog fired its 504 into a live connection 65 s after a SUCCESSFUL login
/// (T086; originally T063).
///
/// So this class does not test the connection to decide whether the request has
/// been answered — those are two different questions, and `closed()` was the wrong
/// test for the wrong one. Whether the connection is dead is still checked, one
/// floor lower: `HttpConnection::send_response` opens with `if (closed_) return;`,
/// so a send into a gone connection is dropped there. What THIS class tracks is the
/// only thing the watchdog actually needs: has any branch answered yet. Every branch
/// answers through `respond()`, which latches and disarms the watchdog. The first
/// caller — a real branch or the watchdog itself — wins; every later one is a no-op.
/// That one latch closes both races: the watchdog's 504 can never follow a real
/// answer, and a late provider reply can never follow the watchdog's. Disarming on
/// the real answer also releases the timerfd now, not 65 s later — one descriptor
/// per login attempt on a slow satellite link mattered.
///
/// Single-threaded: it lives on one event loop, so the latch needs no atomics.
///
/// Local to AuthServer for now; the pattern (deferred answer + safety timer +
/// answer-once) is general enough to promote to libapostol once a second caller
/// wants it.
class DeferredResponse {
public:
    using TimeoutHandler = std::function<void(HttpResponse&)>;

    /// Wrap @p conn and arm a one-shot safety timer of @p window on @p loop. When
    /// it fires — only if nothing answered first — @p on_timeout fills the response
    /// (typically a 504) and it is sent through the same answer-once latch.
    static std::shared_ptr<DeferredResponse>
    arm(std::shared_ptr<HttpConnection> conn,
        EventLoop& loop,
        std::chrono::milliseconds window,
        TimeoutHandler on_timeout)
    {
        auto self = std::shared_ptr<DeferredResponse>(
            new DeferredResponse(std::move(conn), loop));
        // The loop owns the timer entry, the entry owns this lambda, the lambda
        // owns `self`: loop → callback → DeferredResponse. `self` holds only the
        // TimerId (an int), so there is no cycle; when the timer is cancelled or
        // fires, the entry is erased and this reference is released.
        self->timer_ = loop.add_timer(
            window,
            [self, on_timeout = std::move(on_timeout)]() {
                HttpResponse r;
                on_timeout(r);
                self->on_watchdog(r);
            },
            /*repeat=*/false);
        return self;
    }

    /// Answer from a real branch of the deferred chain, at most once. The first
    /// call disarms the watchdog and sends; any later call does nothing.
    ///
    /// `answered_` is set BEFORE the send: if `send_response` were to throw, there
    /// is deliberately no second attempt — a broken connection is not worth
    /// re-entering, and the watchdog is already disarmed.
    void respond(HttpResponse& response)
    {
        if (answered_)
            return;
        answered_ = true;
        disarm();
        conn_->send_response(response);
    }

    /// The wrapped connection, for the rare branch that needs it beyond answering.
    const std::shared_ptr<HttpConnection>& connection() const noexcept { return conn_; }

    /// True once any branch (or the watchdog) has answered. For tests and asserts.
    bool answered() const noexcept { return answered_; }

    DeferredResponse(const DeferredResponse&) = delete;
    DeferredResponse& operator=(const DeferredResponse&) = delete;

private:
    DeferredResponse(std::shared_ptr<HttpConnection> conn, EventLoop& loop)
        : conn_(std::move(conn)), loop_(loop) {}

    /// The watchdog's own answer path — called only from inside the timer callback.
    ///
    /// It latches and sends like respond(), but deliberately does NOT cancel the
    /// timer: a one-shot timer removes itself after its callback returns
    /// (`EventLoop::dispatch_timer`), so cancelling here would mean cancelling the
    /// timer we are running inside — destroying this very callback, and with it the
    /// `self` reference it holds, mid-execution. Not cancelling from here keeps that
    /// correctness inside this file: it does not depend on the dispatcher copying
    /// the std::function before invoking it (it does today, but that is a
    /// libapostol implementation detail, not a contract this class should rest on).
    void on_watchdog(HttpResponse& response)
    {
        if (answered_)
            return;
        answered_ = true;
        timer_ = EventLoop::kInvalidTimer;   // it self-removes; forget the id
        conn_->send_response(response);
    }

    void disarm()
    {
        if (timer_ != EventLoop::kInvalidTimer) {
            loop_.cancel_timer(timer_);
            timer_ = EventLoop::kInvalidTimer;
        }
    }

    std::shared_ptr<HttpConnection> conn_;
    EventLoop&                      loop_;
    EventLoop::TimerId              timer_{EventLoop::kInvalidTimer};
    bool                            answered_{false};
};

} // namespace apostol
