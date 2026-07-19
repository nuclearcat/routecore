# TODO

## Validate and repair the BGP finite-state machine

The BGP FSM is not currently correct enough for production use. Its core
transition table roughly follows RFC 4271, but the surrounding event plumbing
violates the specification in several important cases.

- [ ] Process `ConnectRetryTimerExpires` events. The timer is created and
  started, and the FSM defines transitions for its expiry, but
  `Session::tick()` never selects on `connect_retry_timer.tick()`.

- [ ] Route TCP EOF and read errors through the FSM as `TcpConnectionFails`
  instead of directly forcing `State::Connect`. In particular, a failure in
  `Established` must transition to `Idle` and perform the required cleanup and
  counter handling.

- [ ] Preserve the FSM's error transition. Invalid OPEN processing sets the
  state to `Idle` and returns an error, but `Session::tick()` overwrites that
  state with `Connect`; `Session::process()` then terminates the session task.

- [ ] Do not forward an UPDATE to the application after the FSM has rejected
  it. `handle_msg()` currently forwards the UPDATE even when, for example, an
  UPDATE in `OpenSent` caused an FSM-error notification, disconnection, and a
  transition to `Idle`.

- [ ] Make `Command::Disconnect` perform the appropriate FSM transition.
  Calling `disconnect()` currently removes the connection and stops timers but
  can leave the state as `Established`.

- [ ] Stop, rather than start, the ConnectRetryTimer after successful TCP
  establishment in `Active` when DelayOpen is disabled.

- [ ] Make `Timer::start()` idempotent or prevent it from being called while
  the timer is running. Each call currently spawns a new task and overwrites
  the old stop handle, which can create orphan timers and duplicate events.

- [ ] Implement RFC 4271 section 6.8 connection-collision handling. Second TCP
  connections in `OpenSent`, `OpenConfirm`, and `Established` are currently
  ignored instead of being tracked until OPEN-based collision resolution.

- [ ] Validate ROUTE-REFRESH messages against the FSM state and negotiated
  capability instead of silently ignoring them in every state.

- [ ] Add table-driven FSM tests covering every supported `(State, Event)`
  pair, resulting state, timer effects, counters, emitted messages, connection
  lifecycle, and application-visible messages. The old transition tests in
  `src/bgp/fsm/session.rs` are disabled inside a `/* FIXME ... */` block. The
  current `cargo test --all-features` suite passes, but it does not validate the
  FSM transition matrix.

Reference: [RFC 4271 section 8](https://www.rfc-editor.org/rfc/rfc4271.html#section-8).
