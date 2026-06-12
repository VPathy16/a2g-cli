//! Gateway-side vehicle state ingestion (ADR-0016).
//!
//! The Enforcing Gateway is the authoritative source of vehicle state: it
//! subscribes to speed and gear frames directly from SocketCAN and verifies
//! SAE-J1850-CRC + alive-counter integrity protection (E2E-inspired, not a
//! full AUTOSAR-E2E profile implementation) on every frame. Caller-supplied
//! state (`operator_trusted`) is demoted to non-authoritative — Sensitive-domain
//! enforcement is re-gated against the gateway's own ingested state before any
//! bus write.
//!
//! ## Frame layout (demo profile, documented in ADR-0016)
//!
//! Both frames are 8 bytes with a CRC-8/SAE-J1850 trailer and alive counter:
//!
//! **Speed frame** (default CAN ID `0x3A0`):
//!
//! | Bytes | Content |
//! |-------|---------|
//! | 0–3   | `speed_mmps` as `u32` little-endian (fixed-point, SPEC §6.8) |
//! | 4–5   | reserved, `0x00` |
//! | 6     | alive counter in the low nibble (`0..=14`, wraps; `15` invalid) |
//! | 7     | CRC-8/SAE-J1850 over bytes 0–6 ∥ `SPEED_DATA_ID` |
//!
//! **Gear frame** (default CAN ID `0x3A1`):
//!
//! | Bytes | Content |
//! |-------|---------|
//! | 0     | gear: 0=Park, 1=Reverse, 2=Neutral, 3=Drive |
//! | 1–5   | reserved, `0x00` |
//! | 6     | alive counter in the low nibble (`0..=14`, wraps; `15` invalid) |
//! | 7     | CRC-8/SAE-J1850 over bytes 0–6 ∥ `GEAR_DATA_ID` |
//!
//! The data ID in the CRC input provides masquerade protection: a gear frame
//! replayed on the speed CAN ID fails the CRC.
//!
//! ## Verification rules
//!
//! A frame is **rejected** (counted, ignored) when:
//! - the CRC-8 does not match (`rejected_crc`),
//! - the alive counter equals the previous accepted counter for that signal —
//!   a repeated/frozen counter indicates a stuck or replaying sender
//!   (`rejected_counter`),
//! - the counter nibble is `15` or the payload is malformed
//!   (`rejected_malformed`).
//!
//! ## Staleness / fail-safe
//!
//! If either signal has not been refreshed by a *valid* frame within
//! `ATTESTATION_FRESHNESS_MS` (500 ms default), the ingested state degrades to
//! the fail-safe (`speed_mmps = 277_500`, gear `Drive`) — moving without data
//! is the safe assumption (SPEC §6.6). All staleness checks take an injected
//! `Instant` so they are unit-testable without a clock.
//!
//! ## Note on CRC polynomial
//!
//! CRC-8/SAE-J1850 (poly 0x1D, init 0xFF, xorout 0xFF, no reflection) is the
//! polynomial used by AUTOSAR E2E **Profile 1**. Profile 2 uses CRC-8H2F
//! (poly 0x2F). This implementation intentionally uses Profile 1's polynomial
//! and does not claim compliance with any full AUTOSAR-E2E profile.

use a2g_core::vehicle::{Gear, VehicleState, ATTESTATION_FRESHNESS_MS};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Default CAN arbitration ID carrying the speed signal.
pub const DEFAULT_SPEED_CAN_ID: u32 = 0x3A0;
/// Default CAN arbitration ID carrying the gear signal.
pub const DEFAULT_GEAR_CAN_ID: u32 = 0x3A1;

/// E2E data ID mixed into the speed-frame CRC (masquerade protection).
pub const SPEED_DATA_ID: u8 = 0xA0;
/// E2E data ID mixed into the gear-frame CRC (masquerade protection).
pub const GEAR_DATA_ID: u8 = 0xA1;

/// Alive counter modulus: values `0..=14` cycle; `15` is invalid (sentinel value
/// per AUTOSAR-E2E Profile 1 convention; see module note on polynomial choice).
pub const COUNTER_MODULUS: u8 = 15;

// ── CRC-8/SAE-J1850 (poly 0x1D, init 0xFF, xorout 0xFF, no reflection) ────────

/// CRC-8/SAE-J1850 — the polynomial from AUTOSAR E2E Profile 1 (not Profile 2).
/// See module-level note for rationale.
pub fn crc8_j1850(data: &[u8]) -> u8 {
    let mut crc: u8 = 0xFF;
    for &byte in data {
        crc ^= byte;
        for _ in 0..8 {
            crc = if crc & 0x80 != 0 {
                (crc << 1) ^ 0x1D
            } else {
                crc << 1
            };
        }
    }
    crc ^ 0xFF
}

fn frame_crc(payload_0_to_6: &[u8], data_id: u8) -> u8 {
    let mut buf = [0u8; 8];
    buf[..7].copy_from_slice(payload_0_to_6);
    buf[7] = data_id;
    crc8_j1850(&buf)
}

// ── Frame encode (used by the state simulator and tests) ─────────────────────

/// Encode an E2E-protected speed frame. `counter` is taken modulo 15.
pub fn encode_speed_frame(speed_mmps: u32, counter: u8) -> [u8; 8] {
    let mut f = [0u8; 8];
    f[0..4].copy_from_slice(&speed_mmps.to_le_bytes());
    f[6] = counter % COUNTER_MODULUS;
    f[7] = frame_crc(&f[..7], SPEED_DATA_ID);
    f
}

/// Encode an E2E-protected gear frame. `counter` is taken modulo 15.
pub fn encode_gear_frame(gear: Gear, counter: u8) -> [u8; 8] {
    let mut f = [0u8; 8];
    f[0] = gear_to_byte(gear);
    f[6] = counter % COUNTER_MODULUS;
    f[7] = frame_crc(&f[..7], GEAR_DATA_ID);
    f
}

/// Wire encoding of `Gear` (byte 0 of the gear frame).
pub fn gear_to_byte(gear: Gear) -> u8 {
    match gear {
        Gear::Park => 0,
        Gear::Reverse => 1,
        Gear::Neutral => 2,
        Gear::Drive => 3,
    }
}

fn byte_to_gear(b: u8) -> Option<Gear> {
    match b {
        0 => Some(Gear::Park),
        1 => Some(Gear::Reverse),
        2 => Some(Gear::Neutral),
        3 => Some(Gear::Drive),
        _ => None,
    }
}

// ── Frame verification (pure) ─────────────────────────────────────────────────

/// Why a frame was rejected. Rejected frames are counted and ignored; they
/// never update the ingested state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// CRC-8 trailer did not match payload + data ID.
    BadCrc,
    /// Alive counter identical to the previous accepted frame (frozen/replay).
    RepeatedCounter,
    /// Counter nibble out of range (15) or payload value invalid.
    Malformed,
}

/// Verify a speed frame. Returns `(speed_mmps, counter)` on success.
///
/// `last_counter` is the counter of the previous *accepted* speed frame, or
/// `None` for the first frame.
pub fn verify_speed_frame(
    frame: &[u8; 8],
    last_counter: Option<u8>,
) -> Result<(u32, u8), FrameError> {
    verify_trailer(frame, SPEED_DATA_ID, last_counter)?;
    let speed = u32::from_le_bytes([frame[0], frame[1], frame[2], frame[3]]);
    Ok((speed, frame[6] & 0x0F))
}

/// Verify a gear frame. Returns `(gear, counter)` on success.
pub fn verify_gear_frame(
    frame: &[u8; 8],
    last_counter: Option<u8>,
) -> Result<(Gear, u8), FrameError> {
    verify_trailer(frame, GEAR_DATA_ID, last_counter)?;
    let gear = byte_to_gear(frame[0]).ok_or(FrameError::Malformed)?;
    Ok((gear, frame[6] & 0x0F))
}

fn verify_trailer(
    frame: &[u8; 8],
    data_id: u8,
    last_counter: Option<u8>,
) -> Result<(), FrameError> {
    // CRC first: a frame that fails integrity tells us nothing about its counter.
    if frame_crc(&frame[..7], data_id) != frame[7] {
        return Err(FrameError::BadCrc);
    }
    let counter = frame[6] & 0x0F;
    if counter >= COUNTER_MODULUS {
        return Err(FrameError::Malformed);
    }
    if last_counter == Some(counter) {
        return Err(FrameError::RepeatedCounter);
    }
    Ok(())
}

// ── Ingested state ────────────────────────────────────────────────────────────

/// Rejection / acceptance counters (observable for tests and diagnostics).
#[derive(Debug, Default, Clone, Copy)]
pub struct IngestStats {
    pub accepted: u64,
    pub rejected_crc: u64,
    pub rejected_counter: u64,
    pub rejected_malformed: u64,
}

struct IngestInner {
    speed_mmps: u32,
    gear: Gear,
    last_speed_at: Option<Instant>,
    last_gear_at: Option<Instant>,
    speed_counter: Option<u8>,
    gear_counter: Option<u8>,
    stats: IngestStats,
}

/// Shared, thread-safe ingested-state holder. One per gateway.
pub struct StateIngest {
    inner: Mutex<IngestInner>,
    /// Staleness deadline in milliseconds (default `ATTESTATION_FRESHNESS_MS`).
    freshness_ms: u64,
    /// Set to `true` when `spawn_reader()` is called — i.e. the gateway was
    /// started with `--state-ingest`.  Used by `handle_enforce` to distinguish
    /// "reader never started (backward-compat)" from "reader started but frames
    /// stale (fail-closed)".
    reader_active: AtomicBool,
}

impl Default for StateIngest {
    fn default() -> Self {
        Self::new()
    }
}

impl StateIngest {
    pub fn new() -> Self {
        Self::with_freshness_ms(ATTESTATION_FRESHNESS_MS as u64)
    }

    /// Construct with an explicit staleness deadline (testing / per-deployment tuning).
    pub fn with_freshness_ms(freshness_ms: u64) -> Self {
        StateIngest {
            inner: Mutex::new(IngestInner {
                speed_mmps: 0,
                gear: Gear::Park,
                last_speed_at: None,
                last_gear_at: None,
                speed_counter: None,
                gear_counter: None,
                stats: IngestStats::default(),
            }),
            freshness_ms,
            reader_active: AtomicBool::new(false),
        }
    }

    /// Returns `true` once `--state-ingest` has been activated (i.e. `spawn_reader`
    /// was called).  When `true` and `current_state()` returns `fresh=false`, the
    /// gateway refuses Sensitive enforcement fail-closed instead of warn-and-proceeding.
    pub fn reader_active(&self) -> bool {
        self.reader_active.load(Ordering::Acquire)
    }

    /// Mark the reader as active. Called by `spawn_reader()` and in tests.
    pub fn mark_reader_active(&self) {
        self.reader_active.store(true, Ordering::Release);
    }

    /// Feed a raw speed frame. Invalid frames are counted and ignored.
    pub fn ingest_speed_frame(&self, frame: &[u8; 8], now: Instant) {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        match verify_speed_frame(frame, inner.speed_counter) {
            Ok((speed, counter)) => {
                inner.speed_mmps = speed;
                inner.speed_counter = Some(counter);
                inner.last_speed_at = Some(now);
                inner.stats.accepted = inner.stats.accepted.saturating_add(1);
            }
            Err(e) => record_rejection(&mut inner.stats, e),
        }
    }

    /// Feed a raw gear frame. Invalid frames are counted and ignored.
    pub fn ingest_gear_frame(&self, frame: &[u8; 8], now: Instant) {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        match verify_gear_frame(frame, inner.gear_counter) {
            Ok((gear, counter)) => {
                inner.gear = gear;
                inner.gear_counter = Some(counter);
                inner.last_gear_at = Some(now);
                inner.stats.accepted = inner.stats.accepted.saturating_add(1);
            }
            Err(e) => record_rejection(&mut inner.stats, e),
        }
    }

    /// Current ingested vehicle state at `now`.
    ///
    /// Returns `(state, fresh)`. `fresh == true` means **both** signals were
    /// refreshed by valid frames within the staleness deadline; the state is
    /// then bus-derived and authoritative. `fresh == false` degrades to the
    /// fail-safe state (`speed_mmps = 277_500`, gear `Drive`) — moving without
    /// data is the safe assumption (SPEC §6.6).
    pub fn current_state(&self, now: Instant) -> (VehicleState, bool) {
        let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let deadline = Duration::from_millis(self.freshness_ms);
        let speed_fresh = inner
            .last_speed_at
            .is_some_and(|t| now.duration_since(t) <= deadline);
        let gear_fresh = inner
            .last_gear_at
            .is_some_and(|t| now.duration_since(t) <= deadline);
        if speed_fresh && gear_fresh {
            (
                VehicleState {
                    speed_mmps: inner.speed_mmps,
                    gear: inner.gear,
                    actor: a2g_core::vehicle::Actor::Driver,
                },
                true,
            )
        } else {
            (VehicleState::fail_safe(), false)
        }
    }

    /// Snapshot of acceptance/rejection counters.
    pub fn stats(&self) -> IngestStats {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).stats
    }
}

fn record_rejection(stats: &mut IngestStats, e: FrameError) {
    match e {
        FrameError::BadCrc => stats.rejected_crc = stats.rejected_crc.saturating_add(1),
        FrameError::RepeatedCounter => {
            stats.rejected_counter = stats.rejected_counter.saturating_add(1)
        }
        FrameError::Malformed => {
            stats.rejected_malformed = stats.rejected_malformed.saturating_add(1)
        }
    }
}

// ── SocketCAN reader thread ───────────────────────────────────────────────────

/// Spawn a background reader that subscribes to `iface` and feeds matching
/// frames into `ingest`. Returns a stop flag; set it to `true` to terminate
/// the reader. On non-Linux targets (or if the socket cannot be opened) the
/// reader exits immediately and the ingested state stays fail-safe.
pub fn spawn_reader(
    ingest: Arc<StateIngest>,
    iface: String,
    speed_can_id: u32,
    gear_can_id: u32,
) -> Arc<AtomicBool> {
    // Mark active before the thread is spawned so `handle_enforce` sees the
    // flag as soon as the first request arrives — even if the thread hasn't
    // produced its first frame yet.
    ingest.mark_reader_active();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_c = Arc::clone(&stop);
    std::thread::spawn(move || {
        reader_loop(&ingest, &iface, speed_can_id, gear_can_id, &stop_c);
    });
    stop
}

#[cfg(target_os = "linux")]
fn reader_loop(
    ingest: &StateIngest,
    iface: &str,
    speed_can_id: u32,
    gear_can_id: u32,
    stop: &AtomicBool,
) {
    let reader = match crate::bus::CanReader::open(iface, 100) {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "[gateway:ingest] cannot open CAN reader on {iface}: {e}; state stays fail-safe"
            );
            return;
        }
    };
    eprintln!(
        "[gateway:ingest] reading speed=0x{speed_can_id:03X} gear=0x{gear_can_id:03X} on {iface}"
    );
    while !stop.load(Ordering::Relaxed) {
        match reader.read_frame() {
            Ok(Some((can_id, data))) => {
                let now = Instant::now();
                if can_id == speed_can_id {
                    ingest.ingest_speed_frame(&data, now);
                } else if can_id == gear_can_id {
                    ingest.ingest_gear_frame(&data, now);
                }
            }
            Ok(None) => { /* timeout — loop to re-check stop flag */ }
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

/// QNX (NTO) CAN reader skeleton.
///
/// QNX Neutrino uses character-device CAN drivers (`dev-can-*`, e.g.
/// `dev-can-mx6x`, `dev-can-kvaser`) that expose either a BSD-socket-compatible
/// `socket(AF_CAN, SOCK_RAW, CAN_RAW)` interface (via the optional QNX CAN
/// Socket library, `-lcanctl`) or a `devctl()`-based ioctl path.
///
/// ## Integration path (real hardware)
///
/// 1. Add `dev-can-*` driver startup to the QNX image build script (`bsp.build`).
/// 2. At runtime, open the CAN channel:
///    ```
///    // QNX SDP 8.0 with CAN Socket library
///    let fd = libc::socket(AF_CAN, SOCK_RAW, CAN_RAW);   // requires -lcanctl
///    // bind to /dev/can0 or the appropriate devctl channel
///    ```
/// 3. Replace the `unimplemented!` body below with the real read loop, using
///    the same `ingest_speed_frame` / `ingest_gear_frame` calls already in the
///    Linux path above.
///
/// Until this is implemented, the reader exits immediately, `reader_active`
/// stays `true` (set by `spawn_reader` before the thread is spawned), and
/// every Sensitive enforcement is refused fail-closed — identical semantics to
/// the generic non-Linux stub below.
///
/// This function is reachable on `target_os = "nto"` but intentionally returns
/// `Err` so that integration gaps are surfaced at runtime.
#[cfg(target_os = "nto")]
fn reader_loop(
    _ingest: &StateIngest,
    iface: &str,
    _speed_can_id: u32,
    _gear_can_id: u32,
    _stop: &AtomicBool,
) {
    // TODO(qnx): implement dev-can-* driver integration.
    // See ADR-0019 §3 and docs/qnx-integration.md §CAN Driver Integration.
    eprintln!(
        "[gateway:ingest] QNX CAN driver: real dev-can-* integration required for {iface}; \
         state stays fail-safe (fail-closed)"
    );
}

/// Fallback for any OS that is neither Linux nor QNX NTO.
///
/// SocketCAN is Linux-specific; there is no generic POSIX CAN interface.
/// The reader exits immediately so ingested state stays permanently stale and
/// fail-closed (when `--state-ingest` is active).
#[cfg(not(any(target_os = "linux", target_os = "nto")))]
fn reader_loop(
    _ingest: &StateIngest,
    iface: &str,
    _speed_can_id: u32,
    _gear_can_id: u32,
    _stop: &AtomicBool,
) {
    eprintln!("[gateway:ingest] SocketCAN unavailable on this OS ({iface}); state stays fail-safe");
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// Pin the CRC implementation to the published CRC-8/SAE-J1850 check value.
    #[test]
    fn test_crc8_j1850_check_value() {
        assert_eq!(crc8_j1850(b"123456789"), 0x4B, "CRC-8/SAE-J1850 check");
    }

    #[test]
    fn test_speed_frame_round_trip() {
        let f = encode_speed_frame(16_667, 3);
        let (speed, counter) = verify_speed_frame(&f, Some(2)).unwrap();
        assert_eq!(speed, 16_667);
        assert_eq!(counter, 3);
    }

    #[test]
    fn test_gear_frame_round_trip() {
        let f = encode_gear_frame(Gear::Drive, 7);
        let (gear, counter) = verify_gear_frame(&f, None).unwrap();
        assert_eq!(gear, Gear::Drive);
        assert_eq!(counter, 7);
    }

    #[test]
    fn test_corrupted_crc_rejected() {
        let mut f = encode_speed_frame(1_000, 0);
        f[1] ^= 0x01; // flip a payload bit; CRC trailer no longer matches
        assert_eq!(verify_speed_frame(&f, None), Err(FrameError::BadCrc));
    }

    #[test]
    fn test_repeated_counter_rejected() {
        let f = encode_speed_frame(1_000, 5);
        assert!(verify_speed_frame(&f, Some(4)).is_ok());
        assert_eq!(
            verify_speed_frame(&f, Some(5)),
            Err(FrameError::RepeatedCounter),
            "frozen alive counter must be rejected"
        );
    }

    #[test]
    fn test_gear_frame_on_speed_id_rejected() {
        // Masquerade: a gear frame presented as a speed frame fails the CRC
        // because the data ID differs.
        let f = encode_gear_frame(Gear::Park, 1);
        assert_eq!(verify_speed_frame(&f, None), Err(FrameError::BadCrc));
    }

    #[test]
    fn test_invalid_gear_value_rejected() {
        let mut f = [0u8; 8];
        f[0] = 9; // not a gear
        f[6] = 2;
        f[7] = frame_crc(&f[..7], GEAR_DATA_ID);
        assert_eq!(verify_gear_frame(&f, None), Err(FrameError::Malformed));
    }

    #[test]
    fn test_ingest_updates_state_and_stats() {
        let ingest = StateIngest::new();
        let t0 = Instant::now();
        ingest.ingest_speed_frame(&encode_speed_frame(16_667, 0), t0);
        ingest.ingest_gear_frame(&encode_gear_frame(Gear::Drive, 0), t0);

        let (state, fresh) = ingest.current_state(t0);
        assert!(fresh);
        assert_eq!(state.speed_mmps, 16_667);
        assert_eq!(state.gear, Gear::Drive);
        assert_eq!(ingest.stats().accepted, 2);
    }

    #[test]
    fn test_corrupted_frames_counted_and_ignored() {
        let ingest = StateIngest::new();
        let t0 = Instant::now();
        ingest.ingest_speed_frame(&encode_speed_frame(0, 0), t0);
        ingest.ingest_gear_frame(&encode_gear_frame(Gear::Park, 0), t0);

        // Corrupt frame: ignored, counted, does not overwrite state.
        let mut bad = encode_speed_frame(99_999, 1);
        bad[0] ^= 0xFF;
        ingest.ingest_speed_frame(&bad, t0);

        // Frozen counter: ignored, counted.
        ingest.ingest_speed_frame(&encode_speed_frame(99_999, 0), t0);

        let (state, fresh) = ingest.current_state(t0);
        assert!(fresh);
        assert_eq!(state.speed_mmps, 0, "rejected frames must not update state");
        let stats = ingest.stats();
        assert_eq!(stats.rejected_crc, 1);
        assert_eq!(stats.rejected_counter, 1);
    }

    /// Staleness: with the simulator stopped (no new frames), the state
    /// degrades to fail-safe after the deadline.
    #[test]
    fn test_stale_state_degrades_to_fail_safe() {
        let ingest = StateIngest::new();
        let t0 = Instant::now();
        ingest.ingest_speed_frame(&encode_speed_frame(0, 0), t0);
        ingest.ingest_gear_frame(&encode_gear_frame(Gear::Park, 0), t0);

        // Within the window: parked and fresh.
        let (s1, fresh1) = ingest.current_state(t0 + Duration::from_millis(100));
        assert!(fresh1);
        assert!(s1.is_parked_and_stopped());

        // Past the window: fail-safe (moving) — moving without data is the safe assumption.
        let (s2, fresh2) = ingest.current_state(t0 + Duration::from_millis(600));
        assert!(!fresh2);
        assert!(!s2.is_parked_and_stopped());
        assert_eq!(s2.speed_mmps, a2g_core::vehicle::FAIL_SAFE_SPEED_MMPS);
        assert_eq!(s2.gear, Gear::Drive);
    }

    /// One stale signal is enough to degrade — both must be fresh.
    #[test]
    fn test_one_stale_signal_degrades() {
        let ingest = StateIngest::new();
        let t0 = Instant::now();
        ingest.ingest_speed_frame(&encode_speed_frame(0, 0), t0);
        // Gear frame arrives much earlier (stale by the time we query).
        let (_, fresh) = ingest.current_state(t0 + Duration::from_millis(100));
        assert!(!fresh, "missing gear signal must degrade to fail-safe");
    }

    #[test]
    fn test_never_fed_is_fail_safe() {
        let ingest = StateIngest::new();
        let (state, fresh) = ingest.current_state(Instant::now());
        assert!(!fresh);
        assert!(!state.is_parked_and_stopped());
    }
}
