//! The per-source-IP daily acceptance cap.
//!
//! Every reporter holds the same certificate, so the source address is the only handle the service has on a flood. A
//! source may have at most `limit` reports accepted per UTC day. The counters live in memory only: they are never
//! written to the database or to a log line and are dropped at the day boundary. At rollover the service logs the
//! previous day's three aggregate numbers (accepted, distinct sources, refusals), with no address in them, which is
//! the anomaly signal the plan asks for. IPv6 sources count by /64, the usual allocation to one subscriber.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use time::OffsetDateTime;
use tonic::Status;

use crate::util::log;

/// Most distinct sources tracked in one day. A flood from more sources than this is refused (fail closed) instead of
/// growing memory.
pub const MAX_TRACKED_SOURCES: usize = 1_000_000;

/// The day-boundary aggregate, which names no source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DaySummary {
    /// UTC days since the Unix epoch.
    pub day: i64,
    /// Reports accepted.
    pub accepted: u64,
    /// Distinct sources that had a report accepted.
    pub sources: u64,
    /// Requests refused by the cap.
    pub refused: u64,
}

#[derive(Debug, Default)]
struct State {
    day: i64,
    per_source: HashMap<IpAddr, u32>,
    accepted: u64,
    refused: u64,
}

#[derive(Debug)]
struct Inner {
    limit: u32,
    state: Mutex<State>,
}

/// The cap. Cloning shares the counters.
#[derive(Debug, Clone)]
pub struct DailyCap {
    inner: Arc<Inner>,
}

/// A counted slot. Dropping it without `commit` returns the slot, so reports that fail validation or storage do not
/// use the source's allowance.
#[derive(Debug)]
pub struct Reservation {
    cap: DailyCap,
    key: IpAddr,
    day: i64,
    committed: bool,
}

impl Reservation {
    /// Keep the slot: the report was accepted.
    pub fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if !self.committed {
            self.cap.release(self.key, self.day);
        }
    }
}

/// Group a peer address: IPv4-mapped IPv6 as IPv4, IPv6 by its /64.
pub fn source_key(address: IpAddr) -> IpAddr {
    match address.to_canonical() {
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            octets[8..].fill(0);
            IpAddr::from(octets)
        }
        v4 => v4,
    }
}

fn today() -> i64 {
    let seconds = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs());
    i64::try_from(seconds / 86_400).unwrap_or(0)
}

fn lock(state: &Mutex<State>) -> MutexGuard<'_, State> {
    state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl DailyCap {
    /// A cap of `limit` accepted reports per source per day. `0` refuses everything.
    pub fn new(limit: u32) -> Self {
        Self { inner: Arc::new(Inner { limit, state: Mutex::new(State::default()) }) }
    }

    /// The configured allowance.
    pub fn limit(&self) -> u32 {
        self.inner.limit
    }

    /// Reserve one slot for `address` today.
    pub fn reserve(&self, address: IpAddr) -> Result<Reservation, Status> {
        self.reserve_on(address, today())
    }

    /// Reserve one slot on an explicit UTC day (tests).
    pub fn reserve_on(&self, address: IpAddr, day: i64) -> Result<Reservation, Status> {
        let key = source_key(address);
        let (allowed, rolled) = {
            let mut state = lock(&self.inner.state);
            let rolled = Self::roll(&mut state, day);
            let allowed = match state.per_source.get(&key).copied() {
                Some(used) => used < self.inner.limit,
                None => self.inner.limit > 0 && state.per_source.len() < MAX_TRACKED_SOURCES,
            };
            if allowed {
                *state.per_source.entry(key).or_insert(0) += 1;
                state.accepted += 1;
            } else {
                state.refused += 1;
            }
            (allowed, rolled)
        };
        if let Some(summary) = rolled {
            Self::log_day(summary);
        }
        if allowed {
            Ok(Reservation { cap: self.clone(), key, day, committed: false })
        } else {
            Err(Status::resource_exhausted("daily report limit for this source reached"))
        }
    }

    /// The aggregate of the current day (tests and diagnostics).
    pub fn today_summary(&self) -> DaySummary {
        let state = lock(&self.inner.state);
        DaySummary { day: state.day, accepted: state.accepted, sources: state.per_source.len() as u64, refused: state.refused }
    }

    fn release(&self, key: IpAddr, day: i64) {
        let mut state = lock(&self.inner.state);
        if state.day != day {
            return;
        }
        if let Some(used) = state.per_source.get_mut(&key) {
            *used = used.saturating_sub(1);
            if *used == 0 {
                state.per_source.remove(&key);
            }
            state.accepted = state.accepted.saturating_sub(1);
        }
    }

    /// Move to `day`, returning the previous day's aggregate when it held any traffic.
    fn roll(state: &mut State, day: i64) -> Option<DaySummary> {
        if day <= state.day {
            return None;
        }
        let previous =
            DaySummary { day: state.day, accepted: state.accepted, sources: state.per_source.len() as u64, refused: state.refused };
        let had_traffic = previous.accepted > 0 || previous.refused > 0;
        state.day = day;
        state.per_source.clear();
        state.accepted = 0;
        state.refused = 0;
        had_traffic.then_some(previous)
    }

    fn log_day(summary: DaySummary) {
        let date = OffsetDateTime::from_unix_timestamp(summary.day.saturating_mul(86_400))
            .map_or_else(|_| summary.day.to_string(), |moment| moment.date().to_string());
        log(format_args!(
            "daily telemetry cap day={date} accepted={} sources={} refused={}",
            summary.accepted, summary.sources, summary.refused
        ));
    }
}
