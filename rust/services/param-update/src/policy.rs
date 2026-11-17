//! The configurable change bound that closes GAP-NO-CUMULATIVE-BOUND.
//!
//! The Python service bounds every coordinate (`PARAM_UPDATE_MAX_ABS_GRADIENT`, default 1.0) and nothing else, so an
//! accepted sequence can move the model arbitrarily far. Two further checks apply to an update that passes
//! validation, in this order:
//!
//! 1. a per-update bound on the Euclidean norm of the whole update;
//! 2. a running budget on the sum of the accepted updates' norms since the anchored release (the `release_version` of
//!    the artifact). By the triangle inequality that sum bounds the distance the model has moved from the anchor, and
//!    it needs no copy of the anchor weights.
//!
//! The running total lives in the receipt database (`drift_budget`, one row per anchor) and in the artifact
//! (`update_drift_v1`, committed by the same rename as the weights), so recovery after an interrupted publication
//! restores it. The receipt itself is unchanged. A replayed request is answered from its receipt before any bound is
//! applied, so exhausting the budget never turns an idempotent retry into a failure.
//!
//! # Default values
//!
//! * **16.0 per update.** The studies' payload bound is 0.05 per coordinate (`docs/local-sgd-fuzzer-study-20261006.md`,
//!   FULL Adam `delta_cap`), and an update carries at most 65,536 values: 0.05 * 256 = 12.8. The stage 0 corpus's largest
//!   accepted update (128 coordinates at 1.0) has norm 11.3. 16.0 therefore admits every update the recorded studies and
//!   the corpus could have produced and refuses the "every trainable coordinate at the 1.0 bound" update (norm above 200).
//! * **512.0 per anchored release.** The longest recorded accepted run is the six-hour study's 340 balanced-profile
//!   head updates (`docs/long-fuzzer-results-20261009.md`). A head update carries about 660 coordinates, so its norm is at
//!   most 0.05 * sqrt(660) = 1.3, and 340 of them sum to at most 436.
//!
//! Both defaults are structural upper bounds, not a replay of the recorded sequences: the per-update L2 norms of those
//! studies are not in the repository. See the stage 5 handoff notes of the plan.

use crate::error::Failure;

/// Default per-update L2 bound.
pub const DEFAULT_MAX_UPDATE_L2: f64 = 16.0;
/// Default cumulative budget per anchored release.
pub const DEFAULT_MAX_CUMULATIVE_L2: f64 = 512.0;

/// Which bounds apply.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DriftPolicy {
    /// Only the per-coordinate bound, as the Python service. Artifacts and receipts are then byte-identical to it.
    Off,
    /// The per-update and cumulative bounds.
    Enforce {
        /// Largest accepted update norm.
        max_update_l2: f64,
        /// Largest accepted running total per anchored release.
        max_cumulative_l2: f64,
    },
}

impl Default for DriftPolicy {
    fn default() -> Self {
        Self::Enforce { max_update_l2: DEFAULT_MAX_UPDATE_L2, max_cumulative_l2: DEFAULT_MAX_CUMULATIVE_L2 }
    }
}

impl DriftPolicy {
    /// Whether any bound applies.
    pub fn enforced(&self) -> bool {
        matches!(self, Self::Enforce { .. })
    }

    /// Check an update of norm `update_l2` against a running total of `current_total`. Returns the new total.
    pub fn admit(&self, anchor: &str, update_l2: f64, current_total: f64) -> Result<f64, Failure> {
        let Self::Enforce { max_update_l2, max_cumulative_l2 } = *self else { return Ok(current_total) };
        if update_l2 > max_update_l2 {
            return Err(Failure::invalid(format!("Update L2 norm {update_l2:.6} exceeds the per-update bound {max_update_l2}.")));
        }
        let total = current_total + update_l2;
        if total > max_cumulative_l2 {
            return Err(Failure::Precondition(format!(
                "Cumulative update norm {total:.6} would exceed the drift budget {max_cumulative_l2} of release {anchor}."
            )));
        }
        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn off_admits_everything_and_keeps_the_total() {
        assert_eq!(DriftPolicy::Off.admit("v1", 1e9, 5.0).unwrap(), 5.0);
        assert!(!DriftPolicy::Off.enforced());
    }

    #[test]
    fn the_per_update_bound_is_inclusive() {
        let policy = DriftPolicy::Enforce { max_update_l2: 2.0, max_cumulative_l2: 100.0 };
        assert_eq!(policy.admit("v1", 2.0, 0.0).unwrap(), 2.0);
        assert!(matches!(policy.admit("v1", 2.0000001, 0.0), Err(Failure::Invalid(_))));
    }

    #[test]
    fn many_small_updates_exhaust_the_budget() {
        let policy = DriftPolicy::Enforce { max_update_l2: 2.0, max_cumulative_l2: 5.0 };
        let mut total = 0.0;
        let mut accepted = 0;
        loop {
            match policy.admit("v1", 1.0, total) {
                Ok(next) => {
                    total = next;
                    accepted += 1;
                }
                Err(failure) => {
                    assert!(matches!(failure, Failure::Precondition(_)));
                    break;
                }
            }
        }
        assert_eq!(accepted, 5);
    }

    #[test]
    fn the_defaults_admit_the_recorded_maxima() {
        let policy = DriftPolicy::default();
        // 128 coordinates at the 1.0 bound (the corpus's values-at-bound update).
        assert!(policy.admit("v1", 128f64.sqrt(), 0.0).is_ok());
        // The structural bound of the largest recorded run: 340 head updates of at most 0.05 * sqrt(660).
        let head = 0.05 * 660f64.sqrt();
        assert!(policy.admit("v1", head, 339.0 * head).is_ok());
        // Every trainable coordinate at the 1.0 bound.
        assert!(policy.admit("v1", 60_000f64.sqrt(), 0.0).is_err());
    }
}
