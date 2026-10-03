# Provisional telemetry mechanism and scope review

Sources: `extension/client-runtime/src/telemetry/privacy.py` (domains,
`grr_probabilities`, `randomize_report`, `DailyPrivacyBudget`),
`event_emitter.py` (packet construction/reservation), runtime privacy regressions
and the Docker deployment smoke. This is an agent mechanism review, not external
certification or a proof of all implementation/transport behavior.

For one fixed domain of size k and field budget e, the implemented generalized
randomized-response probabilities are p = exp(e)/(exp(e)+k-1) for the true value
and q = 1/(exp(e)+k-1) for every other value. For any two valid inputs and output,
the largest likelihood ratio is p/q = exp(e). This gives the mechanism-level
e-LDP bound on that field, assuming the stated randomization distribution.

The five protected fields are action (3 values), risk bucket (4), primary category
(11), coarse model version (2) and UTC time bucket (6). `randomize_report` divides
the event budget equally among the five fields. Sequential composition therefore
gives an event budget at most their sum. Defaults are event epsilon 1 and daily
epsilon 8; the daily ledger allows at most eight default-budget reservations.
Variable allowed event budgets consume their stated integer micro-epsilon budget.

Reservation occurs before emission and is not refunded after a failed send. The
persistent installation-local ledger supports restart accounting and caps release
under a trusted clock and persistent state. Deleting/copying the ledger, changing
installation identity, clock manipulation or bypassing the trusted emitter can
break the accounting assumptions. Tests exercise budget exhaustion and persistence;
they do not establish formal floating-point/random-generator correctness or
protection against a compromised emitter.

The bound is conditional on emitted report fields and their fixed domains. It
does not hide whether/when a request occurs, exact report counts, transport
identity, network addresses or arbitrary logging outside the mechanism. Do not
call it user-level DP or anonymous transport. Private telemetry is separate from
the synthetic parameter-update path; bounded/clipped gradients alone do not
establish private training.

No deployment-monitoring utility study has been performed. Estimates concern
emitted, budget-limited reports, with possible censoring/selection bias. Sparse
counts and small per-field budgets can produce high variance. The eight-report
cap and report-selection process prevent treating these aggregates as an unbiased
summary of every prompt encountered by an installation.

Professor confirmation should check the equations, domains, composition and
trust assumptions against the final source revision. Only the stated supporting
mechanism and limitations are appropriate paper claims at this checkpoint.
