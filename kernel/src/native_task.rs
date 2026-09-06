//! Pure, host-testable helpers for the native `run` tasks in `session`.
//!
//! Native tasks execute as EL1 kernel code with no Kindling VM step limit, so any
//! work they do has to be bounded by construction or a shell argument can hang the
//! single core. These helpers keep that bound in one place. `triangular_sum` gives
//! the closed-form (wrapping) sum so `run sum` never loops over a huge argument,
//! and `NATIVE_TASK_WORK_LIMIT` caps the iteration count of any native task that
//! does loop, so the loop path can never spin.

/// Hard cap on iterations any single native `run` task may perform in EL1 code.
/// No shell argument may push a native task past this. A task either stays under
/// the cap, switches to a constant-time computation, or returns a clean error,
/// so a native task can never hang the core the way the old unbounded `sum` loop
/// could.
pub const NATIVE_TASK_WORK_LIMIT: u64 = 1_000_000;

/// Closed-form sum of `1..=n` with wrapping `u64` arithmetic, identical to the
/// result of `for i in 1..=n { acc = acc.wrapping_add(i) }` for every `n`, but
/// computed in constant time so a huge argument cannot spin the core.
///
/// Exactly one of `n` and `n + 1` is even, so halving the even operand before the
/// multiply keeps the result correct modulo 2^64 without an early overflow, and
/// avoids forming `n + 1` when `n` is `u64::MAX`.
pub fn triangular_sum(n: u64) -> u64 {
    if n & 1 == 0 {
        (n / 2).wrapping_mul(n.wrapping_add(1))
    } else {
        n.wrapping_mul((n >> 1).wrapping_add(1))
    }
}

/// The argument given to a native task could not be interpreted as a count.
#[derive(Debug, PartialEq, Eq)]
pub enum ArgError {
    /// Non-decimal text, or a value that does not fit in a `u64`.
    Malformed,
}

/// Parse an optional decimal argument for a native task into a count.
///
/// `None` (no argument given) yields `default`. A well-formed decimal `u64`
/// yields its value. Anything else (non-digits, or a value past `u64::MAX`)
/// yields `ArgError::Malformed`, which the caller turns into a clean error
/// instead of doing work.
pub fn parse_count_arg(arg: Option<&str>, default: u64) -> Result<u64, ArgError> {
    match arg {
        None => Ok(default),
        Some(a) => a.parse::<u64>().map_err(|_| ArgError::Malformed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loop_sum(n: u64) -> u64 {
        let mut acc: u64 = 0;
        let mut i: u64 = 1;
        while i <= n {
            acc = acc.wrapping_add(i);
            if i == n {
                break;
            }
            i += 1;
        }
        acc
    }

    #[test]
    fn closed_form_matches_loop_for_small_n() {
        for n in 0u64..2000 {
            assert_eq!(triangular_sum(n), loop_sum(n), "mismatch at n={n}");
        }
        assert_eq!(triangular_sum(100), 5050);
        assert_eq!(triangular_sum(1000), 500500);
    }

    #[test]
    fn closed_form_matches_loop_across_the_work_limit_boundary() {
        for n in (NATIVE_TASK_WORK_LIMIT - 3)..=(NATIVE_TASK_WORK_LIMIT + 3) {
            assert_eq!(triangular_sum(n), loop_sum(n), "mismatch at n={n}");
        }
    }

    #[test]
    fn closed_form_handles_huge_n_without_looping() {
        // u64::MAX is odd: n*((n>>1)+1) = (2^64-1)*2^63 mod 2^64 = 2^63.
        assert_eq!(triangular_sum(u64::MAX), 1u64 << 63);
        // A large even argument: (n/2)*(n+1) wrapping.
        let n = u64::MAX - 1;
        assert_eq!(triangular_sum(n), (n / 2).wrapping_mul(n + 1));
        // Powers of two near the top do not panic and stay constant time.
        assert_eq!(triangular_sum(1u64 << 62), triangular_sum(1u64 << 62));
    }

    #[test]
    fn arg_parsing_rejects_malformed_and_defaults_on_absent() {
        assert_eq!(parse_count_arg(None, 100), Ok(100));
        assert_eq!(parse_count_arg(Some("0"), 100), Ok(0));
        assert_eq!(parse_count_arg(Some("18446744073709551615"), 100), Ok(u64::MAX));
        assert_eq!(parse_count_arg(Some("abc"), 100), Err(ArgError::Malformed));
        assert_eq!(parse_count_arg(Some("-1"), 100), Err(ArgError::Malformed));
        assert_eq!(
            parse_count_arg(Some("999999999999999999999999"), 100),
            Err(ArgError::Malformed)
        );
    }
}
