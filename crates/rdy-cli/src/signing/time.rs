//! The `signed_at` time stamp: `YYYY-MM-DDTHH:MM:SSZ`, UTC, from the system clock.

use std::time::{SystemTime, UNIX_EPOCH};

/// The system clock is before 1970 or after the year 9999.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("this machine's clock is not set to a usable date")]
pub struct ClockError;

/// The time stamp for `now`, such as `2026-11-30T16:02:11Z`.
///
/// # Errors
///
/// [`ClockError`] when `now` is before 1970 or past the year 9999.
pub fn timestamp(now: SystemTime) -> Result<String, ClockError> {
    let since = now.duration_since(UNIX_EPOCH).map_err(|_| ClockError)?;
    from_unix_seconds(since.as_secs())
}

/// The time stamp for `secs` seconds after 1970-01-01T00:00:00Z.
///
/// # Errors
///
/// [`ClockError`] when the year would need more than four digits.
pub fn from_unix_seconds(secs: u64) -> Result<String, ClockError> {
    let days = i64::try_from(secs / 86_400).map_err(|_| ClockError)?;
    let rest = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    if !(0..=9999).contains(&year) {
        return Err(ClockError);
    }
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    ))
}

/// Days since 1970-01-01 to a proleptic Gregorian date (Howard Hinnant's `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_instants_format_exactly() {
        for (secs, want) in [
            (0, "1970-01-01T00:00:00Z"),
            (951_782_400, "2000-02-29T00:00:00Z"),
            (1_000_000_000, "2001-09-09T01:46:40Z"),
            (1_709_251_199, "2024-02-29T23:59:59Z"),
            (1_772_466_009, "2026-03-02T15:40:09Z"),
            (4_102_444_800, "2100-01-01T00:00:00Z"),
            (253_402_300_799, "9999-12-31T23:59:59Z"),
        ] {
            assert_eq!(from_unix_seconds(secs).as_deref(), Ok(want), "{secs}");
        }
    }

    #[test]
    fn the_year_10000_is_refused() {
        assert_eq!(from_unix_seconds(253_402_300_800), Err(ClockError));
        assert_eq!(from_unix_seconds(u64::MAX), Err(ClockError));
    }

    #[test]
    fn a_clock_before_1970_is_refused() {
        let before = UNIX_EPOCH - std::time::Duration::from_secs(1);
        assert_eq!(timestamp(before), Err(ClockError));
    }

    #[test]
    fn every_stamp_has_the_shape_the_verifier_wants() {
        for step in 0..2000u64 {
            let stamp = from_unix_seconds(step * 1_234_567 + 13).expect("in range");
            assert_eq!(stamp.len(), 20, "{stamp}");
            assert!(
                stamp.ends_with('Z') && stamp.as_bytes()[10] == b'T',
                "{stamp}"
            );
        }
    }
}
