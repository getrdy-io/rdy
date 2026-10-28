//! `metadata.expires`: reading the time and comparing it with a clock (01 sections 2.2 and 4.4 step 7).
//!
//! The time is `YYYY-MM-DDTHH:MM:SSZ`, in UTC, and nothing else. The comparison needs no calendar crate:
//! it turns the date into a count of days since 1970-01-01 with the proleptic Gregorian rules and back.
//! The clock is passed in, so tests never read the real one.
//!
//! Cross-platform: `SystemTime` holds a different range on each OS. On Unix it is seconds and nanoseconds
//! from 1970 in an `i64`. On Windows it is 100 ns ticks from 1601 in an `i64` (a FILETIME), which ends
//! in the year 30828. `UNIX_EPOCH + Duration` panics when the sum does not fit, so nothing here builds an
//! instant. The code only subtracts with `duration_since`, which returns an error and never panics, and
//! a failed subtraction reads as the epoch. Tests build instants with `checked_add`, and stay inside
//! the year 9999, which every OS can hold.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::SpecError;
use crate::sig::valid_timestamp;

const SECS_PER_DAY: i64 = 86_400;

/// Reads `YYYY-MM-DDTHH:MM:SSZ` into seconds since the Unix epoch, or `None` for any other text,
/// including a date that does not exist.
pub(crate) fn parse_utc(text: &str) -> Option<i64> {
    if !valid_timestamp(text) {
        return None;
    }
    let num = |from: usize, to: usize| text.get(from..to)?.parse::<i64>().ok();
    let days = days_from_civil(num(0, 4)?, num(5, 7)?, num(8, 10)?);
    Some(days * SECS_PER_DAY + num(11, 13)? * 3600 + num(14, 16)? * 60 + num(17, 19)?)
}

/// The day `secs` falls on, as `YYYY-MM-DD`.
fn date_of(secs: i64) -> String {
    let (year, month, day) = civil_from_days(secs.div_euclid(SECS_PER_DAY));
    format!("{year:04}-{month:02}-{day:02}")
}

/// Days since 1970-01-01 for a proleptic Gregorian date. The month is 1 to 12 and the day is valid.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The inverse of [`days_from_civil`].
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// Seconds since the epoch for `now`. A clock set before 1970 reads as the epoch.
fn unix_seconds(now: SystemTime) -> i64 {
    now.duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Refuses a spec whose `expires` is before `now`. A spec with no `expires` never expires. A time that
/// is not in the full form is [`SpecError::BadExpires`], so this fails closed even when the parser did
/// not run first.
pub(crate) fn check_not_expired(expires: Option<&str>, now: SystemTime) -> Result<(), SpecError> {
    let Some(text) = expires else {
        return Ok(());
    };
    let at = parse_utc(text).ok_or(SpecError::BadExpires)?;
    let now = unix_seconds(now);
    if now > at {
        return Err(SpecError::Expired {
            expired_on: date_of(at),
            today: date_of(now),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    /// The year 9999, the latest date a spec can name, and a time every OS can hold.
    const END_OF_9999: u64 = 253_402_300_799;

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH
            .checked_add(Duration::from_secs(secs))
            .expect("this instant fits in SystemTime on every OS")
    }

    #[test]
    fn known_instants_convert_both_ways() {
        assert_eq!(parse_utc("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_utc("1970-01-02T00:00:01Z"), Some(86_401));
        assert_eq!(parse_utc("2000-02-29T12:00:00Z"), Some(951_825_600));
        assert_eq!(parse_utc("2027-01-31T00:00:00Z"), Some(1_801_353_600));
        assert_eq!(parse_utc("1969-12-31T23:59:59Z"), Some(-1));
        for secs in [0, 86_399, 951_825_600, 1_801_353_600, 4_102_444_799] {
            assert_eq!(
                parse_utc(&format!("{}T00:00:00Z", date_of(secs))),
                Some(secs.div_euclid(86_400) * 86_400)
            );
        }
        assert_eq!(date_of(-1), "1969-12-31");
        assert_eq!(date_of(951_825_600), "2000-02-29");
    }

    #[test]
    fn every_day_in_a_leap_cycle_round_trips() {
        for days in -800_000..800_000 {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days);
        }
    }

    #[test]
    fn text_that_is_not_the_full_form_is_refused() {
        for bad in [
            "",
            "2027-01-31",
            "2027-01-31T00:00:00",
            "2027-01-31T00:00:00+00:00",
            "2027-01-31 00:00:00Z",
            "2027-02-30T00:00:00Z",
            "2027-13-01T00:00:00Z",
            "2027-01-31T24:00:00Z",
            "2027-01-31t00:00:00z",
            "2027-01-31T00:00:00Z ",
            "２０２７-01-31T00:00:00Z",
        ] {
            assert_eq!(parse_utc(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn the_spec_is_valid_until_the_second_it_names() {
        let expires = Some("2027-01-31T00:00:00Z");
        assert_eq!(check_not_expired(expires, at(1_801_353_599)), Ok(()));
        assert_eq!(check_not_expired(expires, at(1_801_353_600)), Ok(()));
        assert_eq!(
            check_not_expired(expires, at(1_801_353_601)),
            Err(SpecError::Expired {
                expired_on: "2027-01-31".to_owned(),
                today: "2027-01-31".to_owned(),
            })
        );
    }

    #[test]
    fn both_dates_are_in_the_message() {
        let err = check_not_expired(Some("2027-01-31T00:00:00Z"), at(1_801_353_600 + 3 * 86_400))
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "expired on 2027-01-31. This machine's clock says 2027-02-03"
        );
    }

    #[test]
    fn no_expiry_never_expires_and_a_bad_one_fails_closed() {
        assert_eq!(check_not_expired(None, at(END_OF_9999)), Ok(()));
        assert_eq!(
            check_not_expired(Some("2027-01-31"), at(0)),
            Err(SpecError::BadExpires)
        );
    }

    #[test]
    fn an_instant_the_os_cannot_hold_is_not_built_and_the_latest_date_still_compares() {
        // Windows cannot hold a time this far out, so the add reports it instead of panicking.
        let huge = UNIX_EPOCH.checked_add(Duration::from_secs(u64::MAX / 4));
        if let Some(huge) = huge {
            assert_eq!(check_not_expired(None, huge), Ok(()));
        }
        let expires = Some("9999-12-31T23:59:59Z");
        assert_eq!(check_not_expired(expires, at(END_OF_9999)), Ok(()));
        assert_eq!(
            check_not_expired(expires, at(END_OF_9999 + 1)),
            Err(SpecError::Expired {
                expired_on: "9999-12-31".to_owned(),
                today: "10000-01-01".to_owned(),
            })
        );
    }

    #[test]
    fn a_clock_before_1970_expires_nothing() {
        let before = UNIX_EPOCH
            .checked_sub(Duration::from_secs(10))
            .expect("1969 fits in SystemTime on every OS");
        assert_eq!(
            check_not_expired(Some("1970-01-01T00:00:00Z"), before),
            Ok(())
        );
    }
}
