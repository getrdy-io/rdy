//! Table tests for the shared helpers.

use std::cmp::Ordering;

use super::*;

fn v(text: &str) -> Version {
    Version::parse(text).expect("test version")
}

fn q(text: &str) -> Quantity {
    Quantity::parse(text).expect("test quantity")
}

/// `tenths` of a GiB in bytes: `gib(313)` is 31.3 GiB, as `MemTotal` shows it.
fn gib(tenths: u64) -> u64 {
    tenths * GIB / 10
}

#[test]
fn versions_compare_per_numeric_component() {
    let table = [
        ("535.54.03", "535.104.05", Ordering::Less),
        ("535.104.05", "535.54.03", Ordering::Greater),
        ("535.104.05", "535.104.5", Ordering::Equal),
        ("1.9", "1.10", Ordering::Less),
        ("1.28", "1.28.0", Ordering::Equal),
        ("1.28", "1.28.0.1", Ordering::Less),
        ("v1.29.4", "1.29.4", Ordering::Equal),
        ("1.30", "1.3", Ordering::Greater),
        ("14", "9.9.9.9", Ordering::Greater),
        ("0", "0.0.0", Ordering::Equal),
        ("999999999.0", "999999998.999999999", Ordering::Greater),
    ];
    for (a, b, want) in table {
        assert_eq!(compare_versions(&v(a), &v(b)), want, "{a} vs {b}");
        assert_eq!(compare_versions(&v(b), &v(a)), want.reverse(), "{b} vs {a}");
    }
}

#[test]
fn version_at_least_is_inclusive() {
    assert!(version_at_least(&v("535.104.05"), &v("535.104")));
    assert!(version_at_least(&v("550.54.14"), &v("535.104")));
    assert!(!version_at_least(&v("535.54.03"), &v("535.104")));
}

#[test]
fn severity_caps_a_fail() {
    let table = [
        (Level::Pass, Severity::Block, Status::Pass),
        (Level::Pass, Severity::Warn, Status::Pass),
        (Level::Warn, Severity::Block, Status::Warn),
        (Level::Warn, Severity::Warn, Status::Warn),
        (Level::Fail, Severity::Block, Status::Block),
        (Level::Fail, Severity::Warn, Status::Warn),
    ];
    for (level, severity, want) in table {
        assert_eq!(cap_level(level, &severity), want, "{level:?} {severity:?}");
    }
}

#[test]
fn bytes_are_written_for_people() {
    let table = [
        (0, "0 bytes"),
        (100, "100 bytes"),
        (1024, "1 KiB"),
        (256 * MIB, "256 MiB"),
        (GIB, "1 GiB"),
        (32 * GIB, "32 GiB"),
        (gib(313), "31.3 GiB"),
        (gib(37), "3.7 GiB"),
        (22_731 * MIB, "22.2 GiB"),
        (TIB, "1 TiB"),
        (PIB, "1 PiB"),
        (Quantity::MAX_BYTES, "8 PiB"),
    ];
    for (bytes, want) in table {
        assert_eq!(format_bytes(bytes), want, "{bytes}");
    }
}

#[test]
fn a_nominal_32_gib_machine_passes_with_a_note() {
    let fit = Band::MEMORY.assess(gib(313), q("32Gi"));
    assert!(matches!(fit, SizeFit::InBand { .. }), "{fit:?}");
    assert_eq!(fit.level(Level::Pass), Level::Pass);
    assert_eq!(
        fit.note().as_deref(),
        Some("31.3 GiB found, 32 GiB needed, inside the 5% tolerance")
    );
}

#[test]
fn a_small_machine_gets_the_floor_not_the_percent() {
    // 5% of 4Gi is 205 MiB, so the 256 MiB floor sets the band: 3.75 GiB and up.
    assert_eq!(Band::MEMORY.width(q("4Gi")), 256 * MIB);
    let fit = Band::MEMORY.assess(gib(38), q("4Gi"));
    assert_eq!(fit.level(Level::Pass), Level::Pass);
    assert_eq!(
        fit.note().as_deref(),
        Some("3.8 GiB found, 4 GiB needed, inside the 256 MiB tolerance")
    );
}

// A 4096 MiB VM shows about 3.8 GiB. With the default band, max(5%, 256 MiB), the lowest value that
// passes against 4Gi is 3.75 GiB, so 3.8 GiB passes with a note and 3.7 GiB blocks (correction 06).
#[test]
fn a_4096_mib_vm_passes_against_4gi_with_a_note_and_3_7_gib_blocks() {
    let fit = Band::MEMORY.assess(gib(38), q("4Gi"));
    assert_eq!(fit.level(Level::Pass), Level::Pass);
    assert!(fit.note().is_some());
    assert!(matches!(
        Band::MEMORY.assess(gib(37), q("4Gi")),
        SizeFit::Below { .. }
    ));
}

#[test]
fn a_wider_floor_lets_3_7_gib_pass() {
    let fit = Band::new(5.0, q("512Mi")).assess(gib(37), q("4Gi"));
    assert_eq!(fit.level(Level::Pass), Level::Pass);
    assert!(fit.note().is_some());
}

#[test]
fn a_band_edge_is_inclusive_and_one_byte_past_it_is_below() {
    let min = q("32Gi");
    let edge = 32 * GIB - Band::MEMORY.width(min);
    assert!(matches!(
        Band::MEMORY.assess(edge, min),
        SizeFit::InBand { .. }
    ));
    assert!(matches!(
        Band::MEMORY.assess(edge - 1, min),
        SizeFit::Below { .. }
    ));
}

#[test]
fn a_24_gib_machine_blocks_against_32gi() {
    let fit = Band::MEMORY.assess(24 * GIB, q("32Gi"));
    assert_eq!(fit.level(Level::Pass), Level::Fail);
    assert_eq!(fit.note(), None);
}

#[test]
fn meeting_the_minimum_has_no_note() {
    let fit = Band::MEMORY.assess(32 * GIB, q("32Gi"));
    assert_eq!(fit, SizeFit::Meets);
    assert_eq!(fit.level(Level::Warn), Level::Pass);
    assert_eq!(fit.note(), None);
}

#[test]
fn a_band_of_zero_is_off_and_the_floor_goes_with_it() {
    let off = Band::MEMORY.with_percent(0.0);
    assert_eq!(off.width(q("32Gi")), 0);
    assert!(matches!(
        off.assess(gib(313), q("32Gi")),
        SizeFit::Below { .. }
    ));
    assert_eq!(Band::off().width(q("32Gi")), 0);
}

#[test]
fn tolerance_result_warn_turns_an_in_band_value_into_a_warn() {
    let fit = Band::MEMORY.assess(gib(313), q("32Gi"));
    assert_eq!(fit.level(Level::Warn), Level::Warn);
    // The severity cap leaves a warn alone.
    assert_eq!(
        cap_level(fit.level(Level::Warn), &Severity::Warn),
        Status::Warn
    );
}

#[test]
fn vram_uses_eight_percent() {
    // An L4 reports 23034 MiB for "24 GB". 24Gi less 8% is 22.08 GiB, which is 22610 MiB.
    let fit = Band::VRAM.assess(23_034 * MIB, q("24Gi"));
    assert!(matches!(fit, SizeFit::InBand { .. }), "{fit:?}");
    assert_eq!(
        fit.note().as_deref(),
        Some("22.5 GiB found, 24 GiB needed, inside the 8% tolerance")
    );
    // An H100 and an A100 give the same result for 80Gi.
    for have in [81_559 * MIB, 81_920 * MIB] {
        assert_eq!(
            Band::VRAM.assess(have, q("80Gi")).level(Level::Pass),
            Level::Pass
        );
    }
    assert_eq!(
        Band::VRAM.assess(16 * GIB, q("24Gi")).level(Level::Pass),
        Level::Fail
    );
}

#[test]
fn odd_percents_are_clamped_and_never_panic() {
    assert_eq!(Band::new(f64::NAN, q("1Gi")).width(q("32Gi")), 0);
    assert_eq!(Band::new(-3.0, q("1Gi")).width(q("32Gi")), 0);
    assert_eq!(Band::new(500.0, q("0")).width(q("32Gi")), 32 * GIB);
    let max = Quantity::parse("999999999999999").expect("max");
    assert_eq!(Band::new(100.0, q("0")).width(max), max.bytes());
    assert!(matches!(Band::MEMORY.assess(0, max), SizeFit::Below { .. }));
}
