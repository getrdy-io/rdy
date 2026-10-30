//! Boundary tests of the parser and the judgement of `host.memory`. No probe, no runtime.

use proptest::prelude::*;
use rdy_engine::check::Level;
use rdy_engine::units::Band;
use rdy_spec::Quantity;
use rdy_spec::check::SwapPolicy;

use super::judge::{Cgroup, Facts, Limit, Rules, judge};
use super::meminfo::{self, Available};

const KIB: u64 = 1 << 10;
const MIB: u64 = 1 << 20;
const GIB: u64 = 1 << 30;

fn quantity(text: &str) -> Quantity {
    Quantity::parse(text).expect("a size")
}

fn rules(min: &str) -> Rules {
    let min = quantity(min);
    Rules {
        min,
        min_available: min.bytes() / 2,
        swap: SwapPolicy::Any,
        band: Band::MEMORY,
        in_band: Level::Pass,
    }
}

fn facts(total: u64) -> Facts {
    Facts {
        host_total: total,
        available: Some(Available {
            bytes: total,
            estimated: false,
        }),
        swap_total: Some(0),
        swap_free: Some(0),
        cgroup: Cgroup::default(),
        notes: Vec::new(),
    }
}

fn limited(total: u64, limit: u64, at: &str) -> Facts {
    let mut f = facts(total);
    f.cgroup.limit = Some(Limit {
        bytes: limit,
        at: at.to_owned(),
    });
    f
}

// ---- /proc/meminfo -----------------------------------------------------------------------------

#[test]
fn meminfo_values_are_kilobytes_turned_into_bytes() {
    let info = meminfo::parse(
        "MemTotal:       1000 kB\nMemFree: 10 kB\nMemAvailable:   500 kB\nSwapTotal: 8 kB\nSwapFree: 4 kB\n",
    )
    .expect("parses");
    assert_eq!(info.total, 1000 * KIB);
    assert_eq!(
        info.available,
        Some(Available {
            bytes: 500 * KIB,
            estimated: false
        })
    );
    assert_eq!(info.swap_total, Some(8 * KIB));
    assert_eq!(info.swap_free, Some(4 * KIB));
}

#[test]
fn without_memavailable_the_estimate_is_free_plus_buffers_plus_cached() {
    let info = meminfo::parse("MemTotal: 1000 kB\nMemFree: 100 kB\nBuffers: 10 kB\nCached: 1 kB\n")
        .expect("parses");
    assert_eq!(
        info.available,
        Some(Available {
            bytes: 111 * KIB,
            estimated: true
        })
    );
    // Free memory alone is an estimate too.
    let info = meminfo::parse("MemTotal: 1000 kB\nMemFree: 100 kB\n").expect("parses");
    assert_eq!(info.available.map(|a| a.bytes), Some(100 * KIB));
    // Nothing to estimate from.
    let info = meminfo::parse("MemTotal: 1000 kB\n").expect("parses");
    assert_eq!(info.available, None);
    assert_eq!(info.swap_total, None);
}

#[test]
fn available_memory_is_never_more_than_the_total() {
    let info = meminfo::parse("MemTotal: 1000 kB\nMemAvailable: 9999 kB\n").expect("parses");
    assert_eq!(info.available.map(|a| a.bytes), Some(1000 * KIB));
}

#[test]
fn a_meminfo_without_a_usable_total_is_refused() {
    for bad in [
        "",
        "\n\n",
        "MemFree: 5 kB\n",
        "MemTotal: lots kB\n",
        "MemTotal: 0 kB\n",
        "MemTotal: 1000\n",
        "MemTotal: 1000 MB\n",
        "MemTotal: -5 kB\n",
        "MemTotal: 1000 kB extra\n",
        "MemTotal: 18446744073709551615 kB\n",
        "MemTotal 1000 kB\n",
        "\u{0}\u{0}",
    ] {
        assert!(meminfo::parse(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn a_bad_line_does_not_hide_a_good_one_and_the_first_total_wins() {
    let info = meminfo::parse("MemAvailable: x kB\nMemTotal: 7 kB\nMemTotal: 9 kB\n").expect("ok");
    assert_eq!(info.total, 7 * KIB);
    assert_eq!(info.available, None);
}

proptest! {
    #[test]
    fn meminfo_parsing_never_panics_on_arbitrary_text(text in ".{0,2000}") {
        let _ = meminfo::parse(&text);
    }

    #[test]
    fn meminfo_parsing_never_panics_on_lines_shaped_like_meminfo(
        key in "[A-Za-z_()]{0,12}",
        value in "[0-9a-z -]{0,24}",
        unit in "( kB| KB| mB|)",
    ) {
        let text = format!("MemTotal: 1 kB\n{key}:{value}{unit}\nMemFree:{value}{unit}\n");
        let _ = meminfo::parse(&text);
    }
}

// ---- the total, at its edges -------------------------------------------------------------------

#[test]
fn the_total_is_met_exactly_at_min_and_one_byte_below_is_in_the_band() {
    let r = rules("32Gi");
    let at = judge(&r, &facts(32 * GIB));
    assert_eq!(at.level, Level::Pass);
    assert_eq!(at.message, "32 GiB found, 32 GiB needed");
    assert!(at.notes.is_empty());
    let below = judge(&r, &facts(32 * GIB - 1));
    assert_eq!(below.level, Level::Pass);
    assert!(below.message.ends_with("inside the 5% tolerance"));
}

#[test]
fn the_band_edge_is_5_percent_of_min_and_the_byte_after_it_blocks() {
    let r = rules("32Gi");
    let width = 32 * GIB / 20;
    // 5% of 32 GiB is not a whole number of bytes: the band is the floor of it.
    let edge = judge(&r, &facts(32 * GIB - width));
    assert_eq!(edge.level, Level::Pass);
    let past = judge(&r, &facts(32 * GIB - width - 1));
    assert_eq!(past.level, Level::Fail);
}

#[test]
fn a_small_min_gets_the_256_mib_floor_but_never_more_than_half() {
    // 4Gi: 5% is 205 MiB, the floor of 256 MiB wins.
    let r = rules("4Gi");
    assert_eq!(judge(&r, &facts(4 * GIB - 256 * MIB)).level, Level::Pass);
    assert_eq!(
        judge(&r, &facts(4 * GIB - 256 * MIB - 1)).level,
        Level::Fail
    );
    // 400Mi: the floor is capped at half of min, so 100Mi still blocks and 200Mi passes.
    let r = rules("400Mi");
    assert_eq!(judge(&r, &facts(200 * MIB)).level, Level::Pass);
    assert_eq!(judge(&r, &facts(200 * MIB - 1)).level, Level::Fail);
}

#[test]
fn tolerance_result_warn_turns_only_the_band_into_a_warning() {
    let mut r = rules("32Gi");
    r.in_band = Level::Warn;
    assert_eq!(judge(&r, &facts(32 * GIB)).level, Level::Pass);
    assert_eq!(judge(&r, &facts(31 * GIB)).level, Level::Warn);
    assert_eq!(judge(&r, &facts(24 * GIB)).level, Level::Fail);
}

// ---- cgroup ------------------------------------------------------------------------------------

#[test]
fn the_cgroup_limit_is_judged_instead_of_the_host_when_it_is_smaller() {
    let r = rules("8Gi");
    let f = judge(&r, &limited(64 * GIB, 4 * GIB, "/system.slice/acme.slice"));
    assert_eq!(f.level, Level::Fail);
    assert_eq!(
        f.message,
        "4 GiB found, 8 GiB needed, limited by cgroup /system.slice/acme.slice, host has 64 GiB"
    );
    // A limit equal to the host or above it does not bind.
    for limit in [64 * GIB, 65 * GIB] {
        let f = judge(&r, &limited(64 * GIB, limit, "/x"));
        assert_eq!(f.level, Level::Pass);
        assert!(!f.message.contains("limited"));
    }
}

#[test]
fn the_fix_for_a_limit_depends_on_who_set_it() {
    let r = rules("8Gi");
    let fix = |at: &str| {
        judge(&r, &limited(64 * GIB, 4 * GIB, at))
            .fix
            .expect("a fix")
    };
    assert!(
        fix("/system.slice/acme-api.service")
            .contains("`systemctl set-property acme-api.service MemoryMax=8G`")
    );
    assert!(
        fix("/kubepods.slice/kubepods-burstable.slice/pod1/c1").contains("memory limit of the pod")
    );
    assert!(fix("/docker/0123abcd").contains("memory limit of the container"));
    assert!(fix("/system.slice/docker-0123abcd.scope").contains("memory limit of the container"));
    assert!(fix("/").contains("run rdy outside the cgroup"));
    // A name that could carry shell syntax never reaches a command.
    let hostile = fix("/system.slice/a;b.service");
    assert!(!hostile.contains("set-property"), "{hostile}");
    assert!(hostile.contains("run rdy outside the cgroup"));
}

#[test]
fn the_memory_max_size_is_whole_gib_or_rounded_up_mib() {
    let fix = |min: &str| {
        let mut r = rules(min);
        r.band = Band::off();
        let half = r.min.bytes() / 2;
        judge(&r, &limited(64 * GIB, half, "/a.service"))
            .fix
            .expect("a fix")
    };
    assert!(fix("8Gi").contains("MemoryMax=8G`"));
    assert!(fix("1536Mi").contains("MemoryMax=1536M`"));
    assert!(fix("1537Ki").contains("MemoryMax=2M`"));
}

#[test]
fn a_cgroup_path_in_a_sentence_has_no_control_characters_and_a_bound() {
    let r = rules("8Gi");
    let long = format!("/system.slice/{}", "a".repeat(400));
    let f = judge(&r, &limited(64 * GIB, GIB, &long));
    assert!(f.message.len() < 300, "{}", f.message.len());
    assert!(f.message.contains("..."));
    let f = judge(&r, &limited(64 * GIB, GIB, "/a\n\u{1b}[31mb"));
    assert!(!f.message.chars().any(char::is_control), "{:?}", f.message);
}

// ---- available and swap ------------------------------------------------------------------------

#[test]
fn available_below_min_available_warns_and_at_it_passes() {
    let r = rules("8Gi");
    let mut f = facts(16 * GIB);
    f.available = Some(Available {
        bytes: 4 * GIB,
        estimated: false,
    });
    assert_eq!(judge(&r, &f).level, Level::Pass);
    f.available = Some(Available {
        bytes: 4 * GIB - 1,
        estimated: false,
    });
    assert_eq!(judge(&r, &f).level, Level::Warn);
    f.available = None;
    let unknown = judge(&r, &f);
    assert_eq!(unknown.level, Level::Pass);
    assert!(
        unknown
            .notes
            .iter()
            .any(|n| n.contains("could not be read"))
    );
}

#[test]
fn swap_forbid_blocks_on_any_swap_and_passes_with_none_or_unreported() {
    let mut r = rules("8Gi");
    r.swap = SwapPolicy::Forbid;
    let mut f = facts(16 * GIB);
    f.swap_total = Some(1);
    assert_eq!(judge(&r, &f).level, Level::Fail);
    f.swap_total = Some(0);
    assert_eq!(judge(&r, &f).level, Level::Pass);
    f.swap_total = None;
    let none = judge(&r, &f);
    assert_eq!(none.level, Level::Pass);
    assert!(
        none.notes
            .iter()
            .any(|n| n.contains("does not report swap"))
    );
}

#[test]
fn swap_free_above_total_does_not_underflow() {
    let r = rules("8Gi");
    let mut f = facts(16 * GIB);
    f.swap_total = Some(GIB);
    f.swap_free = Some(2 * GIB);
    assert_eq!(judge(&r, &f).observed["swap_used_bytes"], 0);
}

proptest! {
    #[test]
    fn the_judgement_never_panics_and_a_fix_comes_with_every_non_pass(
        total in 1_u64..=u64::MAX,
        limit in proptest::option::of(0_u64..=u64::MAX),
        avail in proptest::option::of(0_u64..=u64::MAX),
        swap in proptest::option::of(0_u64..=u64::MAX),
        free in proptest::option::of(0_u64..=u64::MAX),
        min in 1_u64..=(1_u64 << 44),
        forbid in any::<bool>(),
    ) {
        let mut r = rules("1Gi");
        r.min = quantity(&min.to_string());
        r.min_available = min / 2;
        r.swap = if forbid { SwapPolicy::Forbid } else { SwapPolicy::Any };
        let mut f = facts(total);
        f.available = avail.map(|bytes| Available { bytes, estimated: false });
        f.swap_total = swap;
        f.swap_free = free;
        f.cgroup.limit = limit.map(|bytes| Limit { bytes, at: "/a".to_owned() });
        let finding = judge(&r, &f);
        prop_assert_eq!(finding.level != Level::Pass, finding.fix.is_some());
    }
}
