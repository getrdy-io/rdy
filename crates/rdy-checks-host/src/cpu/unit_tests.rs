//! Unit tests of the pure parts of `host.cpu`: the parsers, the levels and the wording helpers.

use std::collections::BTreeSet;

use super::parse::{
    CpuList, has_feature, level_gaps, level_of, looks_virtual, normalize, normalize_arch,
    parse_cpuinfo, x86_level,
};
use super::*;

fn set(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|n| (*n).to_owned()).collect()
}

fn count(text: &str) -> Option<u64> {
    CpuList::parse(text).map(|l| l.count())
}

#[test]
fn a_cpu_list_counts_ranges_singles_and_overlaps() {
    assert_eq!(count("0-7"), Some(8));
    assert_eq!(count("0"), Some(1));
    assert_eq!(count("0-3,8,10-11\n"), Some(7));
    // Overlapping and adjacent ranges merge, so nothing counts twice.
    assert_eq!(count("0-3,2-5,6"), Some(7));
    assert_eq!(count(" 4 - 5 "), Some(2), "stray spaces are tolerated");
    assert_eq!(count("4-5, 8"), Some(3));
}

#[test]
fn a_malformed_cpu_list_is_none() {
    for bad in [
        "",
        "\n",
        "a",
        "3-1",
        "1-",
        "-2",
        "1,,2",
        "0-x",
        "1-2-3",
        "99999999999",
        "0-2000000",
    ] {
        assert_eq!(count(bad), None, "{bad:?}");
    }
    let many = (0..5000)
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(",");
    assert_eq!(count(&many), None, "more items than rdy reads");
}

#[test]
fn two_cpu_lists_intersect_by_number() {
    let online = CpuList::parse("0-7").expect("a list");
    let allowed = CpuList::parse("0-1,6-9").expect("a list");
    assert_eq!(allowed.common(&online), 4);
    assert_eq!(online.common(&allowed), 4);
    let none = CpuList::parse("20-21").expect("a list");
    assert_eq!(none.common(&online), 0);
}

#[test]
fn a_count_without_ids_makes_a_list_from_zero() {
    assert_eq!(CpuList::first(4).map(|l| l.count()), Some(4));
    assert!(CpuList::first(0).is_none());
}

#[test]
fn the_allowed_list_comes_from_the_status_file() {
    let status = "Name:\trdy\nCpus_allowed:\tff\nCpus_allowed_list:\t0-3\nMems_allowed_list:\t0\n";
    assert_eq!(parse::allowed_list(status).map(|l| l.count()), Some(4));
    assert!(parse::allowed_list("Name:\trdy\n").is_none());
    assert!(parse::allowed_list("Cpus_allowed_list:\tnonsense\n").is_none());
}

const TWO: &str = "processor\t: 0\nphysical id\t: 0\ncore id\t\t: 0\nflags\t\t: fpu avx2 avx512f bmi2\n\nprocessor\t: 1\nphysical id\t: 0\ncore id\t\t: 0\nflags\t\t: fpu avx2 bmi2\n\n";

#[test]
fn a_feature_counts_only_when_every_processor_shows_it() {
    let info = parse_cpuinfo(TWO, false);
    assert_eq!(info.processors, 2);
    // A hybrid CPU: only the first core has avx512f.
    assert_eq!(info.flags, Some(set(&["fpu", "avx2", "bmi2"])));
    // Two threads of one core are one physical core.
    assert_eq!(info.physical_cores, Some(1));
}

#[test]
fn a_cut_read_drops_the_last_block() {
    let cut = "processor\t: 0\nflags\t\t: fpu avx2 bmi2\n\nprocessor\t: 1\nflags\t\t: fpu avx";
    let info = parse_cpuinfo(cut, true);
    assert_eq!(info.processors, 1);
    assert_eq!(info.flags, Some(set(&["fpu", "avx2", "bmi2"])));
    assert_eq!(
        info.physical_cores, None,
        "a cut file does not give a core count"
    );
    // The same text read whole is judged whole.
    assert_eq!(parse_cpuinfo(cut, false).processors, 2);
    // The count of a cut read is marked, so it is never used as the number of CPUs.
    assert!(info.cut && !parse_cpuinfo(cut, false).cut);
}

#[test]
fn arm_features_and_a_file_without_flags_parse() {
    let arm = "processor\t: 0\nBogoMIPS\t: 50.00\nFeatures\t: fp asimd aes\nCPU architecture: 8\n";
    let info = parse_cpuinfo(arm, false);
    assert_eq!(info.flags, Some(set(&["fp", "asimd", "aes"])));
    assert_eq!(info.physical_cores, None);
    let bare = parse_cpuinfo("processor\t: 0\nmodel name\t: x\n", false);
    assert_eq!((bare.processors, bare.flags), (1, None));
    let empty = parse_cpuinfo("", false);
    assert_eq!((empty.processors, empty.flags), (0, None));
}

#[test]
fn nothing_but_flags_and_counts_survives_the_parse() {
    // Old Arm boards print a serial number in a block of their own. The parse keeps no such line.
    let text = "processor\t: 0\nmodel name\t: Acme CPU REDACTED-TEST-MODEL\nflags\t\t: fpu\n\nHardware\t: Acme board\nRevision\t: 0042\nSerial\t\t: REDACTED-TEST-TOKEN\n";
    let info = parse_cpuinfo(text, false);
    let shown = format!("{info:?}");
    for planted in ["REDACTED-TEST-TOKEN", "REDACTED-TEST-MODEL", "Acme", "0042"] {
        assert!(!shown.contains(planted), "{planted} kept: {shown}");
    }
    assert_eq!(
        info.processors, 1,
        "a block with no processor line is not a CPU"
    );
}

#[test]
fn x86_levels_are_the_highest_one_whose_features_are_all_there() {
    let v1 = [
        "cmov", "cx8", "fpu", "fxsr", "mmx", "syscall", "sse", "sse2",
    ];
    let v2 = [
        "cx16", "lahf_lm", "popcnt", "pni", "sse4_1", "sse4_2", "ssse3",
    ];
    let v3 = [
        "avx", "avx2", "bmi1", "bmi2", "f16c", "fma", "abm", "movbe", "xsave",
    ];
    let v4 = ["avx512f", "avx512bw", "avx512cd", "avx512dq", "avx512vl"];
    let mut have = set(&[]);
    assert_eq!(x86_level(&have), 0);
    have.extend(v1.map(str::to_owned));
    assert_eq!(x86_level(&have), 1);
    have.extend(v2.map(str::to_owned));
    assert_eq!(x86_level(&have), 2);
    have.extend(v3.map(str::to_owned));
    assert_eq!(x86_level(&have), 3);
    have.extend(v4.map(str::to_owned));
    assert_eq!(x86_level(&have), 4);
    // One missing feature drops the level to the one below, whatever else is there.
    have.remove("movbe");
    assert_eq!(x86_level(&have), 2);
    assert_eq!(level_gaps(&have, 3), vec!["movbe"]);
    assert_eq!(level_gaps(&have, 2), Vec::<&str>::new());
}

#[test]
fn a_level_is_named_with_dashes_or_underscores() {
    assert_eq!(level_of("x86-64-v3"), Some(3));
    assert_eq!(level_of("X86_64_V2"), Some(2));
    assert_eq!(level_of("x86-64-v4"), Some(4));
    assert_eq!(level_of("x86-64-v9"), None);
    assert_eq!(level_of("avx2"), None);
}

#[test]
fn feature_names_match_by_alias_and_ignore_dash_and_case() {
    let have = set(&["abm", "pni", "asimd", "sse4_2"]);
    assert!(has_feature(&have, "lzcnt"));
    assert!(has_feature(&have, "abm"));
    assert!(has_feature(&have, "sse3"));
    assert!(has_feature(&have, "NEON"));
    assert!(has_feature(&have, "sse4-2"));
    assert!(!has_feature(&have, "avx2"));
    assert_eq!(normalize(" SSE4-2 "), "sse4_2");
}

#[test]
fn machine_types_fold_to_the_two_spec_names() {
    for (raw, want) in [
        ("x86_64", "x86_64"),
        ("amd64", "x86_64"),
        ("AMD64", "x86_64"),
        ("aarch64", "aarch64"),
        ("arm64", "aarch64"),
        ("riscv64", "riscv64"),
        ("s390x\n", "s390x"),
    ] {
        assert_eq!(normalize_arch(raw), want, "{raw:?}");
    }
}

#[test]
fn dmi_text_tells_a_virtual_machine_from_a_server() {
    for vm in [
        "KVM Virtual Machine",
        "QEMU",
        "VMware7,1",
        "HVM domU",
        "Google Compute Engine",
        "Amazon EC2",
    ] {
        assert!(looks_virtual(vm), "{vm}");
    }
    for metal in ["ProLiant RL300 Gen11", "Acme Server 2U", "Ampere Altra"] {
        assert!(!looks_virtual(metal), "{metal}");
    }
}

#[test]
fn the_cpu_count_reads_as_a_person_would_say_it() {
    assert_eq!(vcpus(8000), "8 vCPUs");
    assert_eq!(vcpus(1000), "1 vCPU");
    assert_eq!(vcpus(1500), "1.5 vCPUs");
    // A fraction is cut, never rounded up, so 1.99 never reads as 2.
    assert_eq!(vcpus(1990), "1.9 vCPUs");
    assert_eq!(vcpus(500), "0.5 vCPUs");
    assert_eq!(vcpus(0), "0 vCPUs");
}

#[test]
fn a_quota_is_kept_exact_in_thousandths() {
    let q = |quota_us, period_us| {
        quota_milli(&CpuQuota {
            quota_us,
            period_us,
        })
    };
    assert_eq!(q(200_000, 100_000), 2000);
    assert_eq!(q(150_000, 100_000), 1500);
    assert_eq!(q(50_000, 100_000), 500);
    assert_eq!(q(100_000, 50_000), 2000);
    assert_eq!(q(u64::MAX, 1), u64::MAX, "a huge quota does not wrap");
}

#[test]
fn names_list_with_and_and_a_cap() {
    let names = |n: usize| (0..n).map(|i| format!("f{i}")).collect::<Vec<_>>();
    assert_eq!(list(&names(0)), "");
    assert_eq!(list(&names(1)), "f0");
    assert_eq!(list(&names(3)), "f0, f1 and f2");
    assert_eq!(
        list(&names(10)),
        "f0, f1, f2, f3, f4, f5, f6, f7 and 2 more"
    );
}

#[test]
fn the_worse_level_wins() {
    assert_eq!(raise(Level::Pass, Level::Warn), Level::Warn);
    assert_eq!(raise(Level::Warn, Level::Pass), Level::Warn);
    assert_eq!(raise(Level::Warn, Level::Fail), Level::Fail);
    assert_eq!(raise(Level::Fail, Level::Warn), Level::Fail);
    assert_eq!(raise(Level::Pass, Level::Pass), Level::Pass);
}

#[test]
fn the_constructor_folds_names_and_drops_duplicates() {
    let check = CpuCheck::new(
        Some(4),
        None,
        ["amd64".to_owned(), "x86_64".to_owned(), "arm64".to_owned()],
        [
            "AVX2".to_owned(),
            "avx2".to_owned(),
            " ".to_owned(),
            "x86-64-v3".to_owned(),
        ],
    );
    assert_eq!(check.arch, ["aarch64", "x86_64"]);
    assert_eq!(check.flags, ["avx2", "x86-64-v3"]);
}

#[test]
fn no_parser_panics_on_truncated_or_hostile_text() {
    let sample = format!("{TWO}Hardware\t: x\n\n\n\n:\n: :\nflags\n");
    for end in 0..=sample.len() {
        if !sample.is_char_boundary(end) {
            continue;
        }
        let part = &sample[..end];
        let _ = parse_cpuinfo(part, true);
        let _ = parse_cpuinfo(part, false);
        let _ = CpuList::parse(part);
        let _ = parse::allowed_list(part);
    }
    for hostile in [
        "\0\0\0",
        "\u{202e}0-3",
        "0-\u{0661}",
        "processor\t: \n\n\n",
        "flags: \n",
    ] {
        let _ = parse_cpuinfo(hostile, false);
        let _ = CpuList::parse(hostile);
    }
}
