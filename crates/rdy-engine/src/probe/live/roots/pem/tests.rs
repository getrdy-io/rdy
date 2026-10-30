//! Tests of the PEM trust store reader, on temporary directories. The environment variables are passed in
//! as values (`Sources::new`), because setting them in a test would need `unsafe`.

#![allow(clippy::expect_used)]

use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use tempfile::TempDir;

use super::*;
use crate::testing::loopback::TestCa;

fn der(ca: &TestCa) -> Vec<u8> {
    ca.root_der().as_ref().to_vec()
}

fn none() -> Secrets {
    Secrets::default()
}

/// Standard paths that lead nowhere, so a test never reads the machine's real store.
fn nowhere(root: &Path) -> Sources {
    Sources::new(None, None)
        .with_standard(vec![root.join("no-bundle.crt")], vec![root.join("no-dir")])
}

fn explicit(file: Option<&Path>, dirs: &[&Path], root: &Path) -> Sources {
    let dirs = std::env::join_paths(dirs).expect("a path list");
    Sources::new(
        file.map(|f| f.as_os_str().to_owned()),
        (!dirs.is_empty()).then_some(dirs),
    )
    .with_standard(vec![root.join("no-bundle.crt")], vec![root.join("no-dir")])
}

fn dir() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = fs::canonicalize(dir.path()).expect("real path");
    (dir, root)
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0_u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A PEM block around `payload`. The bytes are not a certificate, which the reader does not check.
fn fake_pem(payload: &[u8]) -> String {
    let body = base64(payload);
    let mut text = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in body.as_bytes().chunks(64) {
        text.push_str(std::str::from_utf8(line).expect("ascii"));
        text.push('\n');
    }
    text.push_str("-----END CERTIFICATE-----\n");
    text
}

#[test]
fn ssl_cert_file_is_read_and_nothing_else_is() {
    let (_guard, root) = dir();
    let (a, b) = (TestCa::root("Root A"), TestCa::root("Root B"));
    let bundle = root.join("bundle.pem");
    fs::write(&bundle, format!("{}\n{}", a.root_pem(), b.root_pem())).expect("write");
    // A standard bundle exists too. With the variable set, it is not read.
    let standard = root.join("standard.crt");
    fs::write(&standard, TestCa::root("Standard").root_pem()).expect("write");
    let sources = Sources::new(Some(bundle.into_os_string()), None)
        .with_standard(vec![standard], vec![root.join("no-dir")]);
    let roots = load(&sources, &none()).expect("roots");
    assert_eq!(roots, [der(&a), der(&b)]);
}

#[test]
fn ssl_cert_dir_reads_certificate_names_only_and_keeps_each_root_once() {
    let (_guard, root) = dir();
    let certs = root.join("certs");
    fs::create_dir(&certs).expect("dir");
    let (a, b, c) = (
        TestCa::root("Root A"),
        TestCa::root("Root B"),
        TestCa::root("Root C"),
    );
    fs::write(certs.join("a.pem"), a.root_pem()).expect("write");
    fs::write(certs.join("B.CRT"), b.root_pem()).expect("write");
    // A rehash link repeats a root, and a link may point outside the directory.
    symlink(certs.join("a.pem"), certs.join("1a2b3c4d.0")).expect("link");
    fs::write(certs.join("notes.txt"), c.root_pem()).expect("write");
    fs::write(certs.join("1a2b3c4d.x"), c.root_pem()).expect("write");
    fs::create_dir(certs.join("sub.pem")).expect("a directory named like a file");
    let elsewhere = root.join("elsewhere.cer");
    fs::write(&elsewhere, c.root_pem()).expect("write");
    symlink(&elsewhere, certs.join("c.cer")).expect("link");

    let sources = explicit(None, &[&certs], &root);
    let roots = load(&sources, &none()).expect("roots");
    assert_eq!(roots.len(), 3, "a, b and c once each");
    for ca in [&a, &b, &c] {
        assert!(roots.contains(&der(ca)));
    }
}

#[test]
fn a_list_of_directories_and_a_file_are_all_read() {
    let (_guard, root) = dir();
    let (one, two, three) = (root.join("one"), root.join("two"), root.join("three.pem"));
    fs::create_dir(&one).expect("dir");
    fs::create_dir(&two).expect("dir");
    let cas: Vec<TestCa> = (0..3).map(|i| TestCa::root(&format!("Root {i}"))).collect();
    fs::write(one.join("x.pem"), cas[0].root_pem()).expect("write");
    fs::write(two.join("y.pem"), cas[1].root_pem()).expect("write");
    fs::write(&three, cas[2].root_pem()).expect("write");
    let sources = explicit(Some(&three), &[&one, &two], &root);
    let roots = load(&sources, &none()).expect("roots");
    assert_eq!(roots.len(), 3);
}

#[test]
fn without_the_variables_the_first_standard_bundle_that_reads_is_used() {
    let (_guard, root) = dir();
    let (first, second) = (TestCa::root("First"), TestCa::root("Second"));
    let (one, two) = (root.join("one.crt"), root.join("two.crt"));
    fs::write(&one, first.root_pem()).expect("write");
    fs::write(&two, second.root_pem()).expect("write");
    let certs = root.join("certs");
    fs::create_dir(&certs).expect("dir");
    fs::write(certs.join("z.pem"), TestCa::root("Dir").root_pem()).expect("write");
    let sources = Sources::new(None, None).with_standard(
        vec![root.join("missing.crt"), one, two],
        vec![certs.clone()],
    );
    let roots = load(&sources, &none()).expect("roots");
    assert_eq!(
        roots,
        [der(&first)],
        "the bundle wins and the directory is not read"
    );

    // With no bundle, the standard directories are read.
    let sources =
        Sources::new(None, None).with_standard(vec![root.join("missing.crt")], vec![certs]);
    assert_eq!(load(&sources, &none()).expect("roots").len(), 1);
}

#[test]
fn a_machine_with_no_store_has_an_empty_one_and_a_named_source_that_is_missing_is_an_error() {
    let (_guard, root) = dir();
    // A scratch image with no `ca-certificates`: an empty list, not a failure.
    assert_eq!(
        load(&nowhere(&root), &none()).expect("empty"),
        Vec::<Vec<u8>>::new()
    );

    let sources = explicit(Some(&root.join("gone.pem")), &[], &root);
    let error = load(&sources, &none()).expect_err("the named file is missing");
    assert_eq!(error.kind(), io::ErrorKind::NotFound);

    // A named file that holds no certificate is an empty store.
    let empty = root.join("empty.pem");
    fs::write(&empty, "not a certificate\n").expect("write");
    let sources = explicit(Some(&empty), &[], &root);
    assert!(load(&sources, &none()).expect("empty").is_empty());
}

#[test]
fn empty_variables_are_not_set() {
    let sources = Sources::new(Some(OsString::new()), Some(OsString::from(":")));
    assert!(sources.file.is_none());
    assert!(sources.dirs.is_empty());
}

#[test]
fn the_count_and_the_size_of_the_answer_are_capped() {
    let (_guard, root) = dir();
    let bundle = root.join("big.pem");
    let mut text = String::new();
    for i in 0..(MAX_SYSTEM_ROOTS + 50) {
        text.push_str(&fake_pem(format!("certificate number {i}").as_bytes()));
    }
    // One certificate over the size cap, first in the file: it is dropped, not cut.
    let oversize = vec![7_u8; MAX_ROOT_BYTES + 1];
    let at_cap = vec![8_u8; MAX_ROOT_BYTES];
    let text = format!("{}{}{text}", fake_pem(&oversize), fake_pem(&at_cap));
    fs::write(&bundle, text).expect("write");
    let roots = load(&explicit(Some(&bundle), &[], &root), &none()).expect("roots");
    assert_eq!(roots.len(), MAX_SYSTEM_ROOTS);
    assert_eq!(roots[0], at_cap, "the largest allowed certificate is kept");
    assert!(roots.iter().all(|der| der.len() <= MAX_ROOT_BYTES));
    assert!(!roots.contains(&oversize));
}

#[test]
fn certificate_names() {
    for name in [
        "a.pem",
        "A.PEM",
        "ca-bundle.crt",
        "root.cer",
        "1a2b3c4d.0",
        "DEADBEEF.12",
    ] {
        assert!(certificate_name(name), "{name}");
    }
    for name in [
        "notes.txt",
        "1a2b3c4d.",
        "1a2b3c4.0",
        "1a2b3c4d.x",
        "1a2b3c4dd.0",
        "pem",
        "key.pem.bak",
        "",
    ] {
        assert!(!certificate_name(name), "{name}");
    }
}
