# ADR 0025: install.sh refuses a cut-off copy by an end marker, stops when it cannot check a signature, and trusts only what it has hashed

- Status: Accepted, security-reviewed (PR #65)
- Date: 2026-10-29

## Context

06 ("Install and signing contract") and 05 (Surface 3, T2, E1, INV-19) fix what `install.sh` does. M1-014
builds the core: root refusal, the truncation guard, platform detection, download, the sha256 rule and an
atomic install. M1-015 adds the cosign check. M1-014 had to settle five things the contract leaves open.

## Decision

1. **Truncation guard with an end marker.** The file holds only assignments and function definitions
   until its last line, which is `main "$@" "$END_MARK"`. `main` refuses to run unless the last argument
   is the marker. 06 says only "all logic in `main()` called on the last line". That is not enough: a
   copy cut right after `main` (or `main "$@"`) is a complete command, and it would run the installer
   with the flags dropped. With the marker, a copy cut at any byte is a syntax error, a missing command,
   or a call that stops with "cut off". The test cuts at every byte of the last 500 and at every 13th
   byte before that, as a file and through `sh -s`, and checks that nothing was installed, no download
   was started and no temp file was left.
2. **Until M1-015, a copy stops as if cosign were missing.** `verify_signature` is the seam. In this
   version it returns only when `RDY_INSECURE_SKIP_SIGNATURE=1` (exactly `1`), with the loud warning.
   Otherwise it exits 1 with a message that says this copy cannot check signatures. A hash taken from
   the same place as the archive proves nothing about who built it, so the safe default is to stop. The
   stop message gives the manual path first: verify the release with `scripts/verify-release.sh` and the
   install docs (06, "Cosign missing"). It does not name the override. The override stays documented
   here and in 06 only. M1-015 replaces the body, downloads `SHA256SUMS.sigstore.json` in `main`, and
   keeps the override. The first alpha release (M1-012) may carry an `install.sh` from this ticket, so a
   user can see this message. Its release notes tell the user to verify with `scripts/verify-release.sh`.
3. **The hash rule is 05's.** The one `SHA256SUMS` line whose file name equals the archive name exactly
   (an optional `*` before the name is allowed). No line, two lines, or a hash that is not 64 lowercase
   hex digits stops the install. The tool is the first of `sha256sum`, `shasum -a 256`, `openssl dgst
   -sha256`. None means stop, before any download. A carriage return on any line of `SHA256SUMS` stops
   the install with its own message. Awks differ on whether `\r` belongs to a field (busybox awk treats it
   as a separator, so a CRLF list would match), so no rule may depend on it. The release workflow writes
   LF only.
4. **Version stamp.** `RDY_STAMPED_VERSION='@@RDY_STAMPED_VERSION@@'` is the only text `sign-release`
   (M1-010) changes. It writes the tag there, with or without a leading `v`. A copy with the
   placeholder still in it has no default: it needs `RDY_VERSION`. The version is limited to digits,
   letters, dots and dashes and the shape `N.N.N[-suffix]` before it reaches the URL. The new binary
   must print `rdy <version>` for that version before it is installed. A mismatch stops the install, so
   a swapped archive of another release is caught even without a signature.
5. **Stricter than 06 in a few small ways.**
   (a) curl gets `--proto-redir '=https'`, so a redirect cannot leave https.
   (b) wget is used only if `wget --help` lists `--https-only` and `--no-config` (GNU wget). BusyBox wget
   lists neither. The `--https-only` option limits recursive mode only. It does not stop a single-file
   download from following a redirect to plain http, so it is no transport guard. With wget, integrity
   rests on the signature check (M1-015) and the sha256 check, not on the transport. A host with only
   another wget gets "install curl". The documented command uses curl, so such a host has it.
   (c) Neither tool reads a user config. curl gets `-q` as its first argument and wget gets
   `--no-config`, so a `~/.curlrc` with `insecure` or a wgetrc with `check_certificate = off` cannot turn
   off certificate checks. The same flags ignore `CURL_HOME` and `WGETRC`. The CA variables
   (`SSL_CERT_FILE`, `CURL_CA_BUNDLE`) stay honored, because a proxy that re-signs TLS needs them.
   (d) A stalled download ends. curl gets `--speed-limit 1024 --speed-time 60` (under 1 KiB/s for 60
   seconds) and `--connect-timeout 20`. wget gets `--timeout=30 --read-timeout=60 --tries=3`.
   (e) The temporary file in the install folder comes from `mktemp "$dir/.rdy.new.XXXXXX"`, not a name
   built from `$$`.
   (f) The binary runs once from the work folder before it goes anywhere, so a `noexec` temp folder or a
   wrong-CPU file stops the install with a `TMPDIR` hint.
   (g) `fetch` takes an optional three-part message for a 404, so M1-015 can give the signature bundle
   06's "this release looks incomplete" wording. `SHA256SUMS` already uses it.
   (h) `--help` is the only way to ask for help. `-h` is an unknown option (06 lists `--allow-root` and
   `--help`). The unknown-option message prints the name up to `=`, so `--x=secret` does not reach stderr.

## Consequences

- The shell tests run under `dash`, `busybox sh` and `/bin/sh`. The busybox leg must use a busybox that
  looks up applets on `PATH`, as Alpine's does. The Debian and Ubuntu `busybox-static` runs its own
  `id`, `uname` and `sha256sum` first, so the stubs are ignored and the tests test the host. CI runs
  that leg in an Alpine container pinned by digest, and the harness proves before the suite that a stub
  `id` and `uname` win, and fails if not. The `sh` leg runs on the Intel macOS runner (bash in POSIX
  mode, BSD tools). A missing shell is a skip on a developer machine and a failure in CI.
- The Alpine digest is bumped by hand. Dependabot does not read it from a `docker run` line.
- A change to the last line of `install.sh` must keep the marker. The tests fail if it goes.
- The release job in M1-010 stamps the file with `sed` on the placeholder. A second copy of the
  placeholder in the file would be replaced too, so there is exactly one. A test counts it, and another
  stamps a copy with `sed` and installs from it.
- `RDY_VERSION` for a version that has no release gives "no file named" from the 404, not an API call.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| Guard only by calling `main` on the last line | A copy cut after `main` runs with its flags dropped. |
| Print a checksum of the whole script at the end and compare | The script cannot hash itself when it comes through a pipe. |
| In M1-014, skip the signature step with a warning | The default would be to trust an unsigned list. The safe default is to stop. |
| Fall back to busybox wget | It cannot refuse plain http redirects and has no `--no-config`. |
| Test busybox with Ubuntu `busybox-static` | It ignores the stubs. 14 of 69 cases failed in the first CI run. |
| Let the CRLF rule depend on awk | Awks disagree on `\r`. One rule: stop on any line that has one. |
