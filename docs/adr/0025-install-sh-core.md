# ADR 0025: install.sh refuses a cut-off copy by an end marker, stops when it cannot check a signature, and trusts only what it has hashed

- Status: Accepted (M1-014). security-reviewer confirms it with the M1-015 signature check.
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
   the same place as the archive proves nothing about who built it, so the safe default is to stop. M1-015
   replaces the body, downloads `SHA256SUMS.sigstore.json` in `main`, and keeps the override. No alpha
   ships before M1-015, so no user sees this message.
3. **The hash rule is 05's.** The one `SHA256SUMS` line whose file name equals the archive name exactly
   (an optional `*` before the name is allowed). No line, two lines, or a hash that is not 64 lowercase
   hex digits stops the install. The tool is the first of `sha256sum`, `shasum -a 256`, `openssl dgst
   -sha256`. None means stop, before any download. A CRLF list fails closed because the names no longer
   match.
4. **Version stamp.** `RDY_STAMPED_VERSION='@@RDY_STAMPED_VERSION@@'` is the only text `sign-release`
   (M1-010) changes. It writes the tag there, with or without a leading `v`. A copy with the
   placeholder still in it has no default: it needs `RDY_VERSION`. The version is limited to digits,
   letters, dots and dashes and the shape `N.N.N[-suffix]` before it reaches the URL. The new binary
   must print `rdy <version>` for that version before it is installed. A mismatch stops the install, so
   a swapped archive of another release is caught even without a signature.
5. **Stricter than 06 in four small ways.** (a) curl gets `--proto-redir '=https'`, so a redirect cannot
   leave https. (b) wget is used only if `wget --help` lists `--https-only` (GNU wget). BusyBox wget has
   no such option and may follow a redirect to http. A host with only that wget gets "install curl". The
   documented command uses curl, so such a host has it. (c) The temporary file in the install folder
   comes from `mktemp "$dir/.rdy.new.XXXXXX"`, not a name built from `$$`. (d) The binary runs once from
   the work folder before it goes anywhere, so a `noexec` temp folder or a wrong-CPU file stops the
   install with a `TMPDIR` hint.

## Consequences

- The shell tests need `dash` and `busybox`. CI installs `busybox-static` with apt and fails if either
  shell is missing. A developer machine skips a missing shell.
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
| Fall back to busybox wget | It cannot refuse plain http redirects. |
