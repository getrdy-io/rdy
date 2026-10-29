# ADR 0033: `trust add` takes a key as a file or as text, refuses secret keys by form, and edits the store through `rdy-spec`

- Status: Proposed (2026-10-29, M1-131). Fills gaps in 01 section 4.3 and 07 A.10 and C.10. It becomes
  Accepted when the security-reviewer signs off (M1-132).
- Date: 2026-10-29

## Context

07 says `trust add --key <key>` takes "a .pub file, or the key text" and must refuse a secret key, with a
different fix line when the text of the secret key was on the command line. It does not say how rdy tells
a file name from key text, whether a `.pub` file may be a symlink, or how a command edits a store that
`rdy-spec` only reads and writes whole. `TrustStore` had no way to list, add or remove an entry: its
pins were private, and `trust add` has to show, add and delete entries.

M1-126 gives `run --key` and `verify --key` the same argument, so the rule has to live in one place.

## Decision

1. **Key text or file name.** The argument is judged after its leading and trailing white space is cut
   off. It is key text when it has a line break, starts with `untrusted comment:`, or is one line of base64
   that starts with `RW` and is at least 40 characters (the algorithm bytes `Ed` encode as `RW`). Anything
   else is a file name. No real file name has that shape. The code is `signing::pubkey::resolve`. The
   secret key test (decision 2) runs first, on the trimmed argument, so a secret key pasted with a stray
   space or carriage return is still key text and never reaches the file-name path, where a "no such file"
   error would print it.
2. **A secret key is refused by its form, from a file or from text.** A line that decodes to the 158 bytes
   of a minisign secret key record counts, and so does a comment line that opens as rdy or minisign write
   it for a secret key (`rdy secret key`, `minisign encrypted secret key`). The words "secret key"
   elsewhere in a comment do not count: the repo's own public key fixture says "The secret key was
   discarded". A damaged or too costly secret key is still a secret key. Nothing of the text is echoed or
   kept in an error. For text the fix adds that the key is now in the shell history.
3. **A `.pub` file may be a symlink.** The private-file rules of `read_private` (no symlink, owner and mode)
   protect a secret. A public key has none, and the person who runs the command names the file and then
   compares the fingerprint with the vendor's. The file must be a regular file, at most 1024 bytes. The
   path is checked with `stat` first, which follows a symlink, and a target that is not a regular file
   (a device, a pipe, a folder) is refused before it is opened, because opening some devices has side
   effects and the command may run under `sudo`. The open does not block, so a pipe that appears in the
   gap cannot hang the command. After the open, the device and inode of the handle are compared with what
   `stat` saw, so a path swapped in between is refused.
4. **The store is edited through three additive `rdy-spec` items** (ADR 0007): `TrustStore::entries`,
   `TrustStore::add` and `TrustStore::remove`, with `TrustEntry` and `TrustAddError`. `add` applies the
   checks `from_yaml` applies (time form, note rules, no second key id for a product), so text this crate
   writes always reads back. `entries` and `remove` see only entries that are kept in a file, never a
   one-run key. The pin list stays private. `add` accepts only the system and user sources and refuses a
   one-run source (`TrustAddError::NotAStore`), so the format crate cannot be made to keep a `--key` key.
5. **Order of `trust add`.** Everything that can fail without asking comes first: platform, product name,
   key, store (read and checked), the new entry in memory. Then, with no terminal and no `--yes`, it
   refuses before it prints the key. Only then does it print the key and ask. After a yes it reads the
   store again, adds the key to that fresh copy (the duplicate check runs again) and writes it. The copy
   from before the question is only a check and is never written. `trust remove` never asks: it only takes
   trust away.
6. **A duplicate is only checked in the store that is written.** The same key id for a product in the
   other store is harmless, because lookup tries every key that has the id.

## Consequences

- A file named like a key (`RW...`, 40 or more base64 characters, no dot) is read as key text. A user who
  does that on purpose gets "not a usable public key", never a wrong trust decision.
- A symlinked `.pub` file is followed. The fingerprint check by a person is the control, as for any file the
  vendor sent.
- `rdy-spec` grows by two types and three methods before its first release. They are covered by its tests.
- Reading the store again after the yes keeps a change made while the question was open: a key removed
  after a compromise is not brought back by a late yes. A small gap remains between that second read and
  the rename. Two `trust add` runs, or an add and a remove, in that gap can still lose one change (read,
  change, rename, with no lock). The last writer wins and the file is never half written. M2-107 adds a
  lock on the store folder across load and save, and closes the gap. A remove done while an add waits at
  its prompt is already safe.
- `rdy-spec` refuses to add a one-run key to a store, so a later caller cannot write one to a file by
  mistake.

## What the build does that the examples do not show

Built in M1-131. These details are not in the examples of 07 C.10. `trust add` and `remove` print on
stderr, `list` on stdout. With no terminal and no `--yes`, `trust add` refuses before it prints the key.
With `--yes` it prints the summary and the result, without the compare paragraph. When `--key` is key text,
the `file` row reads `(key text from the command line)`. `--key-id` takes the id in any case. A normal user
who runs `trust remove` for a key that only the system store has is told to use `sudo rdy trust remove
<product>`, with the same `--key-id` when one was given and the system store has that id. On Windows the
empty `trust list` does not suggest `trust add`.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| Separate flags, `--key-file` and `--key-text` | The design names one `--key`, and the help and C.10 are written for it. |
| Read the argument as a file first, then as text | A typed secret key would be reported as "no such file", and the history sentence would be lost. |
| Match "secret key" anywhere in a comment | Refuses a real public key file whose comment mentions one. |
| Refuse a symlinked `.pub` file | Weakens nothing, since the fingerprint check is the control, and breaks a normal setup. |
| Make `TrustStore`'s pins public | Lets any caller build an entry with no checks. Methods keep the rules in one place. |
