---
title: Exit codes
description: What each rdy exit code means, and what a script or runbook should do with it.
---

After you read this page, you can map each exit code of `rdy` to an action in a script or a runbook.

`rdy` exits with one of five codes. Check the code, not the text. The text can change between releases. The codes do not.

| Code | Name | What it means | What to do |
| --- | --- | --- | --- |
| 0 | ready | Everything the spec asks for passed. | Continue. |
| 1 | warnings | The host is ready, with optional checks that failed. | Read the warnings. Decide if they block your install. |
| 2 | blockers | The host is not ready. A check blocks, or a required check did not run. | Fix each blocker. Run again. |
| 64 | usage | The input is wrong. A flag, a value, the spec or its signature. | Change the input. Run again. |
| 70 | internal | rdy could not deliver its result. The input may be fine. | Read the error and its fix. Run again. If it repeats, report it. |

## Gates

A gate that accepts 0 and 1 passes. Accept 0 only if you do not want warnings to pass.

A required check that did not run exits 2. So a gate that accepts 0 and 1 never passes a host that rdy did not check.

This script stops on the first failure, so it reads the code with `|| code=$?`:

```sh
code=0
rdy run acme-platform.yaml || code=$?
case $code in
  0) echo "ready" ;;
  1) echo "ready with warnings" ;;
  2) echo "not ready: fix the blockers" ;;
  64) echo "input error: fix the spec or the flags" ;;
  70) echo "rdy failed: read the error, then run again" ;;
esac
```

## Exit 70 and the output

Exit 70 can come with output that is cut short. If you use `--json`, do not parse stdout after a 70. Use the exit code.

When stdout holds a complete result and the files could not be written, rdy exits 70. The result on stdout can still say `complete: true`. In a script, trust the exit code.

## Exit 64 and clap

Usage errors from the command line exit 64, the same as other input errors. A bad flag does not exit 2.

## install.sh uses its own codes

The install script has three codes of its own: 0 installed, 1 failed and installed nothing, 64 bad usage. See [Install](/install/).
