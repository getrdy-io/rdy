---
title: First run
description: Run rdy on the example spec, read each part of its output and learn what the exit code means.
---

After you read this page, you can run `rdy` on an example spec, read its output and know what exit code 2 means.

## Before you start

Install `rdy` first. See [Install](install.md). Check that `rdy` is on your `PATH`.

The example needs no root and no cloud account. It works offline too. You do not need to change your machine.

## Check the version

```sh
rdy version
```

The output starts with `rdy` and the version. Some builds also print a commit and a date in parentheses:

```text
rdy <version>
```

## Get the example spec

The example spec is `acme-quickstart.yaml`. You can read it in the [repository](https://github.com/getrdy-io/rdy/blob/main/examples/specs/acme-quickstart.yaml). The [spec reference](reference/spec/index.md) shows the same file as an example.

Save the file in an empty folder. Change into that folder before you run the commands below. rdy writes its reports into the folder you are in.

## Lint the spec

```sh
rdy spec lint acme-quickstart.yaml
```

Lint reads the spec and checks it. It runs no checks on your machine. The output names the file and the count of problems:

```text
acme-quickstart.yaml: 0 errors, 0 warnings
```

Lint exits 0 when the spec is clean. A spec with a mistake prints the line, a fix and a suggestion.

## Run the checks

```sh
rdy run acme-quickstart.yaml --allow-unsigned
```

Vendor specs are signed. This example is not. `--allow-unsigned` tells rdy to run it anyway. rdy prints a warning first, and it marks every report as unsigned.

The text output goes to stderr. It has these parts, in this order:

- A `WARNING: UNSIGNED SPEC` block at the top.
- A header with the spec, the signature state, the host and the user.
- One line per check. Each line has a status, such as `PASS`, `WARN`, `BLOCK` or `SKIP`. A line that is not `PASS` has a fix under it.
- A summary line with the counts.
- The name of the report folder that rdy wrote, and the files in it.
- The warning again, then the verdict on the last line.

Here is the shape of the output when you run the example with no network. The numbers depend on your machine:

```text
WARNING: UNSIGNED SPEC
...
rdy <version>
spec    acme-quickstart >=1.0   (acme-quickstart.yaml)
sig     UNSIGNED (allowed by --allow-unsigned)
...
  SKIP     net.egress        ...
...
<counts>

Report written to ./rdy-report-acme-quickstart-<time>/
  rdy-report-acme-quickstart-<time>.json
  spec.yaml
WARNING: UNSIGNED SPEC
NOT READY: 1 required check was not run
```

The `net.egress` check needs the network. With no network, it is skipped, and the verdict is `NOT READY`, because a required check did not run. With a network, the command looks up the two host names in the spec. They do not resolve, so the check blocks, and the last line is `NOT READY`. Either way, the verdict is the expected first result.

The report folder is `./rdy-report-acme-quickstart-<time>/` in the folder you ran from. On Windows, the default folder is `%USERPROFILE%\rdy-reports`, and the report folder goes inside it. Use `--out-dir` to choose another folder.

The exit code is 2. Exit 2 means at least one check blocks, or a required check did not run. See [exit codes](run/exit-codes.md) for every code.

## Read the JSON report

```sh
rdy run acme-quickstart.yaml --allow-unsigned --json
```

`--json` prints the report on stdout. The text output still goes to stderr. Scripts should read the JSON fields, not the text.

The top-level keys of the report come in this order. Each value is shown as `...`, except the verdict fields and the signature state:

```text
{
  "api_version": ...,
  "kind": ...,
  "producer": {
    ...
  },
  "run": {
    ...
  },
  "spec": {
    ...
  },
  "signature": {
    "state": "unsigned",
    ...
  },
  "host": {
    ...
  },
  "identity": {
    ...
  },
  "proxy": ...,
  "capabilities": [
    ...
  ],
  "verdict": "not_ready",
  "verdict_reason": "required_check_not_run",
  "exit_code": 2,
  "summary": {
    ...
  },
  "checks": [
    ...
  ],
  "actions": [
    ...
  ],
  "actions_truncated": ...,
  "actions_dropped": ...,
  "redaction": {
    ...
  },
  "complete": ...,
  "interrupted": ...
}
```

The `verdict` field is `not_ready` for this example. The `exit_code` field matches the exit code of the process. The `signature` object says that the spec is unsigned.

The [result reference](reference/result/index.md) describes each field.

## Next steps

- Change the host names in `net.egress` to hosts you can reach. Run the example again. The verdict changes when the checks pass.
- Read [Unsigned specs](unsigned.md) to learn what `--allow-unsigned` and `--key` do.
- Read the [spec reference](reference/spec/index.md) to write your own spec.
