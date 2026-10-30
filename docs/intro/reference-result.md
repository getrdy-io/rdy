You can use this page to read the JSON that rdy prints with `--json`, and know what each field means. The first section is the result of a run, which `rdy run --json` prints. The other sections cover the objects that `rdy verify --json`, `rdy spec lint --json` and `rdy version --json` print. The error object has a section too. rdy prints it with `--json` when it exits without a verdict.

In this release, `rdy run` and `rdy verify` are not built yet. Each one exits 70 and prints the error object. Their sections show the objects they will print.

Each table has one row per field. An object that more than one field names has one section. A row that names the same object links to that section.
