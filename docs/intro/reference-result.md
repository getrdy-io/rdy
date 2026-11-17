You can use this page to read the JSON that rdy prints with `--json`, and know what each field means. The first section is the result of a run, which `rdy run --json` prints. The other sections cover the objects that `rdy verify --json`, `rdy spec lint --json` and `rdy version --json` print. The error object has a section too. rdy prints it with `--json` when it exits without a verdict.

In this release, `rdy verify` is not built yet. With `--json`, it prints the error object and exits 70. Its section shows the object it will print.

Each table has one row per field. An object that more than one field names has one section. A row that names the same object links to that section.
