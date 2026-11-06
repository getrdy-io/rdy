PR #48 main-merge round (all three reviewers approve at e84fa56e). Merge origin/main (never rebase), then these nits in one commit:
1. rules.rs ANY_RESOURCE doc (~178): drop "the group holds nothing but constraints" (contradicts ADR 0042); say what ADR 0042 says.
2. 12-progress line: ADR 0042 is "Accepted, security-reviewed (PR #48)", not proposed.
3. LabelEquals: refuse a label selector containing `(` for this rule (so `app in (a,kubernetes.io/service-name=x)` is refused by the guard, not only by the server), with a near-miss test.
Full cargo test --workspace, generator --check, push, cargo clean, reply with head.
