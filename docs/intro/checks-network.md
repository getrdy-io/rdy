You can use this page to fix each network finding. Each section names one check, what it measures and the fix text that rdy prints for it.

Network checks send traffic from this machine. Each check lists what it needs. A check that needs the network is skipped when you run rdy with `--no-network`, and rdy says so in the result.

The Remediation text is the general fix for the check. A finding can carry a more specific fix of its own. When it does, rdy prints that fix instead.

A CA pin is at best a warning until M2-135 ships. A middlebox this machine trusts can append the pinned CA to its chain. Pin the leaf, or set `forbid_interception` to block.

The Reads line lists the paths each check reads. It is one list for every operating system. rdy does not yet list the reads for each system on its own.
