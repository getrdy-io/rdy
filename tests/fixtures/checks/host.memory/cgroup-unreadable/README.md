# host.memory/cgroup-unreadable

Known gap, owner M1-177. The `expect.json` blesses what the check does today: a pass that names the
parent slice limit and does not set `partial`. 03 says an unreadable `memory.max` of the service itself
should give `partial`. When M1-177 fixes the check, regenerate `expect.json` on purpose and read the diff.
