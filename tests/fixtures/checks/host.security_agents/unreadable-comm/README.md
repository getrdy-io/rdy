# host.security_agents/unreadable-comm

Known gap, owner M1-177. The `expect.json` blesses what the check does today: a `fail` for a forbidden
agent that was seen, with a `partial` set because one process directory was unreadable. A positive hit
does not need that `partial`; it is noise on a result that is already certain. When M1-177 fixes the
check, regenerate `expect.json` on purpose and read the diff.
