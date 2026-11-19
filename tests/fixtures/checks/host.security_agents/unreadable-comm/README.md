# host.security_agents/unreadable-comm

A non-root run in which one process directory cannot be read and a forbidden agent (Falco) is seen. A
positive hit is certain, so the result is a `fail` with no `partial` and no "run as root" advice. The
observed evidence still says `limited_view: true` (M1-177).
