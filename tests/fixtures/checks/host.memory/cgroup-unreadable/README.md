# host.memory/cgroup-unreadable

A 62.8 GiB host. The v2 slice caps memory at 4 GiB, and `memory.max` of the service itself cannot be
read. The check keeps the readable limit, notes the gap, and sets `partial` because a lower limit may
have been missed (M1-177).
