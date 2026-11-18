# ADR 0051: Direct nameserver queries go through a facade call that reads the OS list itself, and the Azure DNS address passes only from that list

- Status: Accepted
- Date: 2026-11-18
- Relates to: ADR 0014 decisions 2 and 8, 05 INV-11 and INV-12, backlog M1-155

## Context

`net.dns` asks each nameserver directly to find split horizon and a slow first hop. The facade had no call
for it. `udp_exchange` serves NTP spec hosts only, there was no TCP DNS call, and the facade did not read
the nameserver list. The Azure VM nameserver is 168.63.129.16, an address the table refuses because its
HTTP side serves the VM agent's settings. It must be reachable as a nameserver and nothing else.

## Decision

1. One call: `Probe::nameserver_exchange(index, payload, transport)`, with `Probe::nameserver_count()`.
   `transport` is UDP or TCP. The backend frames TCP with the two byte length. It is a new `Backend`
   method, `dns_exchange`, with a refusing default.
2. The facade reads the list. It reads `/etc/resolv.conf` through a read guard of its own (that file and
   the two `systemd-resolved` files it may link to), takes the first three `nameserver` lines, and keeps
   the list for the check. A check passes an index. Other OSes report `Unsupported` until M2-010.
3. Admission: the check declares `PeerClass::SystemResolver`; the port is 53 and is not a parameter; the
   payload is one plain DNS query (opcode 0, one question, no compression, no answer or authority records),
   so the call cannot carry other bytes to port 53; `--no-network` refuses.
4. Addresses: `is_unusable_peer` refuses. The single exception is the exact IPv4 address 168.63.129.16, and
   only because it came from the OS list on port 53. The IPv4-mapped, IPv4-compatible and NAT64 forms are
   not the exception. `udp_exchange`, `tcp`, `tls_chain`, `http` and `lookup` are unchanged and still
   refuse that address on every port, so a spec host cannot use the door.
5. A refused nameserver is `Denied` with "nameserver in a refused range". The check reports Skipped with
   that text for that nameserver. The GCE metadata address 169.254.169.254 is such a case.
6. Caps: query 512 bytes, reply 4 KiB over UDP and 16 KiB over TCP (the cut is flagged), 3 s per call.
   The log entry is kind `dns` with `server`, `name`, `rtype`, `proto` `udp` (absent for TCP, as for
   `connect`), `bytes` and `truncated`. The payload and reply are never logged.

## Residual

A resolver on the customer's own network that forwards to 168.63.129.16 is not seen. The list is read once
per check, so a change during the check is not seen. The check parses the reply bytes: a hostile server
can send a malformed message, so the parser (part 2) must not trust lengths.
