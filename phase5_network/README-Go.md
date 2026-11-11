# PHANTOM-X -- Phase 5 :: C2 Server (Go implementation)

`c2_server.go` is a Go implementation of the lab C2 server. It speaks the
same wire protocol as the Python reference (`c2_server.py`), so the same C
payload works against it unchanged.

---

## Why a second implementation

The lab's ground rule #6 is *"cross-validate before trusting: every
analyzer is checked against an independent implementation."*

A protocol is a claim about bytes. Two implementations of the same protocol
is what turns that claim into a checked one. The Go server was written from
the protocol description in `px_payload.c`'s source comment; the Python
server was written first and independently. When they agree, the
description is right.

**This found two real bugs:**

- The payload's own formatter did not understand `%ld`, so the exit code in
  every `RESULT` line arrived as the literal text `%ld`. Both servers
  dutifully reported `exit_code=%ld`. Nothing complained, because the value
  was a non-empty string — and a failure was indistinguishable from a
  success.
- The Go server's `Accept()` blocked forever, so `--duration` never fired
  and the server could not shut itself down. The Python server had no such
  problem, which is exactly why the comparison was worth writing.

---

## Build

```powershell
cd phase5_network
go build -trimpath -ldflags "-s -w" -o px_c2.exe .
```

For the Linux rig:

```bash
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o px_c2 .
```

No dependencies. `go.mod` declares no requirements, so this builds offline.

---

## Run

```powershell
.\px_c2.exe --host 127.0.0.1 --port 9001 --log c2_audit.jsonl
```

| Flag | Meaning |
|---|---|
| `--host` | bind address. **Use the lab-segment address, not `0.0.0.0`** |
| `--port` | bind port (default 9001) |
| `--log` | JSONL audit log path |
| `--no-console` | headless, for scripted runs |
| `--duration` | stop cleanly after N seconds (0 = run forever) |

### Console commands

```
  list                 show active sessions
  exec <id|all> <cmd>  run a command in one or all sessions
  ping <id|all>        measure round trip latency
  kill <id|all>        send EXIT (controlled session termination)
  stats                counters and audit log path
  help                 this text
  quit                 stop the server
```

---

## Protocol

```
client -> server   HELLO|<arch>|<pid>|<hostname>
                   PONG
                   RESULT|<cmd_id>|<base64 output>|<exit_code>
server -> client   PING
                   EXEC|<cmd_id>|<command line>
                   EXIT
```

Plain TCP, no encryption, no obfuscation, no domain generation, no traffic
shaping. The point of this rig is to produce traffic that can be analysed,
and a payload that can be observed by Defender and Sysmon. A stealthy
channel would produce nothing worth measuring.

Every session, command, result and disconnect is written to the audit log.
Nothing is done quietly — including a PONG that arrives with no matching
PING outstanding, which is recorded as `unmatched`.

---

## Validation

```bash
# against the REAL Windows payload -- not a mock
cd phase5_network
go test -v -run TestGoC2Integration -payload ../dist/phantom-x-vm-lab/px_payload.exe .

# against the Python reference implementation
python3 validate_c2_equivalence.py --go ../dist/native/px_c2.exe
```

The Go test drives the actual `px_payload.exe` binary and asserts on a
full session: HELLO parsed, latency measured, EXEC round trip with the
correct output, counters incremented, clean EXIT handshake, and a complete
JSONL audit log.

A mock client would only prove that the mock and the server agree with
each other. The point of using the real payload is that it cannot agree
with a mock — it speaks whatever the payload actually speaks, including
the bugs.

---

## Relationship to the Python server

The Python implementation stays. It is the reference, it is what the
existing test harnesses import, and it is readable by anyone who wants to
check the protocol by reading one file.

Use whichever you prefer. `validate_c2_equivalence.py` proves they are
interchangeable.
