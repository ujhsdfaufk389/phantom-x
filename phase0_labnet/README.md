# PHANTOM-X -- Network Isolation (Phase 0)

**Everything in this phase runs BEFORE anything else in the lab.**

The payload in this project executes arbitrary commands inside the research
VM. That is the point of it, and it is also the risk of it. The network
lockdown is the control that contains that risk, and it only works if it is
in place before the payload exists on the machine.

Installing it afterwards is a statement of intent. Installing it first is a
control.

---

## The three networks

```
    HOME LAN                          LAB SEGMENT                 VM
  ┌───────────────┐               ┌────────────────┐        ┌─────────┐
  │  your router  │               │  host-only     │        │         │
  │  192.168.1.1  │               │  192.168.77.0  │        │ Windows │
  │               │               │       /24      │        │   11    │
  │  your laptop  │               │                │        │   Pro   │
  │  your phone   │               │   ┌────────┐   │        │         │
  │  family gear  │               │   │  host  │◄──┼──C2────│  PX-VM  │
  └───────┬───────┘               │   └────────┘   │  TCP   └─────────┘
          │                       └────────────────┘  9001
          │                                  ▲
          │                                  │
          └────────── NO ROUTE ──────────────┘
                    (blocked by firewall)
```

| Network | Who is on it | Purpose |
|---|---|---|
| HOME | your router, laptop, phone, family devices | your actual life. The lab never touches it. |
| LAB SEGMENT | the host and the VM only | carries the C2 connection and file transfer |
| VM-LOCAL | the VM's own stack | where the payload runs |

---

## Why default-deny egress

The scripts set the VM's outbound policy to **default-deny**, then allow
exactly two things:

1. the lab subnet
2. TCP to the C2 port on the lab gateway

Everything else is blocked, including the public internet.

That is stricter than it might look, and the reason is specific: the
payload runs `cmd.exe` with whatever the operator types at the C2 console.
If the VM has a route to the home network, then one mistyped command, one
buggy payload, or one command that gets confused by an environment variable
becomes a problem for someone on your home LAN. With default-deny, the
worst case is "the lab stops working". It is never "the lab reaches the
family laptop".

---

## What this costs you

**The VM has no internet.** That is deliberate. It means:

- Windows Update will not run inside the VM
- you cannot download tools inside the VM
- Defender uses whatever signature set was already present

**The fix, if you need something in the VM:** download it on the host,
transfer it over the lab segment, and install it there. If the lab
genuinely needs internet access, put a logging proxy on the host so the
traffic stays observable. Do not bridge the NIC.

---

## Setup

### On the HOST (the machine that runs the C2 server)

```powershell
cd phase0_labnet
.\setup_labnet.ps1 -Action apply -LabSubnet 192.168.77.0/24 -C2Port 9001
```

This:
- checks that VMware's VMnet1 is **host-only**, and refuses to continue
  silently if it is bridged (a bridged VMnet1 means the VM is sitting on
  your home LAN and the whole model is fiction)
- creates a Hyper-V **Internal** switch named `PX-LAB` if Hyper-V is in use
  (an internal switch has no uplink to the physical network at all)
- adds a Windows Firewall rule that **blocks all inbound** from the lab
  subnet, plus one narrow **allow** for the C2 port

### In the VM

```powershell
cd phase0_labnet
.\setup_vm_labnet.ps1 -LabGateway 192.168.77.1 -C2Port 9001
```

This sets the default-deny egress policy, the explicit home-LAN blocks, and
points DNS at the lab gateway only.

### Verify it

```powershell
.\verify_labnet.ps1 -LabGateway 192.168.77.1 -C2Port 9001
```

```
  [PASS] HOME-1     expect UNREACHABLE TCP 1.1.1.1:443 -> blocked
  [PASS] HOME-2     expect UNREACHABLE 192.168.1.1:80 -> blocked
  [PASS] DNS-1      expect NO RESOLVE    DNS via 192.168.77.1 -> no answer
  [PASS] LAB-1      expect REACHABLE     192.168.77.1:9001 -> open
```

**A firewall configuration that was never tested is a configuration that
does not work.** Run the verification. If `LAB-1` fails, the lab is
broken. If `HOME-1` passes, the lab is not actually isolated and no
measurement should be taken.

---

## The whole VM preparation, in order

```powershell
cd phase4_defender
.\vm_prepare.ps1 -LabFolder C:\pxvm -LabGateway 192.168.77.1 -C2Port 9001
```

That script runs the network lockdown first, then reports the Defender
posture (without changing it), then clears Mark-of-the-Web, then checks
Sysmon.

---

## Files

| File | Runs on | Purpose |
|---|---|---|
| `setup_labnet.ps1` | HOST | VMware host-only check, Hyper-V internal switch, host firewall |
| `setup_vm_labnet.ps1` | VM | default-deny egress, home-LAN blocks, DNS lockdown |
| `verify_labnet.ps1` | VM | proves the isolation holds by probing the live network |
