# Grok Chat Sandbox — Security Analysis

Target: xAI Grok Chat "Computer" execution sandbox.
Period: September 2026. Everything below is live recon and manual testing from my own active sessions — no automation, just poking around until things broke or didn't.

## TL;DR

The way I'd describe the Grok sandbox after spending a while in it: it's a full root workstation dropped inside a disposable per-conversation VM, with a FUSE-backed artifacts store that's scoped per chat. That framing matters because it explains basically every finding here — they trade off in-session freedom (you're root, you have KVM, you have an unauthenticated local tool API) against cross-session isolation (the VM is thrown away constantly, artifacts don't leak between chats, I never got anything cross-user).

So the two-sentence verdict is: cross-user and cross-chat isolation is genuinely solid, and I couldn't break it. But once you're *inside* a session, the confinement is weak — root, nearly all caps, secrets sitting in world-readable files, and a kernel that's in the vulnerable window for CVE-2026-53361 (BadGarbage). Host escape I never fully pulled off, but the kernel bug is reachable, which is the part that actually worries me.

| Layer | How it held up |
|-------|----------------|
| Cross-user / cross-chat | Strong — separate VMs, separate artifact stores, nothing leaked |
| In-session confinement | Weak — root, full caps, KVM, unauthenticated tool API |
| Host escape | Not achieved, but the kernel vuln is present and triggerable |
| Durable remote access | Poor by design — the ephemeral VM kills your shells for you |

## 1. What you're actually sitting inside

The stack, top to bottom, looks like this:

```
[ your Grok chat session ]
        |
[ xAI hypervisor + KVM ]
        |
[ per-session ephemeral VM — hades-vm, Linux 6.12.8+ ]
        |
[ container sandbox — Ubuntu 24.04, root ]   <- you are here
        |- catatonit                          (PID 1)
        |- node /app/grok-computer-server.mjs (tool server, 127.0.0.1:4242)
        |- grok-files                         (FUSE -> /home/workdir/artifacts)
        \- chrome / shells / tool workers
```

Resource-wise it's small: about 2 vCPU (Xeon Platinum 8481C), ~1.2 GB RAM total (and that budget is shared with anything you spin up, including KVM guests), a ~20 GB overlay for the writable filesystem, no GPU, no swap. The hostname changes constantly (always `hds-something`) and uptime is frequently under 10 minutes — the thing recycles a lot.

I pulled the boot cmdline out of `/proc/kcore` strings and it's `console=hvc0 quiet loglevel=3 root=/dev/vda ro init=/hades-container-tools/cata…`, so the rootfs is mounted read-only with an overlay on top for the parts you can write to. Kernel is Linux 6.12.8+ x86_64, built `root@buildkitsandbox` on a July 2026 date — hold that thought, it's the whole reason section 8 exists.

## 2. Privileges: you're just root

Nothing subtle here. You land as uid 0, and the effective capability set is `000001ffffffffff`, which is basically everything. There's a seccomp filter (mode 2, one filter, NoNewPrivs=1) on the tool bash, but it's minimal, and Chrome doesn't even get that — more on that later. No AppArmor, no SELinux that I could see.

One thing I want to clear up because the mid-2026 public research got it wrong: `nsenter --target 1` is **not** an escape here. I checked the namespace inodes and they're identical to PID 1's. PID 1 is just `catatonit`, and you're already in the same namespaces as it. Entering PID 1's namespaces gets you exactly nowhere new. So if you read somewhere that nsenter breaks out of the Grok sandbox — not on this layout, it doesn't.

The overlay is very permissive. I could write to `/tmp`, `/etc`, `/lib`, `/usr/local/bin`, `/etc/ld.so.preload`, `/etc/cron.d/`, `/etc/systemd/system/` — even `/etc/passwd` and `/etc/shadow` are writable, though since you're already root that's an FS-policy smell rather than an actual privesc. I confirmed a PATH hijack works, ld.so.preload is honored by the linker, and the cron/systemd dirs are writable. But — and this is the catch that comes up again and again — none of it survives a VM recycle. The overlay is gone when the box gets thrown away. Only the artifacts FUSE mount persists (section 7).

## 3. Secrets sitting in the open

This is the finding that annoyed me the most because it's so avoidable. There's a session JWT at `/etc/secrets/terminal.jwt`, and it's mode 644 — world-readable. Same value is also exported in the `TERMINAL_JWT_VAL` environment variable. Decoded, it's roughly:

```json
{
  "uid": "<uid-uuid-redacted>",
  "cid": "<cid-uuid-redacted>",
  "email": "<my-email-redacted>",
  "sl": "LoggedIn",
  "exp": "<now + ~60 min>",
  "iat": "<now>"
}
```

(I've redacted my own uid/cid/email — they were real values in the actual token.)

Two problems stacked on top of each other. First, it's readable by anything in the container, so any process at all can grab your session identity and email. Second — and I found this reading the bundled `grok-computer-server.mjs` — the `isValidJWT()` function only checks the format and the header (typ + alg). It never verifies the signature. It's HS256 in the header but nothing actually validates the HMAC in the paths I traced. A token with a well-formed header just... passes that check. The real gate is that the session has to exist server-side, which limits the direct damage, but "we don't check the signature" is not something you want in a credential validator.

## 4. Reading process memory

`/proc/<pid>/mem` of the main node process is readable (and writable — I tested a write and restored it). Since that's the tool server, its memory has live session objects in it, and the session UUIDs the API uses are sitting there in cleartext. So the recipe is: find the node PID, read its `/proc/<pid>/mem`, grep out a session UUID. I got JWTs and session IDs out this way without much trouble. Classic gdb-style ptrace was blocked, but plain `/proc/<pid>/mem` reads weren't, which is all you need.

Why does a session UUID matter? Because of the next section.

## 5. The tool server — local RCE with no auth

There's a node tool server on `127.0.0.1:4242` (version 0.2.22) and it's the control plane for the whole sandbox. The routes I found:

- `GET /health` → `{"healthy": true, "version": "0.2.22"}`
- `POST /sessions/create` → hands back a sessionId
- `POST /sessions/{id}/tools/call` → runs a tool
- `POST /skills/install` → installs a skill, and it does real HTTP fetches

The tools I confirmed work through it: `bash`, `read_file`, `write_file`, `edit_file`, `browser_tab`, `browser_network_details`. There's no auth token in front of any of this. If you have a valid session id — which, per sections 3 and 4, you can just read off disk or out of memory — you can call any tool. From any process in the sandbox, that's root command execution plus filesystem read/write plus browser control. No credential beyond an id you can trivially obtain.

## 6. Putting it together

Individually none of the above is exotic. Chained, it's a clean in-session takeover, and it's worth writing out because the chain is the actual finding:

1. Read the JWT from `/etc/secrets/terminal.jwt` (or the env var) to get the session id.
2. Or, if you want one that's currently live, dump the node process's `/proc/<pid>/mem` and grep for a UUID.
3. Hit `POST 127.0.0.1:4242/sessions/<id>/tools/call` with the `bash` tool. It runs as root.
4. From there it's whatever you want — I ran `id`, `hostname`, file reads, an outbound reverse shell, all fine.
5. Drop a beacon or script into `/home/workdir/artifacts` so it survives the VM getting recycled.
6. After a recycle (new hostname, everything else wiped), pull a fresh session id out of the new container and keep going.

The reverse shells work but they're fragile — the box recycles under you and the channel drops. So it's not a stable C2 host, which is honestly the platform's saving grace here more than any deliberate control. The persistence angle in step 5–6 is the durable part.

## 7. What actually persists

Everything except one mount is ephemeral. The exception is the FUSE mount at `/home/workdir/artifacts`:

```
grok-files on /home/workdir/artifacts type fuse (rw,nosuid,nodev,allow_other)
options: --ttl 5m --content-cache memory --deny-delete off
```

Files I wrote here stuck around across VM recycles within the same conversation — I confirmed this concretely: something I wrote on 2026-09-13 was still there on a fresh VM (`hds-gquuryxaj4hu`, uptime 0) two days later. They do **not** cross into a different chat, though — a different conversation showed a completely disjoint file list (some other beacon/persist files that weren't mine to see, so the per-chat scoping is real). And the mount is flaky under load: big files or lots of parallel writes throw `Transport endpoint is not connected` and the mount drops.

So the persistence story is: overlay changes (cron, systemd units, ld.so.preload, PATH tricks) are session-only and die with the VM. Artifacts survive within a chat. Nothing I found auto-executes on container boot — there's no durable init hook on the guest side — so persistence means "the file is still there next time," not "it runs itself." You re-trigger it by re-hijacking a session.

## 8. The one that matters — CVE-2026-53361 (BadGarbage)

Everything above stays inside the session trust model. This one doesn't. It's the only thing I tested that, if finished, changes the risk *class* — from "compromised user sandbox" to "compromised execution VM."

The bug: CVE-2026-53361, nicknamed BadGarbage, in the Linux kernel's AF_UNIX garbage collector (`net/unix`). It's a race that turns into a use-after-free. The AF_UNIX GC frees cycles of in-flight sockets; a concurrent `MSG_PEEK` can take a reference that isn't counted correctly if `gc_in_progress` is read as false at the wrong instant, and the collector then frees an object that's still live — UAF on `sk_buff` and the chains hanging off it. It's the same family of bugs that's been fixed and then reintroduced a few times (CVE-2021-0920, CVE-2026-23394, now this). Upstream fix is around 6.12.95 (`af_unix: Set gc_in_progress to true in unix_gc()`). This box is 6.12.8+ — inside the window, unless there's a silent backport I can't see, and I couldn't find one.

Why I care about this over the JWT/tool-server stuff: those keep me in my own session. BadGarbage aims at the kernel that's shared between the container and the VM. If it lands the way the public PoCs describe, you get kernel memory control, then typically root in hades-vm's init namespaces, then FS/process/secrets at VM level, and a pivot toward other containers on the same node. It's not "root on all of xAI" — the hypervisor and vsock (`hades-charon`) are the next wall and I didn't touch them — but container → execution VM is already a serious trust jump. And unlike a local privesc, "I'm already root in the container" gives you nothing toward this; the payoff is escape, not uid 0.

### Did it actually fire?

Yeah, the bug is reachable on this build. I ran two PoCs.

The **sgkdev bad_garbage** PoC compiled and ran. GC calibration got to ~100 wins/sec. RACE #1 (leak fops/pages) was a reliable win. RACE #2 (leak rbnode / xattr slot) was a reliable win. RACE #3 — the one that installs an SCM, does the dirty-pagetable trick, and turns into the actual LPE — failed every single time, consistently, right after the init chain-install (either EAGAIN or just no terminal win). So the trigger works, the leaks work, and the final exploitation step is where it fell apart.

The **Google kernelCTF** PoC (the `CVE-2026-53361_lts` one, `lts-6.12.93` binary, supposedly more universal on LTS images) printed `[+] Receive queue is purged` dozens of times per run. That's a strong confirmation the receive queue really is being purged under the race — i.e. the UAF is firing. But no root-host shell, no init-namespace shell, no successful core_pattern write came out of it.

I spent a while on RACE #3 before I understood why it wouldn't finish, and the answer is annoying but structural: the kernel was built `CONFIG_DEBUG_INFO_NONE=y`. No BTF at `/sys/kernel/btf/vmlinux` (absent), and the offset loader in the PoC needs to retarget struct members (`page`, `pipe_inode_info`, `file`, `skb`, `unix_sock`, …) which it can't do without debug info. I tried the DEBIAN/RELH10/KCTF/6.17-UBUNTU profiles (RACE 1/2 fine, 3 dead), tried `unix_sock_addr` variants across 0x300–0x318, hardcoded 0x308 — hygiene, no win. `/proc/kallsyms` got rejected as incomplete by the loader. I went looking for a `vmlinux` or `System.map` on `/dev/vda`, `/dev/vdc`, the hades-tools — nothing usable. The guest kernel is loaded by the hypervisor and the rootfs just doesn't ship the debug artifacts you'd need to retarget the exploit.

A couple of times the prolonged stress killed the session outright, which is consistent with local corruption from the UAF. I never saw a stable host panic in the logs I could reach, but the kernel-DoS potential is clearly there.

### So where does that leave it

The honest verdict: vulnerability confirmed in situ, full container-to-VM escape not achieved on this specific build, and the reason it wasn't achieved is missing BTF/vmlinux plus offset mismatch — **not** a patch. That's an important distinction. Offsets get retargeted offline the moment someone has a leaked build or clones the image in a lab. So I'd treat the residual risk as critical until the kernel is on 6.12.95+, not as "eh, it didn't pop, we're fine."

## 9. KVM — real nested guests

You get `/dev/kvm` open (API v12), and `CPUID` leaf `0x40000000` reports vendor `KVMKVMKVM`, so nested KVM is genuinely on (`kvm_intel.nested=Y`, EPT/VPID). I could do `CREATE_VM`, allocate vCPUs, set up memslots, IRQCHIP, CPUID, REGS, MSR, SET_GUEST_DEBUG, and `KVM_RUN`.

More than just creating VMs, I got guest code to actually execute. Mapping the reset vector (GPA `0xffff0000`, code at `0xfffffff0`) and running small snippets:

- `HLT` → clean HLT exit, RIP advances
- `MOV AL, 0x42; HLT` → HLT exit, RAX = 0x42 (so the register state is real)
- `OUT 80h; HLT` → IO exit as expected
- `INT 3` → MMIO exit
- `UD2` → INTERNAL_ERROR

So instructions are really retiring in the guest, not just being set up. `SET_SREGS` always returned EINVAL even with an unmodified buffer, and a pile of other ioctls (FPU, XSAVE, NMI, TRANSLATE…) also EINVAL, so it's not a fully unrestricted KVM — but I got guest execution working *around* the SET_SREGS block, which was the interesting part.

On limits: I could create hundreds of VMs in parallel, up to ~4092 before hitting EMFILE (the fd ulimit is 4096), and up to 512 vCPUs on a single VM in testing. Guest RAM comes out of the same ~1.2 GB session budget, so it's easy to DoS your own session. Important nuance so nobody misreads this: these are KVM objects *inside one Grok sandbox*. They are not extra Grok sessions and they don't get you extra quota or multi-tenant reach.

Escape-wise I'd call it L1–L2 (guest code exec, guest-side primitives) but not L3 — a real host escape from here would need a hypervisor bug on top, which I didn't have. The practical value of the KVM surface isn't breaking out today, it's that it's a decent lab for developing/testing a kernel exploit (like the BadGarbage one) against a matching target.

## 10. Browser — Chrome with the sandbox forced off

When the `browser_tab` tool runs, it launches Chrome headless like this:

```
CHROMIUM_FLAGS=--disable-software-rasterizer --disable-dev-shm-usage --no-sandbox
/usr/bin/google-chrome --headless --remote-debugging-port=0
  --user-data-dir=/tmp/grok-chrome-…
  --disable-dev-shm-usage --no-sandbox
```

Version ~148.0.7778.167 on Ubuntu 24.04.4. The `--no-sandbox` is the thing: Chromium's own sandbox is off. Measuring the processes, the browser process runs full caps (`…ffffffffff`), NoNewPrivs 0, seccomp 0; the renderer drops caps but still has no seccomp. Now, the session is already root, so a browser bug doesn't need a separate "get root" step to reach the rest of the sandbox — which is exactly why forcing `--no-sandbox` in an already-privileged context is a bad combo. A web → session path is right there.

DevTools is live on a local port plus `/devtools/browser/<uuid>`, reachable inside the VM only. And the crash handler (`chrome_crashpad_handler`) is pointed at Google:

```
--url=https://clients2.google.com/cr/report
--annotation=prod=Chrome_Linux --annotation=ver=148.0.7778.167
```

I checked — `clients2.google.com` resolves to Google IPs and `curl -I` to the report endpoint gets an HTTP/2 400, so the endpoint is reachable and the egress path to Google's crash infra is live if a report ever gets sent. Local crash dirs (`attachments/ completed/ new/ pending/`) exist. It's telemetry, not a break, but worth flagging for anything privacy-sensitive.

## 11. Network and the odds and ends

Outbound TCP/HTTPS is allowed — more open than some mid-2026 writeups claimed. Reverse TCP to a listener works (just unstable, as covered). Interactive reverse shells drop a lot because the VM is short-lived. Inbound SSH is impossible, there's nothing listening. `vsock` and `/dev/vport0p0` are present; I could bind but found no host services on the ports I scanned, and vsock-to-host attempts timed out or got blocked.

Internal services I could reach: `*.hades-openbar.svc.cluster.local` (proxies for CoinGecko, Polygon, etc. — the API keys in env are placeholders like `hellofromgrok`, so nothing sensitive), an internal package registry around `35.245.43.102` (a PyPI-ish mirror — reachable, but uploads were blocked), and `files.grok.com` as a gRPC endpoint. No `docker.sock`, no Kubernetes service account token lying around.

The controller binary `/.hades-container-tools/xai-hades-styx` (read-only EROFS) has subcommands that give root write/exec — `cat-to` (arbitrary write as root), `exec`/`pty` (run as root), `write-random-file`, `open-to` (returns an FD), plus `pentest`/`test-localhost` connectivity checks. The `cat-to` → `exec` chain works and is presumably how the tool server spawns things. Trying to overwrite the binary itself is blocked (EROFS). This is design, not a bug, but it's a handy root primitive if you're already inside.

`/proc/kcore` is a readable ELF (that's where the boot strings came from). `CAP_SYS_MODULE` is present but there's no `/lib/modules` tree to load anything against. The skills-install endpoint is open and does real downloads.

## 12. Findings, ranked

| ID | Finding | Severity | Status |
|----|---------|----------|--------|
| F1 | JWT at `/etc/secrets/terminal.jwt` world-readable (644) + in env | Critical | Confirmed |
| F2 | Session hijack via unauthenticated tool server :4242 | Critical | Confirmed |
| F3 | `/proc/<pid>/mem` readable → extract JWT + session ids | Critical | Confirmed |
| F4 | `isValidJWT()` never verifies signature | High | Confirmed (code) |
| F5 | Overlay hijacks — PATH, ld.so.preload, cron, systemd | High | Confirmed (session-scoped) |
| F6 | Artifacts FUSE survives VM recycles within a chat | High | Confirmed |
| F7 | Chrome forced `--no-sandbox`, DevTools port live | High | Confirmed |
| F8 | CVE-2026-53361 (BadGarbage) kernel UAF | Critical (potential) | UAF proven, escape not completed |
| F9 | Nested KVM + real guest instruction execution | High | Confirmed |
| F10 | Outbound network unrestricted, reverse TCP works | Medium | Confirmed |
| F11 | Crashpad egress to Google | Low–Medium | Confirmed |
| F12 | `xai-hades-styx` root write/exec primitives | High | Confirmed (by design) |
| F13 | LinPEAS: writable passwd/cron/systemd, readable shadow | Low | Confirmed (already root) |

## 13. Risk matrix

| Area | In-session | Cross-chat / user | Host |
|------|-----------|-------------------|------|
| Root + all caps | Critical | No | No |
| Tool server, no auth | Critical | No | No |
| JWT + memory extraction | Critical | No (unless hijack survives recycle) | No |
| xai-hades-styx write/exec | High | No | No (container only, by design) |
| Chrome --no-sandbox | High (web→session) | No | No |
| KVM guest exec | High (as a lab) | No | Needs a hypervisor bug on top |
| Artifacts persistence | Medium (data durable in-chat) | Isolated per chat | No |
| Outbound network | Medium | No | No |
| Crashpad egress | Low–Medium (telemetry) | No | No (Google's infra) |
| CVE-2026-53361 | Critical if finished | Yes (others on the VM) | Yes (VM escape) |

## 14. What I'd fix, in order

Patch the kernel first. Get to 6.12.95+ or backport the BadGarbage fix. The UAF is reachable right now and the only reason I didn't finish the escape is missing debug symbols, which is not a control you can rely on — anyone with a leaked build retargets offsets offline. This is the one that changes the blast radius, so it's the one that matters.

After that, the in-session credential mess. Stop shipping the JWT world-readable — make `/etc/secrets/terminal.jwt` owner-only (600) at minimum, ideally don't drop it on disk at all. Actually verify the signature in `isValidJWT()` instead of just parsing the header. Put auth in front of the tool server on 4242 (a real token, or move it to a Unix socket with proper checks) so that "I read a session id" stops being equivalent to "I have root RCE." And lock down `/proc/<pid>/mem` so session ids and tokens can't just be dumped out of the node process.

Then reduce the blast radius of being root. Drop the caps you don't need — SYS_MODULE, SYS_PTRACE, SYS_ADMIN, NET_ADMIN aren't needed for a tool sandbox. Gate or remove `/dev/kvm` unless nested KVM is actually a product feature; if it stays, cap the VM/fd count and the memory budget harder. Harden the seccomp filter — restricting AF_UNIX / MSG_PEEK usage would also chip at the BadGarbage surface, though it's awkward for a rich shell sandbox. Don't run Chrome `--no-sandbox` if there's any safer pattern, and lock down CDP. Review the Crashpad egress — block or redact it. Keep the per-chat artifacts isolation exactly as it is; that part's a genuine strength.

And don't lean on "there's no BTF" as a mitigation. It slowed me down; it wouldn't slow down anyone working from a cloned build.

## 15. Bottom line

xAI's real security boundary is the ephemeral per-conversation VM plus the separate FUSE namespaces — not a locked-down userspace jail. Inside a box you can run as root through several channels, drive a browser with its sandbox off, reach Google's crash infra, and execute real guest code through KVM. Across sessions and users none of that carries over on its own: artifacts stay per-chat, and the machine gets thrown away often enough that long-lived shells just die.

It's a coherent multi-tenant design with a deliberately sharp knife inside each box. The design bet is "who cares what you do in a disposable box you can't escape." That bet holds right up until the kernel bug in section 8 gets finished — which is exactly why patching it is the whole ballgame.
