# grok-sandbox-analysis

Notes and findings on the Grok runtime environment (the "Computer" feature), which I spent a fair amount of time on in September 2026. Basically it's a root container in an ephemeral per-session VM, and I wanted to map out what holds and what breaks once you're inside.

## What's in this repo

Manual recon and testing done from active Grok sessions. Nothing automated, just exploration: privileges, isolation, networking, persistence, the KVM surface, and especially the kernel angle (CVE-2026-53361 / BadGarbage) which is the only thing that really threatens the container → VM boundary.

## Contents

- **[FINDINGS.md](FINDINGS.md)** — the full report. Architecture, findings sorted by severity, the realistic attack chain (JWT + memory + tool server), the BadGarbage breakdown, and defense recommendations.

## Three-line summary

- Cross-user / cross-chat isolation holds up: separate VMs, artifacts scoped per conversation, no demonstrated cross-user impact.
- Within a session though it's root + nearly all capabilities, an unauthenticated local tool server, and session secrets (JWT) readable by anyone. Session hijack is trivial.
- The kernel (6.12.8+) is in the BadGarbage vulnerability window. The UAF is reachable, full escape didn't pan out on this build (no BTF/vmlinux to retarget offsets), but the residual risk stays critical until it's patched in 6.12.95+.

## Context / disclaimer

Research done on my own sessions, for defensive and learning purposes. Nothing here targets other users — cross-tenant isolation was never breached in my testing anyway. The recommendations at the end of the report are there so the platform can fix this.
