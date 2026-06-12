# Crash Digest Automation

Six-hour email digest for AFL++ crash progress. The design goal is a phone-safe
workflow:

1. receive an email with ranked crash links
2. tap a crash link over Tailscale
3. read the generated summary
4. scroll to the exact PoC/reproducer code
5. download the raw crash artifact only when needed

## Architecture

The digest is split into small jobs so each failure mode is contained.

| stage | script | runs where | writes |
|-------|--------|------------|--------|
| bounded triage | `triage-drain.sh` | fuzz host / Orb VM | normal `crashes-triaged/<hash>/` dirs |
| repro promotion | `promote-repros.py` | fuzz host / Orb VM | `REPORT.md`, `REPRO.md`, `POC.md`, `.status=repro-ok` when replay confirms |
| snapshot | `collect.py` | fuzz host / Orb VM | JSON to stdout |
| render/send | `send-digest.py` | Mac/control host | HTML/text digest artifacts, Resend email |
| launchd install | `install-macos.sh` | Mac/control host | dashboard + digest LaunchAgents |

The email sender calls the first three stages through
`shared/run-on-fuzz-host.sh`, then renders and sends from the Mac.

## Report Artifacts

Each promoted crash directory can contain:

- `REPORT.md` - concise summary, class, severity, signal, next step
- `REPRO.md` - exact replay command and observed output excerpt
- `POC.md` - copy/paste reproducer code and PoC metadata
- `REVIEW.md` - optional agentic root-cause review, generated separately

The fuhq dashboard renders `REPORT.md`, `POC.md`, and `REPRO.md` near the top
of `/c/<target>/<hash>`, before raw `trace.txt` and `meta.json`.

`promote-repros.py` is deterministic. It does not ask Codex or Claude to invent
an explanation. It replays the crash and templates a report from observed facts:
exit code, sanitizer/signal class, top frame, hit count, and replay output.
For targets with a local assessment profile, reports also include:

- `issue_class` - stable bucket such as `oson-recursion-dos`
- `impact` - operator-facing impact category such as `parser-dos`
- `confidence` - confidence in the bucket/reachability assessment
- `report_priority` - 0-100 ranking input for the email digest
- source context around the top frame

For `node-oracledb`, "memory outside buffer bounds" means Node's safe
JavaScript `Buffer` bounds check unless ASAN/native evidence says otherwise.
The reports explicitly call this out so parser DoS and native memory corruption
are not conflated.

`REVIEW.md` is the place for richer LLM-assisted root cause analysis. The
existing `shared/fuzz-dashboard/review-drain.sh` uses a non-interactive Claude
review path for crashes in `review-requested`. Keep that separate from the
six-hour digest unless you deliberately want the email job to spend model
budget.

## Email Policy

The digest sends links, not raw crash attachments.

Reasons:

- malformed PoCs can be quarantined by mail providers
- raw crash files may be large or binary-only
- Resend attachments have a finite size limit after base64 encoding
- dashboard links keep the highest-fidelity view: report, trace, PoC hexdump,
  download, and status controls in one place

The email includes HTML and text bodies. Resend settings live in a private env
file, normally:

```sh
/Users/minimo/fuzzig/.secrets/fuzz-crash-digest.env
```

Expected keys:

```sh
RESEND_API_KEY=re_...
FUZZ_DIGEST_FROM=Fuzzah <michael@msandborn.dev>
FUZZ_DIGEST_TO=michael@msandborn.dev
FUZZ_DASHBOARD_BASE_URL=https://<mac-mini>.<tailnet>.ts.net
```

The sender uses a Resend `Idempotency-Key` derived from the six-hour bucket and
subject so retries do not produce duplicate emails within Resend's idempotency
window.

## Manual Commands

Dry-run the whole email path without sending:

```sh
bash shared/crash-digest/send-digest.sh --dry-run
```

Skip the side-effect stages and only render from current state:

```sh
bash shared/crash-digest/send-digest.sh --dry-run --skip-triage --skip-repro
```

Promote reproducible reports only:

```sh
bash shared/run-on-fuzz-host.sh \
  'python3 /Users/minimo/fuzzig/fuzzah/shared/crash-digest/promote-repros.py --limit 6'
```

Install Mac launchd jobs:

```sh
bash shared/crash-digest/install-macos.sh --dry-run
bash shared/crash-digest/install-macos.sh --tailscale-serve
```

The dashboard LaunchAgent keeps `fuhq` listening on `127.0.0.1:8765`.
`tailscale serve --bg 8765` exposes that localhost service to the tailnet when
`--tailscale-serve` is used.

The launchd dashboard job runs with `FUZZ_DASHBOARD_READ_ONLY=1`. The Tailscale
URL is meant for phone-friendly report viewing and PoC download, not workflow
mutation. Status changes remain available from a local writable dashboard if an
operator starts one explicitly. Do not enable Tailscale Funnel for this service;
Serve is tailnet-only, while Funnel would publish crash reports and PoCs to the
public internet.

The LaunchAgents set a full Homebrew-aware `PATH` because the dashboard and
digest call `shared/run-on-fuzz-host.sh`, which needs to find `orb` from
launchd's otherwise minimal environment.

## Known-Issue Correlation

The digest can prove what reproduced locally; it cannot prove novelty. For
external triage, correlate stable crash signatures against public sources:

- upstream GitHub issues and PRs for `oracle/node-oracledb`
- GitHub advisories, NVD/CVE, and release notes for `node-oracledb`/`oracledb`
- commits after the pinned source revision under test

Use the normalized signature, source file, function/frame, exception class, and
affected revision. Treat public-search misses as "no obvious public match", not
as proof that Oracle has never received a private report or silently fixed the
same root cause.

## Tuning

Set these in the private env file:

| variable | default | purpose |
|----------|---------|---------|
| `FUZZ_DIGEST_MAX_TRIAGE_PER_TARGET` | `25` | max raw AFL crashes drained per target per digest |
| `FUZZ_DIGEST_MAX_TRIAGE_TOTAL` | `75` | global raw crash drain cap |
| `FUZZ_DIGEST_REPRO_LIMIT` | `6` | max crash clusters promoted to reports per digest |
| `FUZZ_DIGEST_REPRO_TIMEOUT` | `45` | replay timeout per promoted crash |
| `FUZZ_DIGEST_MAX_CRASHES` | `12` | max rows shown in email |

Keep the caps conservative. The digest should summarize progress, not compete
with active fuzzers.

The email has a global top table plus a per-target highlights section. The
global table can be dominated by an older target with many high-priority
changes; per-target highlights keep newer targets such as `node-oracledb`
visible without inflating every raw AFL hit into the top list.

The dashboard and digest treat `REPORT.md` `report_priority` as the displayed
priority and primary ordering signal when it exists. Raw AFL `hit_count` remains
visible because it describes stability/repro frequency, but it should not make a
safe parser exception look more security-relevant than a lower-hit higher-impact
finding. The HTML email intentionally uses a light high-contrast palette with
light-only color-scheme hints; this survives mobile mail clients better than the
dark dashboard palette.

## External References

- Resend send API: https://resend.com/docs/api-reference/emails/send-email
- Resend idempotency keys: https://resend.com/docs/dashboard/emails/idempotency-keys
- Tailscale Serve: https://tailscale.com/docs/features/tailscale-serve
