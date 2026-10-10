# Verifying this record

An a11yci evidence export is designed to be verified **without trusting
a11yci**. This page shows how to check, from the export file alone plus the
public Bitcoin blockchain, that the record is internally consistent and that
it existed on the dates it claims. You need no a11yci account, no a11yci
software, and no cooperation from us.

> **Scope.** Automated testing detects a minority of WCAG success criteria;
> manual evaluation and assistive-technology testing are required to assess
> conformance. This record documents **testing performed, not conformance
> achieved** — and this page verifies the record's integrity and dates, not
> the accessibility of any site.

## What the export contains

The export is a single JSON file in a canonical encoding (sorted keys, no
insignificant whitespace). Byte-for-byte reproducibility is the point: the
same data always produces the same bytes, so hashes of it are meaningful.

The parts relevant to verification:

- **`scans[]`** — one entry per scheduled monitoring window. Completed scans
  carry a `manifest` (how the scan ran: tool and browser versions, viewport),
  a `results_digest` (SHA-256 of the raw scan output), a `content_hash`, and
  a `prev_content_hash`.
- **`chain`** — the first (`genesis`) and latest (`head`) hash of the chain.
- **`anchors[]`** — for each anchored chain head: the **raw OpenTimestamps
  protocol bytes** (base64) returned by public calendar servers at submission
  (`submissions`) and after Bitcoin confirmation (`upgrades`), plus the
  derived calendar `commitments`.

Each scan's `content_hash` is:

```
content_hash = SHA-256( canonical_json({
  "manifest":          <the scan's manifest>,
  "results_digest":    <the scan's results digest>,
  "prev_content_hash": <the previous scan's content_hash, null for the first>
}) )
```

Because every hash commits to the previous one, altering any historical entry
changes every hash after it — including the heads that were timestamped to
Bitcoin on dates that cannot be moved.

## Quick start: the standalone verifier

[`verify_record.py`](verify_record.py) is a single-file script,
Python standard library only (3.9+, preinstalled on most machines) — read it
first; it is short on purpose.

```console
$ python3 verify_record.py evidence-export.json
```

`evidence-export.json` is the record itself: in the a11yci dashboard, open
the repo and click **Download evidence** (also on the repo's evidence page).
If someone handed you the record — a disclosure, a filing — use the exact
file you were given; the checks below are about those bytes, not a fresh
download.

Example output against a real export (wcag-bad-demo, October 2026):

```
[1/2] Hash chain — 14 chained scan(s)
  2026-09-20T00:00:00Z  6bbe3f5d0fcf32bb…  ok
  ...
  2026-10-03T00:00:00Z  64ebd33f4df45013…  ok
  genesis 6bbe3f5d0fcf32bb… head 64ebd33f4df45013… (match the export's chain section: true)

[2/2] Bitcoin anchors — 13 anchor(s)
  anchor 1f8ef18ecfe60c26… (submitted 2026-09-21T06:00:07Z): ok — Bitcoin block 967953 (2026-09-21 06:04 UTC), merkle root matches
  ...

RESULT: PASS — every check succeeded.
```

It recomputes every chain hash from scratch, replays the OpenTimestamps bytes
from each anchored head to a Bitcoin block height, fetches that block's header
from a public explorer, and compares merkle roots. `--offline` skips the
explorer lookups (everything else is pure local computation).

## Checking the chain by hand

You do not need our script for the chain. In Python:

```python
import json, hashlib

def canonical(v):
    # sorted keys, compact separators, & < > escaped as \uXXXX
    s = json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return s.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")

e = json.load(open("evidence-export.json"))
prev = None
for scan in [s for s in e["scans"] if s["content_hash"]]:
    payload = canonical({"manifest": scan["manifest"],
                         "results_digest": scan["results_digest"],
                         "prev_content_hash": prev})
    h = hashlib.sha256(payload.encode()).hexdigest()
    assert h == scan["content_hash"], f"MISMATCH at {scan['scheduled_for']}"
    assert scan["prev_content_hash"] == prev, f"BROKEN LINK at {scan['scheduled_for']}"
    prev = h
print("chain ok; head =", prev)
```

The final `prev` must equal `chain.head` in the export.

> Note: the canonical string encoding escapes `&`, `<` and `>` as `\u0026`,
> `\u003c`, `\u003e` (a common JSON-in-HTML convention). The Python above
> reproduces it; if a hash mismatches, check the escaping first.

## Checking the Bitcoin anchors

Each anchor contains raw [OpenTimestamps](https://opentimestamps.org) data.
Three independent ways to check it:

**1. Our standalone script** (above) — replays the bytes directly.

**2. The official OpenTimestamps client.** Write the upgraded timestamp bytes
to a file and verify with the `ots` tool against your own (or any) Bitcoin
node. The `.ots` file format is a header plus the same timestamp bytes the
export carries; the script's source shows the exact assembly, or use
`ots verify` on a reconstructed file:

```console
$ pip install opentimestamps-client
$ ots verify record-head.ots     # against a local Bitcoin node
```

**3. A Bitcoin node, no OTS tooling.** The replay in `verify_record.rb`
reduces each anchor to two facts: a block **height** and an expected **merkle
root**. Compare against your node:

```console
$ bitcoin-cli getblockhash 967953
$ bitcoin-cli getblockheader <hash>   # compare "merkleroot", read "time"
```

or any public explorer, e.g.:

```console
$ curl -s https://blockstream.info/api/block-height/967953
$ curl -s https://blockstream.info/api/block/<hash> | jq '.merkle_root, .timestamp'
```

The block's timestamp is the attested date: the chain head (and therefore
every scan it commits to) existed **no later than** that block.

## What this does and does not establish

**Established by the checks above:**

- The record is internally consistent — no scan entry was altered, inserted,
  or removed after the fact without breaking the chain.
- The scanned URLs, the repo identity, the branch, and — where the scan ran
  against a known commit — the commit SHA are inside each scan's hashed
  manifest: re-attributing the record to a different site, repo, or commit
  after the fact breaks the chain.
- The anchored chain heads existed on the Bitcoin-attested dates, on public
  infrastructure outside a11yci's control.
- Every scheduled window is accounted for — missed windows appear in the
  record as `missed`, never silently omitted.

**Not established (and not claimed):**

- That the scanned site is accessible or satisfies any legal standard. The
  record's own limitations section governs: it documents testing performed.
- That the target site actually served the scanned content. The scanner
  self-reports what it fetched; the identity binding shows whether that
  claim has been tampered with since it was recorded, not whether it was
  accurate in the first place.
- That `results_digest` matches the raw scan output — for that, obtain the
  archived raw bytes (available via data export) and compare
  `sha256(raw bytes)` to the digest recorded in the chain.
- The contents of the `findings` and `exceptions` sections are derived
  renderings of the same scans; they are convenience views, not separately
  hashed material.

## Porting the verifier to another language

Everything the script does is documented above — the canonical encoding, the
hash recipe, and the OpenTimestamps replay. If your situation calls for an
independent reimplementation (for example, an expert who should not rely on
tooling supplied by the party whose record is being examined), reimplement it
in any language you trust, by hand or with an AI coding agent, from this page
and the reference script.

Before relying on a port, make it pass the test vectors in
[`test_vectors/`](test_vectors/): it must verify `valid.json`
(hashes listed in `expected.json`) and fail every `tampered_*.json` for the
reason each one was built to trigger. A verifier that passes tampered input
is worse than no verifier.

## Questions

If a verification step fails on a record we issued, we want to know:
**support@a11yci.com**.
