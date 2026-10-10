#!/usr/bin/env python3
"""verify_record.py — standalone verifier for an a11yci evidence export.

Verifies, with no trust in a11yci:
  1. CHAIN   — recomputes every scan's content hash from its recorded method
               manifest + results digest and walks the links (genesis -> head).
  2. ANCHORS — replays the raw OpenTimestamps bytes included in the export:
               chain head -> calendar commitment -> Bitcoin block height, and
               (unless --offline) compares the derived merkle root against the
               public Bitcoin blockchain via a block explorer.

What this cannot check from the export alone: that each results_digest matches
the archived raw scan output (request the raw archive and sha256 it yourself),
and the findings/exceptions sections (derived renderings of the same scans).

This is the reference implementation. A faithful port in any other language
must produce the same verdicts on the test vectors in test_vectors/.

Dependencies: Python >= 3.9 standard library ONLY. No pip installs, no a11yci code.

    python3 verify_record.py path/to/evidence-export.json [--offline]

Exit status: 0 = every check passed, 1 = any check failed.
"""

import base64
import hashlib
import io
import json
import os
import sys
import urllib.request
from datetime import datetime, timezone

# -----------------------------------------------------------------------------
# Canonical JSON — byte-identical reimplementation of the encoding a11yci
# hashes (sorted keys, compact separators, HTML-entity escaping of & < >,
# floats rejected as non-deterministic). The chain hashes below are
# only meaningful because this produces the exact bytes the server hashed.
# -----------------------------------------------------------------------------

_ESCAPES = (("&", "\\u0026"), ("<", "\\u003c"), (">", "\\u003e"))


def canonical_dump(value):
    out = []
    _encode(value, out)
    return "".join(out)


def _encode(value, out):
    # bool must be tested before int: True/False are ints in Python.
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, int):
        out.append(str(value))
    elif isinstance(value, float):
        raise ValueError("float %r in evidence data is not canonicalizable" % value)
    elif isinstance(value, str):
        encoded = json.dumps(value, ensure_ascii=False)
        for char, escape in _ESCAPES:
            encoded = encoded.replace(char, escape)
        out.append(encoded)
    elif isinstance(value, dict):
        out.append("{")
        for i, key in enumerate(sorted(str(k) for k in value)):
            if i:
                out.append(",")
            _encode(key, out)
            out.append(":")
            _encode(value[key], out)
        out.append("}")
    elif isinstance(value, list):
        out.append("[")
        for i, element in enumerate(value):
            if i:
                out.append(",")
            _encode(element, out)
        out.append("]")
    else:
        raise ValueError("unsupported type %s in evidence data" % type(value).__name__)


# -----------------------------------------------------------------------------
# OpenTimestamps deserializer — walks a timestamp's op tree from a starting
# message, collecting every attestation it commits to. Ops and tags per the
# OpenTimestamps serialization spec (varints are LEB128).
# -----------------------------------------------------------------------------

PENDING_TAG = bytes.fromhex("83dfe30d2ef90c8e")  # calendar (pending)
BITCOIN_TAG = bytes.fromhex("0588960d73d71901")  # Bitcoin block header


class ParseError(Exception):
    pass


class Ots:
    @classmethod
    def replay(cls, start_msg, data):
        """Returns {"pending": [{commitment, url}], "bitcoin": [{height, merkle_msg}]}."""
        return cls(data).parse(start_msg)

    def __init__(self, data):
        self.io = io.BytesIO(bytes(data))

    def parse(self, msg):
        self.found = {"pending": [], "bitcoin": []}
        self._walk(bytes(msg))
        return self.found

    def _walk(self, msg):
        while True:
            tag = self._read_byte()
            if tag == 0xFF:  # fork: a complete sub-tree of the same msg
                self._walk(msg)
            elif tag == 0x00:
                return self._read_attestation(msg)
            else:
                msg = self._apply_op(tag, msg)

    def _read_attestation(self, msg):
        attestation_type = self.io.read(8)
        if len(attestation_type) != 8:
            raise ParseError("truncated attestation type")

        payload = self._read_varbytes(self.io)
        if attestation_type == PENDING_TAG:
            url = self._read_varbytes(io.BytesIO(payload))
            self.found["pending"].append({"commitment": msg, "url": url.decode("utf-8")})
        elif attestation_type == BITCOIN_TAG:
            # Payload is the Bitcoin block height; at this point in the op tree
            # the message equals that block's merkle root (internal byte order).
            height = self._read_varint(io.BytesIO(payload))
            self.found["bitcoin"].append({"height": height, "merkle_msg": msg})

    def _apply_op(self, tag, msg):
        if tag == 0xF0:
            return msg + self._read_varbytes(self.io)
        if tag == 0xF1:
            return self._read_varbytes(self.io) + msg
        if tag == 0x08:
            return hashlib.sha256(msg).digest()
        if tag == 0x02:
            return hashlib.sha1(msg).digest()
        if tag == 0x67:
            try:
                return hashlib.new("ripemd160", msg).digest()
            except ValueError:
                raise ParseError(
                    "timestamp uses RIPEMD-160 (op 0x67) but this Python/OpenSSL "
                    "build does not provide it"
                )
        raise ParseError("unknown op 0x%02x" % tag)

    def _read_byte(self):
        byte = self.io.read(1)
        if not byte:
            raise ParseError("unexpected end of timestamp")
        return byte[0]

    def _read_varint(self, stream):
        value = 0
        shift = 0
        while True:
            byte = stream.read(1)
            if not byte:
                raise ParseError("unexpected end of varint")
            value |= (byte[0] & 0x7F) << shift
            if not byte[0] & 0x80:
                return value
            shift += 7
            if shift > 63:
                raise ParseError("varint too large")

    def _read_varbytes(self, stream):
        length = self._read_varint(stream)
        data = stream.read(length)
        if len(data) != length:
            raise ParseError("truncated varbytes")
        return data


# -----------------------------------------------------------------------------
# Public Bitcoin block lookup (blockstream.info — swap for any explorer or
# your own node; the doc shows the bitcoin-cli equivalent).
# -----------------------------------------------------------------------------

EXPLORER_BASE = "https://blockstream.info/api"


def explorer_block_at(height):
    block_hash = _explorer_get("/block-height/%d" % height)
    header = json.loads(_explorer_get("/block/%s" % block_hash))
    return {
        "hash": block_hash,
        "merkle_root": header["merkle_root"],
        "time": datetime.fromtimestamp(header["timestamp"], timezone.utc),
    }


def _explorer_get(path):
    url = EXPLORER_BASE + path
    with urllib.request.urlopen(url, timeout=30) as response:
        if response.status != 200:
            raise RuntimeError("explorer %s returned %d" % (url, response.status))
        return response.read().decode("utf-8")


# -----------------------------------------------------------------------------
# The verification run.
# -----------------------------------------------------------------------------

class Runner:
    def __init__(self, envelope, offline=False, out=sys.stdout):
        self.envelope = envelope
        self.offline = offline
        self.out = out
        self.failures = []

    def call(self):
        self._puts("a11yci evidence record verification")
        repo = (self.envelope.get("repo") or {}).get("name")
        self._puts("repo: %s   generated_at: %s" % (repo, self.envelope.get("generated_at")))
        self._puts("")
        chain_hashes = self._verify_chain()
        self._verify_anchors(chain_hashes)
        self._puts("")
        if not self.failures:
            suffix = (
                " (offline: Bitcoin block comparisons were SKIPPED — rerun without"
                " --offline for the full result)" if self.offline else ""
            )
            self._puts("RESULT: PASS — every check succeeded." + suffix)
        else:
            self._puts("RESULT: FAIL — %d check(s) failed:" % len(self.failures))
            for failure in self.failures:
                self._puts("  ✗ %s" % failure)
        self._puts("")
        self._puts("Not checked from the export alone: results_digest vs archived raw scan")
        self._puts("bytes (obtain the raw archive and compare sha256 yourself); findings/")
        self._puts("exceptions sections (derived renderings of the scans verified above).")
        return not self.failures

    def _puts(self, line):
        self.out.write(line + "\n")

    def _fail(self, message):
        self.failures.append(message)
        return False

    def _verify_chain(self):
        entries = [s for s in self.envelope.get("scans") or [] if s.get("content_hash")]
        self._puts("[1/2] Hash chain — %d chained scan(s)" % len(entries))
        prev = None
        verified = []
        for scan in entries:
            payload = canonical_dump({
                "manifest": scan["manifest"],
                "results_digest": scan["results_digest"],
                "prev_content_hash": prev,
            })
            recomputed = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            ok_link = scan.get("prev_content_hash") == prev
            ok_hash = scan["content_hash"] == recomputed
            status = "ok" if ok_link and ok_hash else "FAIL"
            self._puts("  %s  %s…  %s" % (scan.get("scheduled_for"), scan["content_hash"][:16], status))
            if not ok_link:
                self._fail("chain link broken at %s (prev mismatch)" % scan.get("scheduled_for"))
            if not ok_hash:
                self._fail("content hash mismatch at %s: recomputed %s" % (scan.get("scheduled_for"), recomputed))
            prev = scan["content_hash"]
            verified.append(scan["content_hash"])

        chain = self.envelope.get("chain") or {}
        first = verified[0] if verified else None
        last = verified[-1] if verified else None
        if chain.get("genesis") != first:
            self._fail("chain.genesis %s != walked genesis %s" % (chain.get("genesis"), first))
        if chain.get("head") != last:
            self._fail("chain.head %s != walked head %s" % (chain.get("head"), last))
        matches = chain.get("genesis") == first and chain.get("head") == last
        self._puts("  genesis %s… head %s… (match the export's chain section: %s)" % (
            first[:16] if first else "", last[:16] if last else "", str(matches).lower()))
        return verified

    def _verify_anchors(self, chain_hashes):
        anchors = self.envelope.get("anchors") or []
        self._puts("")
        self._puts("[2/2] Bitcoin anchors — %d anchor(s)%s" % (
            len(anchors), " (offline: block lookup skipped)" if self.offline else ""))
        for anchor in anchors:
            self._verify_anchor(anchor, chain_hashes)

    def _verify_anchor(self, anchor, chain_hashes):
        head = anchor["content_hash"]
        label = "anchor %s… (submitted %s)" % (head[:16], anchor.get("submitted_at"))

        if head not in chain_hashes:
            return self._fail("%s: anchored hash is not part of the verified chain" % label)

        digest = bytes.fromhex(head)
        derived = {}
        for calendar, encoded in (anchor.get("submissions") or {}).items():
            try:
                for pending in Ots.replay(digest, base64.b64decode(encoded))["pending"]:
                    derived[pending["url"]] = pending["commitment"].hex()
            except ParseError as error:
                self._fail("%s: submission from %s unparseable: %s" % (label, calendar, error))

        for url, expected_hex in (anchor.get("commitments") or {}).items():
            if derived.get(url) != expected_hex:
                self._fail("%s: commitment for %s does not derive from the chain head" % (label, url))

        bitcoin = []
        for url, encoded in (anchor.get("upgrades") or {}).items():
            commitment_hex = (anchor.get("commitments") or {}).get(url)
            if not commitment_hex:
                self._fail("%s: upgrade from %s has no matching commitment" % (label, url))
                continue
            try:
                found = Ots.replay(bytes.fromhex(commitment_hex), base64.b64decode(encoded))["bitcoin"]
            except ParseError as error:
                self._fail("%s: upgrade from %s unparseable: %s" % (label, url, error))
                continue
            if not found:
                self._fail("%s: upgrade from %s contains no Bitcoin attestation" % (label, url))
                continue
            bitcoin.extend(found)

        if anchor.get("status") == "attested" and not bitcoin:
            return self._fail("%s: marked attested but no Bitcoin attestation replayed" % label)

        seen_heights = set()
        for attestation in bitcoin:
            if attestation["height"] in seen_heights:
                continue
            seen_heights.add(attestation["height"])
            # OTS records merkle roots in Bitcoin's internal byte order; explorers
            # display the reversed hex.
            expected_root = attestation["merkle_msg"][::-1].hex()
            if self.offline:
                self._puts("  %s: block %d, expect merkle root %s… (not checked, offline)" % (
                    label, attestation["height"], expected_root[:16]))
                continue
            try:
                block = explorer_block_at(attestation["height"])
            except Exception as error:
                self._fail("%s: block %d lookup failed: %s" % (label, attestation["height"], error))
                continue
            if block["merkle_root"] == expected_root:
                self._puts("  %s: ok — Bitcoin block %d (%s), merkle root matches" % (
                    label, attestation["height"], block["time"].strftime("%Y-%m-%d %H:%M UTC")))
            else:
                self._fail("%s: block %d merkle root mismatch (chain says %s, replay says %s)" % (
                    label, attestation["height"], block["merkle_root"], expected_root))


def main(argv):
    args = list(argv)
    offline = "--offline" in args
    if offline:
        args.remove("--offline")
    path = args[0] if args else None
    if not path or not os.path.isfile(path):
        print("usage: python3 verify_record.py path/to/evidence-export.json [--offline]", file=sys.stderr)
        return 2

    try:
        with open(path, "rb") as handle:
            envelope = json.load(handle)
    except json.JSONDecodeError as error:
        print("not a valid evidence export (JSON parse failed): %s" % error, file=sys.stderr)
        return 2

    return 0 if Runner(envelope, offline=offline).call() else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
