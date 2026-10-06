#!/usr/bin/env python3
"""record.py: keep and check the sealed forward record.

The record is MANIFEST.csv: one row per event, append-only. Each row
carries the SHA-256 of every byte of the manifest above it, so no row
can be changed, dropped or inserted without breaking every later row.
Sealed files never enter this repository. Only their SHA-256 and their
OpenTimestamps proof do.

Commands
  init            create MANIFEST.csv with its header (once)
  seal-protocol   seal one version of the sealing rules
  seal-read       seal one lane read: our list, gold-1, gold-2, incumbent
  outcome-read    record that a seal's first outcome was read (no scores)
  withdraw        withdraw a seal, allowed only before its first outcome read
  stamp-manifest  stamp the whole manifest as it stands now
  upgrade         fetch the Bitcoin confirmation for every proof
  verify          check every row, the chain and every proof

Python 3.8 or later. Checking the chain needs the standard library
only. Stamping, upgrading and verify --bitcoin need the OpenTimestamps
library:  python -m pip install opentimestamps==0.4.5
"""

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "MANIFEST.csv"
PROOFS = ROOT / "proofs"
MANIFEST_PROOFS = PROOFS / "manifest"

HEADER = ("seq,utc_time,status,lane,seal_id,item,list_size,supersedes,"
          "reason_class,gate,receipt,sha256,ots_proof,prev_manifest_sha256")
COLS = HEADER.split(",")

LIST_ITEMS = ("list", "gold-1", "gold-2", "incumbent")
LIST_REASONS = ("tools-added", "data-corrected", "window-changed",
                "defect-fixed", "unit-changed")
PROTOCOL_REASONS = ("rule-added",)
WITHDRAW_CAUSES = ("data-error", "testing-error", "tools-not-applied",
                   "instrument", "hardware")

RE_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
RE_LANE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
RE_SEAL = re.compile(r"^([a-z0-9]+(?:-[a-z0-9]+)*)-v([1-9][0-9]*)$")
RE_HEX = re.compile(r"^[0-9a-f]{64}$")
RE_RECEIPT = re.compile(r"^[A-Za-z]{0,8}-?[0-9]{1,8}$")
RE_GATE = re.compile(r"^([1-9][0-9]?)/([1-9][0-9]?)$")
RE_RULE = re.compile(r"^rule:([1-9][0-9]?)$")
RE_MANIFEST_PROOF = re.compile(r"^through-row-([0-9]{4,})\.ots$")
SALT_LINE = re.compile(rb"^salt: [0-9a-f]{64}\n")

OTS_MAGIC = (b"\x00OpenTimestamps\x00\x00Proof\x00"
             b"\xbf\x89\xe2\xe8\x84\xe8\x92\x94")
CALENDARS = ("https://a.pool.opentimestamps.org", "https://b.pool.opentimestamps.org",
             "https://a.pool.eternitywall.com", "https://ots.btc.catallaxy.com")
CALENDARS_NEEDED = 2
UPGRADE_FROM = ["https://*.calendar.opentimestamps.org", "https://*.calendar.eternitywall.com",
                "https://*.calendar.catallaxy.com"]
EXPLORERS = ("https://blockstream.info/api", "https://mempool.space/api")

# Only these paths may ever be tracked. Anything else is a leak.
ALLOWED_TRACKED = (
    r"README\.md", r"RULES\.md", r"LICENSE", r"MANIFEST\.csv",
    r"\.gitignore", r"\.gitattributes", r"\.github/workflows/verify\.yml",
    r"tools/record\.py",
    r"proofs/[0-9]{4,}-[a-z0-9-]+\.ots",
    r"proofs/manifest/through-row-[0-9]{4,}\.ots",
)


class Refused(Exception):
    """A command refused to write. The manifest is unchanged."""


# ---------------------------------------------------------------- basics

def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def utc_now():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def valid_time(value):
    if not RE_TIME.match(value):
        return False
    try:
        dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return False
    return True


def proof_path(seq, seal_id, item):
    return "proofs/%04d-%s-%s.ots" % (seq, seal_id, item)


def manifest_proof_path(row_count):
    return MANIFEST_PROOFS / ("through-row-%04d.ots" % row_count)


def read_manifest():
    if not MANIFEST.exists():
        raise Refused("MANIFEST.csv is missing: run  python tools/record.py init")
    return MANIFEST.read_bytes()


def outside_repo(path):
    resolved = Path(path).resolve()
    try:
        resolved.relative_to(ROOT)
    except ValueError:
        return resolved
    raise Refused("%s is inside the repository folder. Sealed files must stay "
                  "outside it (beside the ledger); only their hash goes in." % path)


# ------------------------------------------------------- proof file format

def read_varuint(buf, i):
    value = shift = 0
    while True:
        if i >= len(buf):
            raise ValueError("proof file is truncated")
        byte = buf[i]
        i += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, i
        shift += 7


def proof_digest(data):
    """The SHA-256 digest an OpenTimestamps proof commits to, as hex."""
    if not data.startswith(OTS_MAGIC):
        raise ValueError("not an OpenTimestamps proof")
    major, i = read_varuint(data, len(OTS_MAGIC))
    if major != 1:
        raise ValueError("unsupported proof version %d" % major)
    if i >= len(data) or data[i] != 0x08:
        raise ValueError("proof is not over a SHA-256 digest")
    digest = data[i + 1:i + 33]
    if len(digest) != 32:
        raise ValueError("proof file is truncated")
    return digest.hex()


# ------------------------------------------------------ manifest checking

class State:
    """What the manifest says, rebuilt row by row."""

    def __init__(self):
        self.rows = []          # dicts, one per row, with byte offsets
        self.protocols = []     # (version, checks, seq)
        self.seals = {}         # seal_id -> info dict (lane seals only)
        self.last_version = {}  # lane -> highest version sealed

    @property
    def checks_in_force(self):
        return self.protocols[-1][1] if self.protocols else None


def check_manifest(raw):
    """Check the manifest bytes. Returns (problems, state)."""
    problems = []
    st = State()
    if not raw.isascii():
        problems.append("MANIFEST.csv must be plain ASCII")
        return problems, st
    if b"\r" in raw:
        problems.append("MANIFEST.csv has Windows line endings (CR); it must use LF only")
        return problems, st
    if not raw.endswith(b"\n"):
        problems.append("MANIFEST.csv must end with a newline")
        return problems, st
    lines = raw.decode("ascii").split("\n")[:-1]
    if not lines or lines[0] != HEADER:
        problems.append("line 1 must be exactly the header:\n  " + HEADER)
        return problems, st

    offset = len(lines[0]) + 1
    group = None  # the lane seal being read, while its four rows arrive
    last_time = ""
    for number, line in enumerate(lines[1:], start=1):
        start, offset = offset, offset + len(line) + 1
        where = "row %d" % number
        fields = line.split(",")
        if len(fields) != len(COLS):
            problems.append("%s: has %d fields, needs %d" % (where, len(fields), len(COLS)))
            continue
        r = dict(zip(COLS, fields))
        r["start"], r["end"] = start, offset
        st.rows.append(r)

        if r["seq"] != str(number):
            problems.append("%s: seq is %r, must be %d (rows run 1, 2, 3 ... with no gaps)"
                            % (where, r["seq"], number))
        if not valid_time(r["utc_time"]):
            problems.append("%s: utc_time %r is not YYYY-MM-DDTHH:MM:SSZ" % (where, r["utc_time"]))
        elif r["utc_time"] < last_time:
            problems.append("%s: utc_time goes backwards (%s after %s)"
                            % (where, r["utc_time"], last_time))
        else:
            last_time = r["utc_time"]
        expected_prev = sha256_hex(raw[:start])
        if r["prev_manifest_sha256"] != expected_prev:
            problems.append("%s: chain broken: prev_manifest_sha256 must be %s (the SHA-256 of "
                            "every byte above this row)" % (where, expected_prev))

        # A lane seal is four rows in a fixed order, written together.
        if group is not None:
            expect = LIST_ITEMS[len(group["items"])]
            same = ("utc_time", "lane", "seal_id", "list_size", "supersedes",
                    "reason_class", "gate", "receipt")
            if (r["status"] != "sealed" or r["item"] != expect
                    or any(r[k] != group["first"][k] for k in same)):
                problems.append("%s: the seal %s needs its %s row here, with the same time, size, "
                                "gate and receipt as its list row"
                                % (where, group["first"]["seal_id"], expect))
                group = None
            else:
                if r["sha256"] in group["hashes"]:
                    problems.append("%s: same sha256 as another file in this seal" % where)
                group["hashes"].add(r["sha256"])
                group["items"].append(r["item"])
                _check_sealed_file(r, number, where, problems)
                if len(group["items"]) == len(LIST_ITEMS):
                    group = None
                continue

        status = r["status"]
        if status == "sealed" and r["lane"] == "protocol":
            _check_protocol(r, number, where, st, problems)
        elif status == "sealed":
            group = _check_lane_seal(r, number, where, st, problems)
        elif status in ("withdrawn", "outcome-read"):
            _check_event(r, where, st, problems)
        else:
            problems.append("%s: status %r must be sealed, withdrawn or outcome-read"
                            % (where, status))
        if number == 1 and not (status == "sealed" and r["lane"] == "protocol"):
            problems.append("row 1 must seal the protocol (the rules come before any list)")

    if group is not None:
        problems.append("the seal %s is missing rows: it has %s, needs %s"
                        % (group["first"]["seal_id"], ", ".join(group["items"]),
                           ", ".join(LIST_ITEMS)))
    return problems, st


def _check_sealed_file(r, number, where, problems):
    if not RE_HEX.match(r["sha256"]):
        problems.append("%s: sha256 must be 64 lowercase hex characters" % where)
    expected = proof_path(number, r["seal_id"], r["item"])
    if r["ots_proof"] != expected:
        problems.append("%s: ots_proof must be %s" % (where, expected))


def _check_protocol(r, number, where, st, problems):
    version = len(st.protocols) + 1
    if r["seal_id"] != "protocol-v%d" % version or r["item"] != "protocol":
        problems.append("%s: the next protocol row must be seal_id protocol-v%d, item protocol"
                        % (where, version))
    m = RE_RULE.match(r["gate"])
    checks = int(m.group(1)) if m else None
    if checks is None:
        problems.append("%s: a protocol row's gate is rule:N, N = the checks this version defines"
                        % where)
    if r["list_size"] != "-":
        problems.append("%s: list_size must be - on a protocol row" % where)
    if r["receipt"] != "-" and not RE_RECEIPT.match(r["receipt"]):
        problems.append("%s: receipt %r is not a ledger receipt" % (where, r["receipt"]))
    if version == 1:
        if r["supersedes"] != "-" or r["reason_class"] != "-":
            problems.append("%s: protocol-v1 supersedes nothing (- and -)" % where)
    else:
        if r["supersedes"] != "protocol-v%d" % (version - 1):
            problems.append("%s: protocol-v%d must supersede protocol-v%d"
                            % (where, version, version - 1))
        if r["reason_class"] not in PROTOCOL_REASONS:
            problems.append("%s: reason_class must be one of %s"
                            % (where, ", ".join(PROTOCOL_REASONS)))
        elif (r["reason_class"] == "rule-added" and checks is not None
              and st.checks_in_force is not None and checks <= st.checks_in_force):
            problems.append("%s: rule-added, so it must define more than %d checks"
                            % (where, st.checks_in_force))
    _check_sealed_file(r, number, where, problems)
    st.protocols.append((version, checks or 0, number))


def _check_lane_seal(r, number, where, st, problems):
    lane = r["lane"]
    if not RE_LANE.match(lane) or re.search(r"-v[0-9]+$", lane):
        problems.append("%s: lane %r must be lowercase words joined by -" % (where, lane))
    m = RE_SEAL.match(r["seal_id"])
    if not m or m.group(1) != lane:
        problems.append("%s: seal_id must be %s-vN" % (where, lane))
        return None
    version = int(m.group(2))
    expected = st.last_version.get(lane, 0) + 1
    if version != expected:
        problems.append("%s: the next %s seal is %s-v%d" % (where, lane, lane, expected))
    if r["item"] != "list":
        problems.append("%s: a seal opens with its list row, then gold-1, gold-2, incumbent"
                        % where)
    if not st.protocols:
        problems.append("%s: no protocol is sealed yet" % where)
    else:
        k = st.checks_in_force
        if r["gate"] != "%d/%d" % (k, k):
            problems.append("%s: gate must be %d/%d: a list is sealed only when every check "
                            "in protocol-v%d passes" % (where, k, k, st.protocols[-1][0]))
    if not r["list_size"].isdigit() or int(r["list_size"]) < 1:
        problems.append("%s: list_size must be a whole number of entries" % where)
    if not RE_RECEIPT.match(r["receipt"]):
        problems.append("%s: a seal needs its ledger receipt" % where)
    if version == 1:
        if r["supersedes"] != "-" or r["reason_class"] != "-":
            problems.append("%s: %s-v1 supersedes nothing (- and -)" % (where, lane))
    else:
        if r["supersedes"] != "%s-v%d" % (lane, version - 1):
            problems.append("%s: %s must supersede %s-v%d"
                            % (where, r["seal_id"], lane, version - 1))
        if r["reason_class"] not in LIST_REASONS:
            problems.append("%s: reason_class must be one of %s"
                            % (where, ", ".join(LIST_REASONS)))
    _check_sealed_file(r, number, where, problems)
    st.last_version[lane] = max(version, st.last_version.get(lane, 0))
    st.seals[r["seal_id"]] = {"lane": lane, "version": version, "seq": number,
                              "time": r["utc_time"], "withdrawn": None,
                              "outcome_read": None}
    return {"first": r, "items": ["list"], "hashes": {r["sha256"]}}


def _check_event(r, where, st, problems):
    for key in ("item", "list_size", "supersedes", "gate", "sha256", "ots_proof"):
        if r[key] != "-":
            problems.append("%s: %s must be - on a %s row" % (where, key, r["status"]))
    seal = st.seals.get(r["seal_id"])
    if seal is None or seal["lane"] != r["lane"]:
        problems.append("%s: %s is not a sealed %s list" % (where, r["seal_id"], r["lane"]))
        return
    if not RE_RECEIPT.match(r["receipt"]):
        problems.append("%s: a %s row needs its ledger receipt" % (where, r["status"]))
    if seal["withdrawn"]:
        problems.append("%s: %s was already withdrawn at row %d"
                        % (where, r["seal_id"], seal["withdrawn"]))
    if r["status"] == "withdrawn":
        if r["reason_class"] not in WITHDRAW_CAUSES:
            problems.append("%s: cause must be one of %s" % (where, ", ".join(WITHDRAW_CAUSES)))
        if seal["outcome_read"]:
            problems.append("%s: %s cannot be withdrawn: its first outcome was read at row %d"
                            % (where, r["seal_id"], seal["outcome_read"]))
        seal["withdrawn"] = int(r["seq"]) if r["seq"].isdigit() else -1
    else:
        if r["reason_class"] != "-":
            problems.append("%s: reason_class must be - on an outcome-read row" % where)
        if seal["outcome_read"]:
            problems.append("%s: the first outcome of %s was already recorded at row %d"
                            % (where, r["seal_id"], seal["outcome_read"]))
        seal["outcome_read"] = int(r["seq"]) if r["seq"].isdigit() else -1


# ------------------------------------------------- files beside the manifest

def check_proofs(raw, st, problems):
    referenced = set()
    for r in st.rows:
        if r["status"] != "sealed":
            continue
        referenced.add(r["ots_proof"])
        path = ROOT / r["ots_proof"]
        if not path.exists():
            problems.append("row %s: proof %s is missing" % (r["seq"], r["ots_proof"]))
            continue
        try:
            digest = proof_digest(path.read_bytes())
        except ValueError as exc:
            problems.append("row %s: %s: %s" % (r["seq"], r["ots_proof"], exc))
            continue
        if digest != r["sha256"]:
            problems.append("row %s: proof %s is for %s, not this row's sha256"
                            % (r["seq"], r["ots_proof"], digest))

    covered = set()
    if MANIFEST_PROOFS.exists():
        for path in sorted(MANIFEST_PROOFS.iterdir()):
            m = RE_MANIFEST_PROOF.match(path.name)
            if not m:
                if not path.name.endswith(".bak"):
                    problems.append("%s does not belong in proofs/manifest" % path.name)
                continue
            n = int(m.group(1))
            if n < 1 or n > len(st.rows):
                problems.append("%s stamps row %d, which does not exist" % (path.name, n))
                continue
            try:
                digest = proof_digest(path.read_bytes())
            except ValueError as exc:
                problems.append("%s: %s" % (path.name, exc))
                continue
            expected = sha256_hex(raw[:st.rows[n - 1]["end"]])
            if digest != expected:
                problems.append("%s does not match the manifest through row %d" % (path.name, n))
            covered.add(n)
    if st.rows and len(st.rows) not in covered:
        problems.append("the newest row (%d) is not stamped yet: run  "
                        "python tools/record.py stamp-manifest" % len(st.rows))

    if PROOFS.exists():
        for path in sorted(PROOFS.iterdir()):
            if path.is_file() and not path.name.endswith(".bak"):
                rel = "proofs/" + path.name
                if rel not in referenced:
                    problems.append("%s is not named by any row" % rel)


def git(*args):
    return subprocess.run(["git", "-C", str(ROOT)] + list(args), capture_output=True)


def check_tracked(problems, notes):
    r = git("ls-files", "-z")
    if r.returncode != 0:
        notes.append("not a git checkout: tracked-file check skipped")
        return
    for name in r.stdout.decode("utf-8", "replace").split("\0"):
        if name and not any(re.fullmatch(p, name) for p in ALLOWED_TRACKED):
            problems.append("%s is tracked: only hashes and proofs belong in this repository"
                            % name)


def check_base(ref, raw, problems):
    """The manifest at ref must be a byte prefix of today's; no proof may vanish."""
    if git("cat-file", "-e", ref + "^{commit}").returncode != 0:
        problems.append("the previous head %s is not in this history: history was rewritten" % ref)
        return
    if git("merge-base", "--is-ancestor", ref, "HEAD").returncode != 0:
        problems.append("HEAD does not descend from %s: history was rewritten" % ref)
        return
    old = git("show", ref + ":MANIFEST.csv")
    if old.returncode == 0 and not raw.startswith(old.stdout):
        problems.append("MANIFEST.csv was edited, not appended: the version at %s is not "
                        "a prefix of this one" % ref[:12])
    listing = git("ls-tree", "-r", "--name-only", ref, "--", "proofs")
    for name in listing.stdout.decode().split("\n"):
        if not name:
            continue
        path = ROOT / name
        if not path.exists():
            problems.append("%s was deleted after it was published" % name)
            continue
        before = git("show", ref + ":" + name).stdout
        try:
            if proof_digest(before) != proof_digest(path.read_bytes()):
                problems.append("%s now proves a different hash" % name)
        except ValueError as exc:
            problems.append("%s: %s" % (name, exc))


# --------------------------------------------------------------- bitcoin

def http_get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "sealed-record-verify"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        return resp.read()


_blocks = {}


def fetch_block(height):
    """(merkle_root_hex, unix_time) of a Bitcoin block, from a public explorer."""
    if height in _blocks:
        return _blocks[height]
    last = None
    for base in EXPLORERS:
        try:
            block_hash = http_get("%s/block-height/%d" % (base, height)).decode().strip()
            info = json.loads(http_get("%s/block/%s" % (base, block_hash)))
            _blocks[height] = (info["merkle_root"], int(info["timestamp"]))
            return _blocks[height]
        except Exception as exc:  # try the next explorer
            last = exc
    raise ConnectionError("no explorer answered for block %d: %s" % (height, last))


def bitcoin_status(data, fetch=fetch_block):
    """('anchored', height, time) / ('pending', None, None); raises ValueError on a bad proof."""
    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
    from opentimestamps.core.serialize import BytesDeserializationContext
    from opentimestamps.core.timestamp import DetachedTimestampFile

    detached = DetachedTimestampFile.deserialize(BytesDeserializationContext(data))
    best = None
    for msg, att in detached.timestamp.all_attestations():
        if isinstance(att, BitcoinBlockHeaderAttestation):
            root_hex, when = fetch(att.height)
            # Explorers print the merkle root byte-reversed.
            if msg != bytes.fromhex(root_hex)[::-1]:
                raise ValueError("Bitcoin block %d does not contain this proof" % att.height)
            if best is None or att.height < best[0]:
                best = (att.height, when)
    if best is None:
        return ("pending", None, None)
    return ("anchored", best[0], best[1])


def check_bitcoin(raw, st, problems, notes):
    try:
        ots_library()
    except Refused as exc:
        problems.append("--bitcoin: %s" % exc)
        return
    paths =[ROOT / r["ots_proof"] for r in st.rows if r["status"] == "sealed"]
    if MANIFEST_PROOFS.exists():
        paths += sorted(p for p in MANIFEST_PROOFS.iterdir() if RE_MANIFEST_PROOF.match(p.name))
    for path in paths:
        if not path.exists():
            continue
        rel = path.relative_to(ROOT).as_posix()
        try:
            state, height, when = bitcoin_status(path.read_bytes())
        except ConnectionError as exc:
            notes.append("%s: could not reach a block explorer (%s)" % (rel, exc))
            continue
        except Exception as exc:
            problems.append("%s: %s" % (rel, exc))
            continue
        if state == "anchored":
            stamp = dt.datetime.fromtimestamp(when, dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            notes.append("%s: anchored in Bitcoin block %d (%s)" % (rel, height, stamp))
        else:
            notes.append("%s: pending; run  python tools/record.py upgrade  a few hours "
                         "after stamping" % rel)


# ------------------------------------------------------------- reporting

def seal_table(st):
    lines = []
    for version, checks, seq in st.protocols:
        state = "in force" if version == st.protocols[-1][0] else "superseded"
        lines.append("  protocol-v%d  row %d  %d checks  %s" % (version, seq, checks, state))
    for seal_id, s in st.seals.items():
        if s["withdrawn"]:
            state = "withdrawn (row %d)" % s["withdrawn"]
        elif s["outcome_read"]:
            state = "scored from row %d" % s["outcome_read"]
        else:
            state = "open"
        if st.last_version.get(s["lane"], 0) > s["version"]:
            state += ", superseded"
        lines.append("  %s  row %d  sealed %s  %s" % (seal_id, s["seq"], s["time"], state))
    return lines


def run_verify(base_ref=None, bitcoin=False, quiet=False):
    raw = read_manifest()
    problems, st = check_manifest(raw)
    notes = []
    if not problems:
        check_proofs(raw, st, problems)
    check_tracked(problems, notes)
    if base_ref:
        check_base(base_ref, raw, problems)
    if bitcoin and not problems:
        check_bitcoin(raw, st, problems, notes)
    if not quiet:
        print("Sealed forward record: %d rows" % len(st.rows))
        for line in seal_table(st):
            print(line)
        for note in notes:
            print("NOTE " + note)
        for problem in problems:
            print("FAIL " + problem)
        print("RESULT: %s" % ("FAIL" if problems else "PASS"))
    return problems


# --------------------------------------------------------------- writing

def ots_library():
    try:
        from opentimestamps import calendar
        from opentimestamps.core import notary, op, serialize, timestamp
    except ImportError:
        raise Refused("the OpenTimestamps library is missing: "
                      "python -m pip install opentimestamps==0.4.5")
    return calendar, notary, op, serialize, timestamp


def serialize_proof(detached):
    _, _, _, serialize, _ = ots_library()
    ctx = serialize.BytesSerializationContext()
    detached.serialize(ctx)
    return ctx.getbytes()


def stamp_bytes(data, calendars=CALENDARS, needed=CALENDARS_NEEDED):
    """Stamp data with public OpenTimestamps calendars. Returns the .ots bytes.

    Only the SHA-256 of a random nonce and the data's hash leaves the
    machine, never the data.
    """
    calendar, _, op, _, timestamp = ots_library()
    detached = timestamp.DetachedTimestampFile(
        op.OpSHA256(), timestamp.Timestamp(hashlib.sha256(data).digest()))
    tip = detached.timestamp.ops.add(op.OpAppend(os.urandom(16))).ops.add(op.OpSHA256())
    answered, errors = 0, []
    for url in calendars:
        try:
            tip.merge(calendar.RemoteCalendar(url).submit(tip.msg, timeout=30))
            answered += 1
        except Exception as exc:  # try every calendar
            errors.append("%s: %s" % (url, exc))
    if answered < needed:
        raise Refused("stamping failed: %d of %d calendars answered, %d needed; nothing was "
                      "written.\n  %s" % (answered, len(calendars), needed, "\n  ".join(errors)))
    proof = serialize_proof(detached)
    if proof_digest(proof) != sha256_hex(data):
        raise Refused("stamping produced a proof for the wrong hash; nothing was written")
    return proof


def upgrade_proof(data):
    """Ask each calendar for the Bitcoin confirmation of a pending proof.

    Returns (new_bytes, anchored) where new_bytes is None if nothing changed.
    """
    calendar, notary, _, serialize, timestamp = ots_library()
    detached = timestamp.DetachedTimestampFile.deserialize(
        serialize.BytesDeserializationContext(data))
    allowed = calendar.UrlWhitelist(UPGRADE_FROM)

    def leaves(stamp):
        if stamp.attestations:
            yield stamp
        for sub in stamp.ops.values():
            yield from leaves(sub)

    changed = False
    for leaf in list(leaves(detached.timestamp)):
        for att in list(leaf.attestations):
            if not isinstance(att, notary.PendingAttestation) or att.uri not in allowed:
                continue
            try:
                upgraded = calendar.RemoteCalendar(att.uri).get_timestamp(leaf.msg, timeout=30)
            except Exception:  # not confirmed yet, or calendar unreachable
                continue
            before = len(list(leaf.all_attestations()))
            leaf.merge(upgraded)
            changed = changed or len(list(leaf.all_attestations())) > before
    anchored = any(isinstance(a, notary.BitcoinBlockHeaderAttestation)
                   for _, a in detached.timestamp.all_attestations())
    return (serialize_proof(detached) if changed else None), anchored


def salted(path):
    """A list file starts with a random salt line so its hash cannot be guessed.

    If the file has no salt line, a salted copy is written beside it as
    <name>.sealed and that copy is what gets sealed and kept.
    """
    data = path.read_bytes()
    if SALT_LINE.match(data):
        return path, data
    out = path.with_name(path.name + ".sealed")
    if out.exists():
        raise Refused("%s already exists: seal that file, or move it away first" % out)
    data = b"salt: " + secrets.token_hex(32).encode() + b"\n" + data
    with open(out, "xb") as fh:
        fh.write(data)
    return out, data


def append(new_rows, proofs):
    """Append rows (dicts without seq/prev) and their proofs, then stamp the manifest."""
    raw = read_manifest()
    problems, st = check_manifest(raw)
    if not problems:
        check_proofs(raw, st, problems)
    if problems:
        raise Refused("the record has problems; nothing was written:\n  "
                      + "\n  ".join(problems))
    out = raw
    for r in new_rows:
        r["prev_manifest_sha256"] = sha256_hex(out)
        out += (",".join(r[c] for c in COLS) + "\n").encode("ascii")
    new_problems, _ = check_manifest(out)
    if new_problems:
        raise Refused("these rows would break the record; nothing was written:\n  "
                      + "\n  ".join(new_problems))
    manifest_proof = stamp_bytes(out)
    written = []
    try:
        for rel, data in proofs.items():
            path = ROOT / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "xb") as fh:
                fh.write(data)
            written.append(path)
        mpath = manifest_proof_path(len(st.rows) + len(new_rows))
        mpath.parent.mkdir(parents=True, exist_ok=True)
        with open(mpath, "xb") as fh:
            fh.write(manifest_proof)
        written.append(mpath)
        tmp = MANIFEST.with_name("MANIFEST.csv.tmp")
        with open(tmp, "wb") as fh:
            fh.write(out)
        os.replace(str(tmp), str(MANIFEST))
    except Exception:
        for path in written:
            path.unlink()
        raise
    first, last = len(st.rows) + 1, len(st.rows) + len(new_rows)
    rows = "row %d" % first if first == last else "rows %d-%d" % (first, last)
    print("Wrote %s." % rows)
    if not run_verify(quiet=True):
        print("Record checks PASS. Next:")
        print('  git add -A && git commit -m "%s: %s" && git push'
              % (rows, new_rows[0]["seal_id"]))
    else:
        run_verify()


def next_row(**values):
    row = {c: "-" for c in COLS}
    row.update(values)
    return row


def cmd_init(_args):
    if MANIFEST.exists():
        raise Refused("MANIFEST.csv already exists; init runs once")
    with open(MANIFEST, "xb") as fh:
        fh.write((HEADER + "\n").encode("ascii"))
    MANIFEST_PROOFS.mkdir(parents=True, exist_ok=True)
    print("Created MANIFEST.csv (header only) and proofs/.")


def cmd_seal_protocol(a):
    raw = read_manifest()
    _, st = check_manifest(raw)
    version = len(st.protocols) + 1
    if a.version != version:
        raise Refused("the next protocol version is %d" % version)
    path = outside_repo(a.file)
    data = path.read_bytes()
    digest = sha256_hex(data)
    if a.existing_proof:
        proof = Path(a.existing_proof).read_bytes()
        if proof_digest(proof) != digest:
            raise Refused("the file no longer matches its earlier proof.\n  file sha256:  %s\n"
                          "  proof sha256: %s\nNothing was written. Do not re-hash; report both."
                          % (digest, proof_digest(proof)))
        if a.time:
            when = a.time
        else:
            mtime = os.path.getmtime(a.existing_proof)
            when = dt.datetime.fromtimestamp(mtime, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            print("utc_time taken from the proof file's modified time: %s "
                  "(pass --time to use the ledger's time instead)" % when)
        if not valid_time(when) or when > utc_now():
            raise Refused("--time must be YYYY-MM-DDTHH:MM:SSZ and not in the future")
    else:
        if a.time:
            raise Refused("--time is only for a proof made earlier; a new stamp uses now")
        proof = stamp_bytes(data)
        when = utc_now()
    if version > 1 and not a.reason:
        raise Refused("protocol-v%d supersedes protocol-v%d: give --reason %s"
                      % (version, version - 1, "|".join(PROTOCOL_REASONS)))
    seq = len(st.rows) + 1
    seal_id = "protocol-v%d" % version
    row = next_row(seq=str(seq), utc_time=when, status="sealed", lane="protocol",
                   seal_id=seal_id, item="protocol", gate="rule:%d" % a.checks,
                   receipt=a.receipt, sha256=digest,
                   ots_proof=proof_path(seq, seal_id, "protocol"))
    if version > 1:
        row.update(supersedes="protocol-v%d" % (version - 1), reason_class=a.reason)
    append([row], {row["ots_proof"]: proof})


def cmd_seal_read(a):
    raw = read_manifest()
    _, st = check_manifest(raw)
    lane = a.lane
    version = st.last_version.get(lane, 0) + 1
    if version > 1 and not a.reason:
        raise Refused("%s-v%d supersedes %s-v%d: give --reason %s"
                      % (lane, version, lane, version - 1, "|".join(LIST_REASONS)))
    k = st.checks_in_force
    if k is None:
        raise Refused("no protocol is sealed yet")
    if a.gate != "%d/%d" % (k, k):
        raise Refused("gate %s: a list is sealed only at %d/%d (every check in protocol-v%d "
                      "passes). Nothing was written." % (a.gate, k, k, st.protocols[-1][0]))
    files = {"list": a.list, "gold-1": a.gold_1, "gold-2": a.gold_2, "incumbent": a.incumbent}
    seq = len(st.rows)
    seal_id = "%s-v%d" % (lane, version)
    when = utc_now()
    rows, proofs, kept = [], {}, []
    for item in LIST_ITEMS:
        path, data = salted(outside_repo(files[item]))
        kept.append((item, path))
        seq += 1
        row = next_row(seq=str(seq), utc_time=when, status="sealed", lane=lane,
                       seal_id=seal_id, item=item, list_size=str(a.list_size),
                       gate=a.gate, receipt=a.receipt, sha256=sha256_hex(data),
                       ots_proof=proof_path(seq, seal_id, item))
        if version > 1:
            row.update(supersedes="%s-v%d" % (lane, version - 1), reason_class=a.reason)
        rows.append(row)
        proofs[row["ots_proof"]] = stamp_bytes(data)
    append(rows, proofs)
    print("KEEP these exact files; the hashes in the record prove them:")
    for item, path in kept:
        print("  %-9s %s" % (item, path))


def cmd_event(a, status):
    raw = read_manifest()
    _, st = check_manifest(raw)
    seal = st.seals.get(a.seal_id)
    if seal is None:
        raise Refused("%s is not a sealed lane list" % a.seal_id)
    row = next_row(seq=str(len(st.rows) + 1), utc_time=utc_now(), status=status,
                   lane=seal["lane"], seal_id=a.seal_id, receipt=a.receipt)
    if status == "withdrawn":
        row["reason_class"] = a.cause
    append([row], {})


def cmd_stamp_manifest(_args):
    raw = read_manifest()
    problems, st = check_manifest(raw)
    if problems:
        raise Refused("the record has problems:\n  " + "\n  ".join(problems))
    if not st.rows:
        raise Refused("no rows to stamp yet")
    path = manifest_proof_path(len(st.rows))
    if path.exists():
        raise Refused("%s already exists" % path.relative_to(ROOT).as_posix())
    proof = stamp_bytes(raw)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "xb") as fh:
        fh.write(proof)
    print("Stamped the manifest through row %d: %s"
          % (len(st.rows), path.relative_to(ROOT).as_posix()))


def cmd_upgrade(_args):
    paths = sorted(PROOFS.glob("*.ots")) + sorted(MANIFEST_PROOFS.glob("*.ots"))
    for path in paths:
        data = path.read_bytes()
        new, anchored = upgrade_proof(data)
        if new is not None:
            if proof_digest(new) != proof_digest(data):
                raise Refused("%s: upgrade changed the proven hash; file left as it was" % path)
            tmp = path.with_name(path.name + ".tmp")
            tmp.write_bytes(new)
            os.replace(str(tmp), str(path))
        print("%s: %s%s" % (path.relative_to(ROOT).as_posix(),
                            "anchored in Bitcoin" if anchored else "still pending",
                            " (upgraded now)" if new is not None else ""))
    print("Then:  python tools/record.py verify --bitcoin  and commit the upgraded proofs.")


# ------------------------------------------------------------------ main

def main(argv=None):
    p = argparse.ArgumentParser(prog="record.py", description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="create MANIFEST.csv (once)")

    s = sub.add_parser("seal-protocol", help="seal one version of the sealing rules")
    s.add_argument("--version", type=int, required=True)
    s.add_argument("--checks", type=int, required=True,
                   help="how many gate checks this version defines")
    s.add_argument("--file", required=True, help="the protocol file (outside this folder)")
    s.add_argument("--receipt", default="-", help="ledger receipt, or - if none")
    s.add_argument("--reason", choices=PROTOCOL_REASONS, help="needed from version 2")
    s.add_argument("--existing-proof", help="an .ots made earlier for this exact file")
    s.add_argument("--time", help="UTC time of that earlier stamp, YYYY-MM-DDTHH:MM:SSZ")

    s = sub.add_parser("seal-read", help="seal one lane read (four files)")
    s.add_argument("--lane", required=True)
    for item in LIST_ITEMS:
        s.add_argument("--" + item, required=True, metavar="FILE")
    s.add_argument("--list-size", type=int, required=True)
    s.add_argument("--gate", required=True, help="checks passed, e.g. 8/8")
    s.add_argument("--receipt", required=True)
    s.add_argument("--reason", choices=LIST_REASONS, help="needed from v2 of a lane")

    s = sub.add_parser("outcome-read", help="record a seal's first outcome read")
    s.add_argument("--seal-id", required=True)
    s.add_argument("--receipt", required=True)

    s = sub.add_parser("withdraw", help="withdraw a seal before its first outcome read")
    s.add_argument("--seal-id", required=True)
    s.add_argument("--cause", choices=WITHDRAW_CAUSES, required=True)
    s.add_argument("--receipt", required=True)

    sub.add_parser("stamp-manifest", help="stamp the manifest as it stands")
    sub.add_parser("upgrade", help="fetch Bitcoin confirmations for every proof")

    s = sub.add_parser("verify", help="check the whole record")
    s.add_argument("--base-ref", help="git commit the record must have grown from")
    s.add_argument("--bitcoin", action="store_true",
                   help="also check each proof against the Bitcoin block it names")

    a = p.parse_args(argv)
    try:
        if a.cmd == "init":
            cmd_init(a)
        elif a.cmd == "seal-protocol":
            cmd_seal_protocol(a)
        elif a.cmd == "seal-read":
            cmd_seal_read(a)
        elif a.cmd == "outcome-read":
            cmd_event(a, "outcome-read")
        elif a.cmd == "withdraw":
            cmd_event(a, "withdrawn")
        elif a.cmd == "stamp-manifest":
            cmd_stamp_manifest(a)
        elif a.cmd == "upgrade":
            cmd_upgrade(a)
        elif a.cmd == "verify":
            return 1 if run_verify(a.base_ref, a.bitcoin) else 0
    except Refused as exc:
        print("REFUSED: %s" % exc)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
