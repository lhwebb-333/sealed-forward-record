# Sealed forward record

A public, append-only record of forward lists, each fixed before its outcomes exist.

Every row in `MANIFEST.csv` is the SHA-256 fingerprint of one sealed file, stamped with [OpenTimestamps](https://opentimestamps.org), which anchors it in the Bitcoin blockchain. The files themselves are not here. Nobody, including us, can change, drop, insert or backdate a row without the check below failing in public.

## What is here, and what never is

Here:

1. `MANIFEST.csv`: one row per event (a seal, a first outcome read, a withdrawal).
2. `proofs/`: one OpenTimestamps proof per sealed file, and in `proofs/manifest/` a proof of the whole manifest after each write.
3. `tools/record.py`: writes rows and checks the whole record.
4. `.github/workflows/verify.yml`: runs that check on every change and once a day.

Never here: the lists, any person's or company's name, methods, scores, or the text of the sealing rules. The rules are sealed too: their fingerprint is row 1, so any text later shown to a reviewer can be checked against it.

## How a seal works

1. A list is sealed only when it passes every check in the sealing rules in force. The `gate` column shows it, for example `8/8`. A list that fails any check is not sealed.
2. Every list is sealed with three comparison lists, made the same day at the same size: the two strongest comparison methods (`gold-1`, `gold-2`) and the method in use today (`incumbent`). A list is judged against them, never alone.
3. Every list file starts with a random salt line, so its fingerprint cannot be matched by guessing the list.
4. When a list's outcomes are first read, an `outcome-read` row records it. Every sealed list is scored, including superseded ones. Scores are published separately, never in this record.
5. A newer version names the version it supersedes and the reason. Older versions stay and keep being scored.
6. A seal can be withdrawn only before its first outcome read, with its cause. The withdrawal is a new row; the seal stays.
7. A list that names people is never published. An independent reviewer, under confidentiality, checks it against its fingerprint and publishes only the aggregate result.

## Check it yourself

With the tool (Python 3.8 or later):

```
python -m pip install opentimestamps
python tools/record.py verify --bitcoin
```

By hand, with standard tools (`sha256sum` on Linux, `shasum -a 256` on macOS, `certutil -hashfile <file> SHA256` on Windows):

1. **The chain.** The last column of the row with `seq` = s is the SHA-256 of the first s lines of `MANIFEST.csv` (the header and every row above it):
   `head -n s MANIFEST.csv | sha256sum`
2. **A sealed file's proof.** `ots info proofs/<proof>.ots` prints "File sha256 hash", which must equal that row's `sha256`. `ots verify -d <sha256> proofs/<proof>.ots` checks it against Bitcoin (the `ots` client needs a Bitcoin node for this step; `record.py verify --bitcoin` uses public block explorers instead).
3. **The whole manifest.** `proofs/manifest/through-row-N.ots` stamps the first N+1 lines (the header and rows 1 to N): `head -n $((N+1)) MANIFEST.csv | sha256sum` must equal the hash `ots info` prints for that proof.
4. **A sealed file, if you hold it** (a reviewer): its SHA-256 must equal its row's `sha256`.

## The manifest

| Column | Meaning |
|---|---|
| `seq` | Row number, 1, 2, 3 ... with no gaps |
| `utc_time` | When the row was written, by our clock (UTC) |
| `status` | `sealed`, `outcome-read` or `withdrawn` |
| `lane` | The field the list covers; `protocol` for the sealing rules |
| `seal_id` | `<lane>-v<N>`, one per version |
| `item` | `protocol`, `list`, `gold-1`, `gold-2` or `incumbent` |
| `list_size` | Entries in the list; the same for all four files of a seal |
| `supersedes` | The version this one replaces, or `-` |
| `reason_class` | Why a version replaces the last (`tools-added`, `data-corrected`, `window-changed`, `defect-fixed`, `unit-changed`; `rule-added` for the rules), or the cause of a withdrawal (`data-error`, `testing-error`, `tools-not-applied`, `instrument`, `hardware`) |
| `gate` | Checks passed, for example `8/8`; on a rules row, `rule:N` is how many checks that version defines |
| `receipt` | Our internal ledger receipt for the read |
| `sha256` | Fingerprint of the sealed file |
| `ots_proof` | Path of its OpenTimestamps proof |
| `prev_manifest_sha256` | SHA-256 of every byte of the manifest above this row |

`-` means the column does not apply to that row.

## Times

`utc_time` is our clock. The proof is the Bitcoin block: it shows the file existed no later than that block's time. A new proof stays pending until a block confirms it, usually within a few hours, and is then upgraded in a later commit. A proof file changes only by gaining that confirmation; the fingerprint it proves never changes, and the check fails if it does.

## Licence

MIT, see `LICENSE`. It covers the tool and these documents.
