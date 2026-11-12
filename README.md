# Artifact Acceptance Ledger

A small, offline Python CLI for a common handoff failure: **a review passed, then the delivered file changed**.

把验收要求、文件版本和检查证据联系起来。文件或要求改变后，旧检查不能继续显示为当前通过。

## What it does

- Snapshots SHA-256 hashes for artifacts and local evidence files.
- Keeps requirement ID, criterion, checker/version, manual/automated method and caller-supplied result together.
- Detects changed requirements, artifact bytes or evidence bytes.
- Keeps `pending`, `blocked` and `fail` separate from current recorded passes.
- Runs locally using only the Python standard library. No upload, telemetry, LLM, command execution or document parsing.

**Important:** a `pass` is supplied by you or your separate checker. This program does not inspect whether a paper is good, whether a requirement is satisfied, or whether evidence tells the truth. `all_recorded_passes_current` means only that all supplied pass records still match the files and specification. It is NOT a signed attestation, authenticity guarantee, safety certification, or semantic acceptance.

## Requirements

Python 3.10+ on a POSIX platform with `dir_fd`, `O_NOFOLLOW` and `O_DIRECTORY` (tested on Linux/Python 3.12.14 only). Windows is not supported by this prototype: it fails closed rather than using weaker path checks. macOS is not tested.

## Quick start

From this repository:

```sh
python ledger.py snapshot --root examples --spec spec.json > examples/ledger.json
python ledger.py verify --root examples --spec spec.json --ledger ledger.json
```

Change `examples/artifact.txt` and run verify again. It reports stale evidence and exits with code 1. Restore the original bytes to match the original snapshot, or perform a new review and generate a new snapshot after updating the evidence and spec.

Use a fresh output filename for snapshots. **Never redirect output over the spec, artifact or evidence input**: your shell would truncate the input before Python runs. The CLI itself writes only JSON to stdout and never modifies the inspected files.

For your own files, create a trusted project directory with a spec like:

```json
{
  "version": 1,
  "requirements": [{
    "id": "REQ-1",
    "criterion": "The opening section has been reviewed for readability",
    "artifact": "deliverables/script.docx",
    "evidence": "reviews/REQ-1.txt",
    "method": "manual",
    "status": "pass",
    "checker": "editorial-review",
    "checker_version": "rubric-1"
  }]
}
```

Allowed methods: `manual`, `automated`. Allowed statuses: `pass`, `fail`, `pending`, `blocked`. `pass` and `fail` require a nonempty evidence file. For unperformed work use `pending` or `blocked` and `evidence: null`. A checker name is metadata only; this tool never runs it.

All filenames are normalized POSIX-style relative paths under `--root`. Duplicate requirement IDs and unknown fields are errors. SHA-256 fingerprints cover bytes, not visual layout, permissions or external hyperlinks. Use saved screenshots/review reports as evidence when appropriate; verify their quality yourself.

### Exit codes

- `0`: snapshot created, or all recorded passes match current inputs.
- `1`: verification completed, but some requirements are missing, changed, failed, pending, blocked or unsafe/unreadable.
- `2`: invalid input or unsupported environment.

### Privacy and threat model

The tool rejects path traversal, absolute paths, Windows drive paths, symbolic links in project-relative paths, and non-regular files. Descriptor-relative traversal limits symlink races. The selected root and its ancestor directories must be trusted. Do not run it against a directory concurrently controlled by an attacker. File mutation checks are best-effort; snapshots are not atomic across multiple files.

Each input JSON is limited to 1 MiB, artifacts/evidence to 64 MiB per file, and a specification to 500 requirements. Per-operation file reads are capped at 256 MiB; repeated paths reuse the first digest. Snapshots represent first reads, not a synchronized filesystem view. Files are read, not executed. Evidence content and artifact content are not copied into JSON output, but paths, criteria, reviewer labels and hashes can still reveal sensitive information. Keep real ledgers private unless reviewed for sharing. Examples and tests here are synthetic.

Re-snapshotting old evidence does not rerun a review; you must genuinely recheck it yourself. Both the ledger and spec are unsigned and editable. Someone who can change them can forge a claim. For authenticated build provenance use in-toto, Sigstore or GitHub artifact attestations instead. This tool detects stale self-reported records in a trusted local workflow; it does not solve hostile evidence forgery.

## Tests

```sh
python -m unittest discover -s tests -v
python -m py_compile ledger.py
```

See [TESTING.md](TESTING.md) for what was and was not tested. See [RESEARCH.md](RESEARCH.md) for adjacent work and scope. License: MIT. This is a prototype, not a reviewed compliance product.
