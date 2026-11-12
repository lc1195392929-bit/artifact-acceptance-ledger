# Verification record

2026-11-12, local Linux/Python 3.12.14. Tests use synthetic temporary files only.

Executed: `python -m unittest discover -s tests -v`: **38 tests passed**.

Covered: initial current record; artifact/evidence/spec/checker changes; missing requirements; duplicate IDs/JSON keys; all result states; missing/empty evidence; missing files; traversal/absolute/Windows paths; symlink file/directory; directories/FIFO; size boundary; malformed JSON; invalid digest/timestamp/control character; nested file paths; CLI snapshot and verify exit codes.

Not verified: Windows (unsupported), macOS, real Word/WPS or PPT files, semantic correctness of documents or evidence, malicious concurrent filesystem mutation, public CI, signed attestations, high-volume performance, integration with an existing product. The tests prove only the listed behaviors on the local environment; they do not establish production readiness.

Post-review fixes: oversized integer JSON now returns structured invalid_input/exit 2; added a 256 MiB operation read budget and per-path digest cache, plus root-symlink and JSON-size regressions. Final 38-test run and py_compile passed.
