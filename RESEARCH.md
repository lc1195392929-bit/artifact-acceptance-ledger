# Scope and related work (2026-11-12)

This is an independently written small prototype, not a claim to invent requirements traceability or artifact hashes. No third-party code was copied and no runtime packages are bundled.

Primary sources reviewed:

- [Doorstop](https://github.com/doorstop-dev/doorstop): requirements management using version control. It covers a larger requirements lifecycle; this prototype is a focused file/evidence freshness check.
- [in-toto attestation specification](https://github.com/in-toto/attestation): binds artifact subjects to authenticated metadata. This prototype does **not** implement that specification or authentication.
- [GitHub artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations): signed software-build provenance. Even provenance is not proof of artifact security; similarly, matching a review hash is not proof that a requirement is actually satisfied.

Earlier research of Cloudflare security-audit-skill suggested distinguishing verified, uncertain and rejected claims and bounding inputs. This implementation borrows the general discipline, not its source code or schema.

Practical intended niche: editors and agent-assisted workflows that hand over opaque documents or slide decks, then accidentally reuse an old review after a file change. Existing mature tools may be a better choice for regulated or adversarial workflows. The comparison is a limited research pass, not an exhaustive market survey, and no global novelty is claimed.
