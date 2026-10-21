# Changelog

All notable changes to TRACE are documented here.  The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [1.1.0] - 2026-10-21

### Added
- **Live demo** (`live/`, published at https://anwardebes.github.io/trace/): the
  content guard, the five temporal monitors, the adapters and the certificate
  ledger ported to JavaScript, around five scripted agent sessions in three
  providers' wire formats, with a per-call comparison on every step.
- Tamper mode: edit any logged field of a sealed session and the independent
  verifier fails at that entry.
- The browser writes the exact ledger format of `tracekit` (canonical JSON,
  SHA-256 chain, HMAC-SHA256, Merkle root). CI checks that its ledgers pass
  `verify_ledger` in Python, along with Node tests for monitor semantics.

## [1.0.0] - 2026-06-24

First public release accompanying the paper.

### Added
- **Content guard**: an interpretable Tsetlin-Machine detector for unsafe text
  (prompt injection / jailbreak), built on the Echo-Trace automaton substrate
  from THGTM, with per-decision clause extraction and CNF audit hooks.
- **Behaviour guard**: online, bounded-memory monitors for finite-trace
  temporal safety policies (`Always`, `Never`, `BoundedCount`, `Response`,
  `Precedence`), each with memory constant in the trajectory length.
- **Policy language**: a small declarative DSL compiling to the monitors and
  serialising to JSON for embedding in certificates.
- **Certificate ledger**: a tamper-evident, hash-chained, HMAC-signed, Merkle-
  rooted audit log with model-free independent verification and tamper
  localisation.
- **Model-agnostic adapters**: normalise OpenAI / DeepSeek / Anthropic tool
  calls into policy events.
- **TRACE engine**: a drop-in wrapper running both guards and sealing a session
  certificate, in `monitor` or `enforce` mode.
- Six reproducible experiments on two real Apache-2.0 datasets plus synthetic
  trajectory benchmarks; 40 unit tests; figure-generation script; LaTeX paper.

### Fixed (pre-release audit)
A systematic pre-release correctness audit found and corrected several
defects; all reported numbers were regenerated from the corrected code.
- **Content guard**: the Tsetlin-Machine feedback rule now uses the single
  canonical per-example feedback probability for clauses of both polarities
  (Granmo, 2018); the previous build applied a sign-flipped probability to
  negative-polarity clauses. Corrected results: prompt-injection F1
  0.827 ± 0.036 (was 0.836), jailbreak F1 0.967 ± 0.005 (was 0.920).
- **Behaviour guard**: `Response(t, r, d)` now enforces the inclusive
  finite-trace window `F_{<=d}` (delays 0..d, `deadline = 0` satisfiable),
  matching `G(t -> F_{<=d} r)`; the previous build was off by one and could not
  express a same-step obligation.
- **Adapters**: external-recipient detection now evaluates list-valued
  recipients element-wise (one external address can no longer be masked by an
  internal one) and treats a null recipient like an empty string.
- **Experiments / docs**: corrected the Mann-Whitney degeneracy guard for
  zero-variance pairs; isolated the forged-signature check to the per-entry
  HMAC; split tamper localisation into entry-level vs structural; declared the
  `scipy` dependency; fixed the seed count and KiB unit labels.

### Known limitations (v1.0)
- Token-presence booleanisation is brittle to surface obfuscation (quantified in
  the robustness experiment).
- Trajectory benchmark is synthetic, grounded in published attack taxonomies but
  not yet validated on a live agent harness (e.g. AgentDojo).
- The ledger provides tamper-evidence and symmetric (HMAC) authentication;
  non-repudiation requires the asymmetric-signature upgrade discussed in the
  paper.

[1.0.0]: https://github.com/AnwarDebes/TRACE/releases/tag/v1.0.0
