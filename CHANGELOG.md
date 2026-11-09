# Changelog

All notable changes to RET are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] — 2026-11-08

### Added
- **`ret iocs <path>`** — indicator-of-compromise extraction with byte-level
  provenance: URLs, IPv4 addresses, domain-looking labels, e-mail addresses,
  MD5/SHA1/SHA256 literals, Windows registry keys, and file paths. Scans
  ASCII/UTF-8 strings *and* UTF-16LE (where Windows malware stores most of
  its strings). Every indicator cites the byte range it was found at;
  heuristic kinds (domains, IPv4s) are marked `inferred` with their
  limitations stated in the finding. `--record` appends to the case file.
- **`ret entropy <path>`** — Shannon-entropy profiling: overall entropy plus
  a windowed entropy map with contiguous high-entropy regions reported as
  byte ranges (`--window N`, default 4096; `--threshold`, default 7.0
  bits/byte). Findings state what high entropy does and does not imply.
- **PE imphash** — a `pe.imphash` finding and fact (pefile-compatible: MD5
  over the lowercased import table, ordinals normalized to `ordN`), wired
  into analyze/inspect output, case files, and structural digests.
- **SARIF 2.1.0 export** — `ret report --out sarif` renders the whole case
  as SARIF with RET's evidence, confidence, and limitations preserved under
  each result's `properties`, so findings flow into GitHub code scanning,
  IDEs, and CI gates without losing provenance.
- **Two new MCP tools** — `extract_iocs` and `entropy_profile` (13 tools
  total), exposed via `tools/list` and documented in the generated agent
  skill.

### Changed
- **Dashboard API is same-origin only (security fix).** v0.1.0 answered with
  `Access-Control-Allow-Origin: *`, which let any web page the user browses
  drive the local API and read case data. The wildcard is removed:
  same-origin dashboard fetches need no CORS header, non-browser callers
  (curl, scripts, agents) are unaffected, and cross-origin browser requests
  get `403`.

### Notes
- New dependency: `md-5` (RustCrypto) for imphash.
- Structural digests change for PE artifacts: the new `pe.imphash` fact joins
  the digest, so recorded 0.1.x snapshots will show a metadata diff on
  compare. That is expected and desirable — imphash is build-stable.
