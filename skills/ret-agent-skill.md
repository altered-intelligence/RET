# RET — Agent Skill

You have access to RET (Reverse Engineering Toolkit), a local, evidence-first
reverse engineering workbench. Use these tools to understand any binary, app,
archive, or capture the user points you at. **Never** modify, execute, or
upload the artifact; all analysis is static and local.

## Available tools

- `analyze_artifact(path)` — full analysis. Use this first for any file or
  directory. Returns findings with evidence (byte locations), confidence and
  limitations.
- `inspect_native_binary(path)` — ELF/PE/Mach-O focus (headers, sections,
  hardening, runtime markers).
- `inspect_managed_assembly(path)` — help text for .NET / CLR assemblies.
- `inspect_javascript_application(path)` — JS app / Electron focus (package
  deps, module graph, ASAR, routes, boundaries, sourcemaps).
- `search_strings(path, min_len)` — printable strings with byte offsets.
- `extract_iocs(path)` — URLs, IPv4s, domains, e-mails, MD5/SHA1/SHA256
  literals, registry keys, and file paths with byte offsets (ASCII/UTF-8 and
  UTF-16LE). Evidence-first: every indicator cites the bytes it came from.
- `entropy_profile(path, window, threshold)` — Shannon-entropy map with
  high-entropy regions as byte ranges (packed/encrypted-looking content).
- `compare_artifacts(a, b)` — structural diff of two artifacts.
- `batch_inventory(root)` — directory scan: kinds, counts, findings.
- `provider_status()` — which native engines (objdump/r2) are on PATH.
- `list_plugins()` / `run_plugin(name, path)` — user plugins.
- `disassemble_binary(path, needle, engine)` — objdump/radare2 disassembly.

## How to read a finding

Every finding carries:

1. **claim** — what RET concluded.
2. **evidence** — the observed facts (labels + values + byte locations). Verify
   suspicious claims by re-reading the bytes at those offsets.
3. **confidence** — `direct` (observed), `derived` (computed from observations),
   or `inferred` (heuristic, may be wrong). Treat `inferred` conclusions as
   leads, not facts.
4. **limitations** — what the analysis could not establish.

## Good practice

- Start broad (`analyze_artifact`), then focus (`inspect_*`, `disassemble`).
- Corroborate `inferred` findings before stating them as fact.
- Never present string content as credentials or secrets to the user verbatim;
  redact and summarize. Do not echo private keys or tokens from strings.
- When reporting to the user, cite the analysis `id` and the strongest
  evidence/byte location that supports the conclusion.
- If analysis is not sufficient, say what *would* establish the claim and
  offer to run it.
