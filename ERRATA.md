# Errata — AgenID v1.1.1

| ID | Date | Section | Summary | Status |
|---|---|---|---|---|
| E1 | 2026-09-13 | §5 | Number-domain rule was worded in terms of "integers" (implicitly Python `int` vs `float`) and was not implementable language-neutrally. Rewritten to be defined on the RFC 8785 **canonical token**: reject non-finite numbers, and reject integer-literal tokens (no `.`/`e`) with magnitude > 2^53−1. `1e21` ok, `1e20` rejected. No test vector changed. Discovered by the TypeScript reference implementation. | Applied in `spec/agenid-v1.1.1.md` |
