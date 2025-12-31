# Java/Kotlin Invariants (v1)
- Avoid insecure deserialization or enforce allowlists/filters.
- SQL must use prepared statements; no concat queries.
- Validate uploads; prevent path traversal.
- SSRF protections for URL fetchers.
- Crypto: avoid ECB; avoid MD5/SHA1 for security; prefer modern libraries.
