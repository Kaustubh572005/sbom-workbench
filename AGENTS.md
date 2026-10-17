# Architecture rules

- Keep external advisory data in the intelligence namespace and resolve scores centrally through the NIST scoring module so all pages agree without changing uploaded records.
- Preserve managed backend connection files and current secured dependency versions when merging uploaded source archives to retain project identity and compatibility.
- Keep threat enrichment independently testable through its plain enrichment function, with the existing server-function wrapper providing app transport.
- Run pure intelligence regression tests with Bun’s built-in test runner so no additional runtime dependencies are required.
