# SwarmUI SMB recovery

1. Correlate the WIP commit, nas-mount log, and SwarmUI LiteDB recovery path.
2. Make cache and pending-delete path indexes case-insensitive while preserving exact server names for SMB wire operations.
3. Add regression tests for mixed-case path resolution and stale lazy-open invalidation/recreation.
4. Run focused tests and a syntax/import check.
5. Remount with debug logging and reproduce against SwarmUI, if local runtime state allows it safely.
6. Capture the live SwarmUI console and identify the first LiteDB failure, not just the recovery cascade.
7. Make pipelined SMB reads refill legal short responses before later in-flight data is appended.
8. Run exact-page live stress checks, then remount for a clean SwarmUI test.
9. Reproduce LiteDB itself on an isolated debug mount and trace cross-handle size/content visibility.
10. Verify 1,500 upserts, WAL checkpoints, concurrent queries, close, and reopen over the isolated SMB mount.
11. Remount production M:/Y:/Z: with the verified cross-handle fixes and perform one final SwarmUI startup audit.
12. Close the first-write publication race found by the real parallel preview rebuild; verify four concurrent LiteDB checkpoint/reopen workloads and a clean rebuild of the quarantined July 6 metadata database in SwarmUI.

Final result: completed. The production mount remained error-free while SwarmUI rebuilt the affected folder's database and WAL, loaded its thumbnails, and completed a post-load soak with no `ReadFull`, `Page type`, corruption, or disposed-database errors.
