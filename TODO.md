# TODO - vero-audit-guard tamper-detection state hasher

## Planned Implementation

- [x] Add verification capability to `verifiable-audit-trail/src/index.ts`:
  - [x] Compute local report hash identifiers consistent with memo format
  - [x] Query Horizon for a specific prior audit anchor and extract its memo hash
  - [x] Compare local identifiers vs anchored identifiers
  - [x] On mismatch/missing anchors: log integrity incident + fail
  - [x] Add CLI modes: `anchor` and `verify` (keep backward compatibility)

- [ ] Integrate verification into `BUILD_GUARD.sh` after anchoring

- [x] Add/extend tests (prefer pure helper tests first)

- [x] Run test/build commands to validate everything

