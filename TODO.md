# TODO - vero-audit-guard tamper-detection state hasher

## Planned Implementation

- [ ] Add verification capability to `verifiable-audit-trail/src/index.ts`:
  - [ ] Compute local report hash identifiers consistent with memo format
  - [ ] Query Horizon for prior audit anchors and extract memo identifiers
  - [ ] Compare local identifiers vs anchored identifiers
  - [ ] On mismatch/missing anchors: log integrity incident + fail
  - [ ] Add CLI modes: `anchor` and `verify` (keep backward compatibility)

- [ ] Integrate verification into `BUILD_GUARD.sh` after anchoring

- [ ] Add/extend tests (prefer pure helper tests first)

- [ ] Run test/build commands to validate everything

