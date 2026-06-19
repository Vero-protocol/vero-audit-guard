# Proposal State Machine - Design Documentation

## Overview

This document defines the finite state machine (FSM) for governance proposals in `vero-core-engine`. The FSM prevents invalid state transitions that could lead to bugs such as double-execution, approval after execution, or execution without proper thresholds.

## State Definitions

```rust
pub enum ProposalState {
    Pending  = 0,   // Awaiting approvals (default at creation)
    Approved = 1,   // Threshold met; time-lock window active
    Executed = 2,   // Executed; terminal state
}
```

### Pending
- **When**: Immediately after proposal creation via `governance::propose()`
- **Duration**: Until `approve()` is called enough times to reach threshold
- **Allowed Operations**: 
  - `approve()` — receives another signer's approval
  - Query — check approval count and state
- **Blocked Operations**: 
  - `execute()` — panics with `InvalidStateTransition`
  - `approve()` on already-approved signer — panics with `AlreadyApproved`

### Approved
- **When**: When `approve()` causes `approved_by.len()` to reach or exceed `threshold`
- **Automatic Transition**: Triggered in `governance::approve()` immediately upon threshold
- **Events Emitted**: `(symbol_short!("GOV"), symbol_short!("approved"))` with proposal ID
- **Duration**: From threshold met until time-lock expiry + `execute()` call
- **Allowed Operations**:
  - `execute()` — executes proposal if time-lock has expired
  - Query — check time-lock expiry and execution window
- **Blocked Operations**:
  - `approve()` — panics with `InvalidStateTransition`
  - `execute()` (if timelock active) — panics with `TimelockActive`

### Executed
- **When**: `governance::execute()` completes successfully
- **Transition**: Automatic at end of `execute()` function
- **Events Emitted**: `(symbol_short!("GOV"), symbol_short!("execute"))` with proposal ID
- **Duration**: Permanent (terminal state)
- **Allowed Operations**: 
  - Query — check execution history and proposal details
- **Blocked Operations**:
  - `approve()` — panics with `InvalidStateTransition`
  - `execute()` — panics with `InvalidStateTransition`

## State Transition Diagram

```
       ┌─────────────────────────────────────────┐
       │                                         │
       ▼                                         │
    ┌─────────┐                                  │
    │ Pending │                                  │
    └────┬────┘                                  │
         │                                       │
         │ approve() with                        │
         │ approved_by.len() >= threshold        │
         │                                       │
         ▼                                       │
    ┌──────────┐                                 │
    │ Approved │                                 │
    └────┬─────┘                                 │
         │                                       │
         │ execute() with                        │
         │ ledger >= unlock_ledger               │
         │                                       │
         ▼                                       │
    ┌──────────┐                                 │
    │ Executed │ ════════════════════════════════│
    └──────────┘                                 (invalid transitions)
```

## Transition Rules

### Valid Transitions

| Transition | Trigger | Condition | Side Effects |
|---|---|---|---|
| **Pending → Approved** | `approve()` called | `approved_by.len() >= threshold` AND current state is Pending | Emit `"GOV/approved"` event; unlock_ledger already set |
| **Approved → Executed** | `execute()` called | `state == Approved` AND `ledger >= unlock_ledger` | Emit `"GOV/execute"` event; state becomes terminal |

### Invalid Transitions (All Panic with `InvalidStateTransition`)

| Attempted Transition | Trigger | Why Blocked |
|---|---|---|
| **Pending → Executed** | `execute()` called | Skips approval threshold validation |
| **Approved → Pending** | (no operation) | Backwards transition not allowed |
| **Approved → Approved** | `approve()` called | Cannot approve already-approved proposals |
| **Executed → Approved** | (no operation) | Backwards transition not allowed |
| **Executed → Executed** | `execute()` called | Double-execution protection |
| **Executed → Pending** | (no operation) | Backwards transition not allowed |

## Implementation Details

### Code: Pending State Initialization

**File**: `engine-core/src/governance.rs::propose()`

```rust
pub fn propose(env: &Env, mut proposal: Proposal) -> u64 {
    // ... validation ...
    proposal.state = ProposalState::Pending;  // ← Initialize state
    // ... storage ...
}
```

### Code: Pending → Approved Transition

**File**: `engine-core/src/governance.rs::approve()`

```rust
pub fn approve(env: &Env, signer: &Address, proposal_id: u64) {
    // ... auth and signer validation ...
    
    let (mut prop, unlock) = props.get(proposal_id).unwrap_or_else(|| {
        panic_with_error!(env, GovError::ProposalNotFound)
    });
    
    // GUARD: Only pending proposals can receive approvals
    if prop.state != ProposalState::Pending {
        panic_with_error!(env, GovError::InvalidStateTransition);
    }
    
    if prop.approved_by.contains(signer) {
        panic_with_error!(env, GovError::AlreadyApproved);
    }
    
    prop.approved_by.push_back(signer.clone());
    
    // AUTO-TRANSITION: When threshold is met
    if (prop.approved_by.len() as u32) >= threshold {
        prop.state = ProposalState::Approved;
        env.events().publish(
            (symbol_short!("GOV"), symbol_short!("approved")),
            proposal_id,
        );
    }
    
    props.set(proposal_id, (prop, unlock));
    env.storage().instance().set(&KEY_PROPOSALS, &props);
}
```

### Code: Approved → Executed Transition

**File**: `engine-core/src/governance.rs::execute()`

```rust
pub fn execute(env: &Env, proposal_id: u64) -> Proposal {
    let mut props = load_proposals(env);
    let (mut prop, unlock) = props.get(proposal_id).unwrap_or_else(|| {
        panic_with_error!(env, GovError::ProposalNotFound)
    });
    
    // GUARD: Only approved proposals can be executed
    if prop.state != ProposalState::Approved {
        panic_with_error!(env, GovError::InvalidStateTransition);
    }
    
    if env.ledger().sequence() < unlock {
        panic_with_error!(env, GovError::TimelockActive);
    }
    
    // AUTO-TRANSITION: To Executed
    prop.state = ProposalState::Executed;
    props.set(proposal_id, (prop.clone(), unlock));
    env.storage().instance().set(&KEY_PROPOSALS, &props);
    env.events().publish(
        (symbol_short!("GOV"), symbol_short!("execute")),
        proposal_id,
    );
    prop
}
```

## Error Codes

### Updated Error Enum: `GovError`

```rust
pub enum GovError {
    NotASigner            = 1,  // Signer not in governance set
    AlreadyApproved       = 2,  // Signer already approved this proposal
    ThresholdNotMet       = 3,  // [DEPRECATED - now checked via state]
    TimelockActive        = 4,  // Proposal not yet executable (timelock)
    InvalidStateTransition = 5,  // NEW: Guard against invalid state changes
    ProposalNotFound      = 6,  // Proposal ID doesn't exist
}
```

## Acceptance Criteria

✅ **AC1: Valid states only**
- Proposals can only exist in one of three states: Pending, Approved, or Executed
- Verified by: `ProposalState` enum definition and state validation guards

✅ **AC2: State transitions enforced**
- Pending → Approved: Only when threshold met during `approve()`
- Approved → Executed: Only when timelock expired during `execute()`
- All other transitions rejected with `InvalidStateTransition` panic
- Verified by: State checks at entry of `approve()` and `execute()`

✅ **AC3: FSM verified**
- State transition matrix documented (see above)
- No backwards transitions possible
- No invalid paths through FSM
- Terminal state (Executed) prevents all further transitions
- Verified by: Comprehensive guard clauses in governance module

## Testing Strategy

The FSM validation must be tested with:

1. **Happy Path**: Pending → Approved → Executed
   - Create proposal (state = Pending)
   - Receive approvals until threshold (state = Pending)
   - Receive final approval (state → Approved)
   - Wait for timelock
   - Execute (state → Executed)

2. **Invalid Transition Tests**: Each blocked transition must panic
   - Attempting `execute()` on Pending proposal
   - Attempting `approve()` on Approved proposal
   - Attempting `execute()` on Executed proposal
   - Etc.

3. **Edge Cases**:
   - Exactly threshold approvals trigger transition
   - Timelock active blocks execution even if approved
   - Duplicate approval detection still works

## Security Implications

This FSM provides **defense in depth** against:

1. **Double-Execution Bugs**: State guard prevents executing Executed proposals
2. **Approval-After-Execution**: State guard prevents approving Executed proposals
3. **Premature Execution**: State guard prevents executing Pending proposals
4. **Time-Lock Bypass**: Separate `TimelockActive` check ensures lock isn't bypassed
5. **Race Conditions**: State transitions are atomic within Soroban contract invocation

## Future Extensions

This FSM can be extended to support additional states such as:
- **Cancelled**: For vetoed or withdrawn proposals
- **Expired**: For proposals that hit a maximum age without execution
- **Failed**: For proposals that failed during execution

Such extensions would maintain FSM validity by defining new allowed transitions.

---

**Document Version**: 1.0  
**Last Updated**: 2026-06-19  
**Status**: Implemented and Verified
