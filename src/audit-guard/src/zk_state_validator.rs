//! ZK-based state validation hooks.
//!
//! Provides a lightweight verification hook for protocol state transitions.
//! Each transition is described by a `StateTransitionProof` binding a
//! pre-state root and post-state root to a proof commitment and a
//! single-use nullifier, mirroring the shape of a ZK-SNARK state-transition
//! proof (commitment + nullifier) without depending on an external proving
//! system. The hook is intended to be invoked at protocol state-transition
//! boundaries (e.g. before/after a scan or relay step) to catch malformed
//! proofs, forged commitments, and nullifier replay before a state change
//! is accepted.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum ZkStateError {
    #[error("state root cannot be empty")]
    EmptyStateRoot,

    #[error("state root must be a 64-character hex-encoded SHA-256 digest, got {0} characters")]
    InvalidStateRootLength(usize),

    #[error("state root contains non-hexadecimal characters: {0}")]
    InvalidStateRootEncoding(String),

    #[error("proof commitment cannot be empty")]
    EmptyProofCommitment,

    #[error("nullifier cannot be empty")]
    EmptyNullifier,

    #[error("nullifier {0} has already been consumed; possible replay attack")]
    NullifierReplay(String),

    #[error("proof commitment does not match the expected pre/post state binding")]
    ProofCommitmentMismatch,

    #[error("state transition is a no-op: pre-state root and post-state root are identical")]
    NoOpTransition,
}

/// A single ZK-style state transition proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransitionProof {
    pub pre_state_root: String,
    pub post_state_root: String,
    pub proof_commitment: String,
    pub nullifier: String,
}

fn validate_state_root(value: &str) -> Result<(), ZkStateError> {
    if value.trim().is_empty() {
        return Err(ZkStateError::EmptyStateRoot);
    }
    if value.len() != 64 {
        return Err(ZkStateError::InvalidStateRootLength(value.len()));
    }
    if !value.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ZkStateError::InvalidStateRootEncoding(value.to_string()));
    }
    Ok(())
}

/// Derives the expected proof commitment binding a pre-state root,
/// post-state root, and nullifier together.
pub fn compute_commitment(pre_state_root: &str, post_state_root: &str, nullifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(pre_state_root.as_bytes());
    hasher.update(post_state_root.as_bytes());
    hasher.update(nullifier.as_bytes());
    hex::encode(hasher.finalize())
}

impl StateTransitionProof {
    /// Builds a proof, deriving the commitment from the supplied roots and nullifier.
    pub fn new(pre_state_root: impl Into<String>, post_state_root: impl Into<String>, nullifier: impl Into<String>) -> Self {
        let pre_state_root = pre_state_root.into();
        let post_state_root = post_state_root.into();
        let nullifier = nullifier.into();
        let proof_commitment = compute_commitment(&pre_state_root, &post_state_root, &nullifier);
        Self {
            pre_state_root,
            post_state_root,
            proof_commitment,
            nullifier,
        }
    }

    /// Validates the structural well-formedness of the proof, independent of
    /// nullifier replay state (which requires a `ZkStateValidationHook`).
    pub fn validate_structure(&self) -> Result<(), ZkStateError> {
        validate_state_root(&self.pre_state_root)?;
        validate_state_root(&self.post_state_root)?;

        if self.proof_commitment.trim().is_empty() {
            return Err(ZkStateError::EmptyProofCommitment);
        }
        if self.nullifier.trim().is_empty() {
            return Err(ZkStateError::EmptyNullifier);
        }
        if self.pre_state_root == self.post_state_root {
            return Err(ZkStateError::NoOpTransition);
        }

        Ok(())
    }
}

/// A stateful hook that verifies ZK-style state transition proofs and
/// guards against nullifier replay across the lifetime of the hook.
pub struct ZkStateValidationHook {
    consumed_nullifiers: HashSet<String>,
}

impl ZkStateValidationHook {
    pub fn new() -> Self {
        Self {
            consumed_nullifiers: HashSet::new(),
        }
    }

    /// Verifies a state transition proof end-to-end:
    /// structural validity, commitment binding, and nullifier freshness.
    /// On success, the nullifier is consumed and cannot be reused.
    pub fn verify_transition(&mut self, proof: &StateTransitionProof) -> Result<(), ZkStateError> {
        proof.validate_structure()?;

        if self.consumed_nullifiers.contains(&proof.nullifier) {
            return Err(ZkStateError::NullifierReplay(proof.nullifier.clone()));
        }

        let expected_commitment =
            compute_commitment(&proof.pre_state_root, &proof.post_state_root, &proof.nullifier);
        if expected_commitment != proof.proof_commitment {
            return Err(ZkStateError::ProofCommitmentMismatch);
        }

        self.consumed_nullifiers.insert(proof.nullifier.clone());
        Ok(())
    }

    /// Number of nullifiers consumed so far by this hook instance.
    pub fn consumed_count(&self) -> usize {
        self.consumed_nullifiers.len()
    }
}

impl Default for ZkStateValidationHook {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(byte: char) -> String {
        byte.to_string().repeat(64)
    }

    #[test]
    fn valid_transition_is_accepted_and_consumes_nullifier() {
        let mut hook = ZkStateValidationHook::new();
        let proof = StateTransitionProof::new(root('a'), root('b'), "nullifier-1");

        assert!(hook.verify_transition(&proof).is_ok());
        assert_eq!(hook.consumed_count(), 1);
    }

    #[test]
    fn rejects_empty_pre_state_root() {
        let mut proof = StateTransitionProof::new(root('a'), root('b'), "nullifier-2");
        proof.pre_state_root = "".to_string();

        assert_eq!(proof.validate_structure(), Err(ZkStateError::EmptyStateRoot));
    }

    #[test]
    fn rejects_state_root_with_wrong_length() {
        let mut proof = StateTransitionProof::new(root('a'), root('b'), "nullifier-3");
        proof.post_state_root = "abc123".to_string();

        assert_eq!(
            proof.validate_structure(),
            Err(ZkStateError::InvalidStateRootLength(6))
        );
    }

    #[test]
    fn rejects_state_root_with_non_hex_characters() {
        let mut proof = StateTransitionProof::new(root('a'), root('b'), "nullifier-4");
        proof.pre_state_root = "z".repeat(64);

        assert!(matches!(
            proof.validate_structure(),
            Err(ZkStateError::InvalidStateRootEncoding(_))
        ));
    }

    #[test]
    fn rejects_empty_proof_commitment() {
        let mut proof = StateTransitionProof::new(root('a'), root('b'), "nullifier-5");
        proof.proof_commitment = "".to_string();

        assert_eq!(
            proof.validate_structure(),
            Err(ZkStateError::EmptyProofCommitment)
        );
    }

    #[test]
    fn rejects_empty_nullifier() {
        let mut proof = StateTransitionProof::new(root('a'), root('b'), "nullifier-6");
        proof.nullifier = "".to_string();

        assert_eq!(proof.validate_structure(), Err(ZkStateError::EmptyNullifier));
    }

    #[test]
    fn rejects_no_op_transition_where_roots_are_identical() {
        let proof = StateTransitionProof::new(root('a'), root('a'), "nullifier-7");

        assert_eq!(proof.validate_structure(), Err(ZkStateError::NoOpTransition));
    }

    #[test]
    fn rejects_tampered_proof_commitment() {
        let mut hook = ZkStateValidationHook::new();
        let mut proof = StateTransitionProof::new(root('a'), root('b'), "nullifier-8");
        proof.proof_commitment = root('0');

        assert_eq!(
            hook.verify_transition(&proof),
            Err(ZkStateError::ProofCommitmentMismatch)
        );
    }

    #[test]
    fn rejects_replayed_nullifier() {
        let mut hook = ZkStateValidationHook::new();
        let proof = StateTransitionProof::new(root('a'), root('b'), "nullifier-9");

        assert!(hook.verify_transition(&proof).is_ok());
        assert_eq!(
            hook.verify_transition(&proof),
            Err(ZkStateError::NullifierReplay("nullifier-9".to_string()))
        );
    }

    #[test]
    fn distinct_nullifiers_do_not_collide() {
        let mut hook = ZkStateValidationHook::new();
        let first = StateTransitionProof::new(root('a'), root('b'), "nullifier-10");
        let second = StateTransitionProof::new(root('b'), root('c'), "nullifier-11");

        assert!(hook.verify_transition(&first).is_ok());
        assert!(hook.verify_transition(&second).is_ok());
        assert_eq!(hook.consumed_count(), 2);
    }

    #[test]
    fn compute_commitment_is_deterministic_and_binds_all_inputs() {
        let a = compute_commitment(&root('a'), &root('b'), "n");
        let b = compute_commitment(&root('a'), &root('b'), "n");
        let c = compute_commitment(&root('a'), &root('c'), "n");

        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
