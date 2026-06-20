use crate::types::Proposal;
use soroban_sdk::{contract, contractimpl, Address, Env, BytesN, Symbol, Vec};

#[contract]
pub struct Governance;

#[contractimpl]
impl Governance {
    pub fn propose(
        env: Env,
        proposer: Address,
        action_hash: BytesN<32>,
    ) -> u64 {
        proposer.require_auth();

        let storage = env.storage().instance();
        let mut next_id: u64 = storage.get(&Symbol::new(&env, "prop_id")).unwrap_or(0);
        next_id += 1;

        let proposal = Proposal {
            id: next_id,
            proposer,
            action_hash,
            approved_by: Vec::new(&env),
            state: 0, 
        };

        storage.set(&Symbol::new(&env, "prop_id"), &next_id);
        env.storage().persistent().set(&next_id, &proposal);

        next_id
    }

    pub fn approve(env: Env, voter: Address, proposal_id: u64) {
        voter.require_auth();

        let mut proposal: Proposal = env
            .storage()
            .persistent()
            .get(&proposal_id)
            .expect("Proposal not found");

        assert_eq!(proposal.state, 0, "Proposal is not active");
        
        let mut approved_by = proposal.approved_by;
        if !approved_by.contains(&voter) {
            approved_by.push_back(voter);
        }
        proposal.approved_by = approved_by;

        env.storage().persistent().set(&proposal_id, &proposal);
    }

    pub fn execute(env: Env, proposal_id: u64) {
        let mut proposal: Proposal = env
            .storage()
            .persistent()
            .get(&proposal_id)
            .expect("Proposal not found");

        assert_eq!(proposal.state, 0, "Proposal already executed or closed");
        assert!(proposal.approved_by.len() >= 2, "Insufficient signature count");

        proposal.state = 2; 
        env.storage().persistent().set(&proposal_id, &proposal);
    }
}
