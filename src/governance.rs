// src/governance.rs

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// The possible states of a governance proposal.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum ProposalState {
    Pending,
    Active,
    Succeeded,
    Failed,
    Executed,
}

/// The possible payloads of a governance proposal, representing on-chain actions to be taken.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum ProposalPayload {
    None,
    UpdateTargetBlockTime(u64),
    UpdateFeeBurnRate(f64),
}

/// The structure of a governance proposal.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Proposal {
    pub id: u64,
    pub proposer: String,
    pub title: String,
    pub description: String,
    pub start_block: u32,
    pub end_block: u32,
    pub votes_for: u64,
    pub votes_against: u64,
    pub state: ProposalState,
    pub payload: ProposalPayload,
}

/// The main governance struct, which manages all proposals.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Governance {
    pub proposals: HashMap<u64, Proposal>,
    pub next_proposal_id: u64,
}

impl Governance {
    /// Creates a new Governance instance.
    pub fn new() -> Self {
        Governance {
            proposals: HashMap::new(),
            next_proposal_id: 0,
        }
    }

    /// Creates a new governance proposal and adds it to the system.
    pub fn create_proposal(
        &mut self,
        proposer: String,
        title: String,
        description: String,
        start_block_height: u32,
        payload: ProposalPayload,
        governance_config: &crate::config::GovernanceConfig,
    ) -> u64 {
        let id = self.next_proposal_id;
        let proposal = Proposal {
            id,
            proposer,
            title,
            description,
            start_block: start_block_height,
            end_block: start_block_height + governance_config.proposal_duration_blocks,
            votes_for: 0,
            votes_against: 0,
            state: ProposalState::Active,
            payload,
        };
        self.proposals.insert(id, proposal);
        self.next_proposal_id += 1;
        id
    }

    /// Casts a vote on a governance proposal, weighted by the voter's stake.
    pub fn cast_vote(&mut self, proposal_id: u64, stake_weight: u64, in_favor: bool) -> Result<(), String> {
        let proposal = self.proposals.get_mut(&proposal_id).ok_or("Proposal not found")?;

        if proposal.state != ProposalState::Active {
            return Err("Proposal is not active for voting.".to_string());
        }

        if in_favor {
            proposal.votes_for += stake_weight;
        } else {
            proposal.votes_against += stake_weight;
        }

        Ok(())
    }
}