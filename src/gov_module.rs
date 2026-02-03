// src/gov_module.rs

use crate::params::{ParamManager, ProtocolParams};
// CORRECTED: Address and StakeAmount are now public in stk_module
use crate::stk_module::{StakingModule, StakeAmount, Address};
use crate::storage::{GovernanceStore, StorageError}; 
use std::sync::Arc;
use parking_lot::RwLock;
use log::{info, error, debug};
use serde::{Serialize, Deserialize};
use thiserror::Error;

// --- Data Structures (Required for the implementation below) ---

pub type ProposalId = u64;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum VoteType { Yes, No, Abstain }

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum ProposalAction {
    ParameterChange { param_name: String, new_value: Vec<u8> },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum ProposalState {
    VotingPeriod,
    ExecutionPending,
    Executed,
    Rejected,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Proposal {
    pub id: ProposalId,
    pub action: ProposalAction,
    pub state: ProposalState,
    pub voting_end_height: u32,
    pub execution_height: u32,
    pub votes_yes: StakeAmount,
    pub votes_no: StakeAmount,
    pub votes_abstain: StakeAmount,
}

#[derive(Error, Debug)]
pub enum GovernanceError {
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("Proposal {0} is not in the active VotingPeriod.")]
    NotVotingPeriod(ProposalId),
    #[error("Voter {0} has already voted on proposal {1}.")]
    AlreadyVoted(Address, ProposalId),
    #[error("Voter {0} has insufficient stake or is not bonded.")]
    InsufficientVotingPower(Address),
}

const BPS_MAX: u128 = 10000;

pub struct GovernanceModule {
    param_manager: Arc<ParamManager>,
    staking_module: Arc<StakingModule>,
    store: GovernanceStore,
    gov_params: Arc<RwLock<ProtocolParams>>,
}

impl GovernanceModule {
    pub fn new(param_manager: Arc<ParamManager>, staking_module: Arc<StakingModule>, store: GovernanceStore) -> Self {
        let params = param_manager.get_params();
        Self { 
            param_manager, 
            staking_module, 
            store, 
            gov_params: Arc::new(RwLock::new(params)),
        }
    }

    fn refresh_params(&self) {
        let new_params = self.param_manager.get_params();
        let mut cached_params = self.gov_params.write();
        *cached_params = new_params;
        info!("Governance parameters cache refreshed.");
    }

    pub fn process_submit_proposal(&self, action: ProposalAction, current_height: u32) -> Result<ProposalId, GovernanceError> {
        let id = self.store.get_next_proposal_id()?;
        
        let params = self.gov_params.read();
        let voting_end_height = current_height + params.voting_period_blocks;
        let execution_height = voting_end_height + params.execution_delay_blocks;

        let proposal = Proposal {
            id, action,
            state: ProposalState::VotingPeriod,
            voting_end_height, execution_height,
            votes_yes: 0, votes_no: 0, votes_abstain: 0,
        };

        self.store.insert_proposal(&proposal)?;
        info!("New governance proposal submitted (ID: {}). Voting ends at height {}.", id, voting_end_height);
        Ok(id)
    }

    pub fn process_vote(&self, proposal_id: ProposalId, voter_address: Address, vote_type: VoteType) -> Result<(), GovernanceError> {
        if self.store.has_voted(proposal_id, &voter_address)? {
            return Err(GovernanceError::AlreadyVoted(voter_address, proposal_id));
        }

        let mut proposal = self.store.get_proposal(proposal_id)?;
        if proposal.state != ProposalState::VotingPeriod {
            return Err(GovernanceError::NotVotingPeriod(proposal_id));
        }

        let voting_power = self.staking_module.get_voting_power(&voter_address);
        if voting_power == 0 {
            return Err(GovernanceError::InsufficientVotingPower(voter_address));
        }

        match vote_type {
            VoteType::Yes => proposal.votes_yes = proposal.votes_yes.saturating_add(voting_power),
            VoteType::No => proposal.votes_no = proposal.votes_no.saturating_add(voting_power),
            VoteType::Abstain => proposal.votes_abstain = proposal.votes_abstain.saturating_add(voting_power),
        }

        self.store.update_proposal(&proposal, &ProposalState::VotingPeriod)?;
        self.store.store_vote(proposal_id, &voter_address, &vote_type)?;
        
        debug!("Vote recorded for Proposal {}: Type {:?}, Power {}", proposal_id, vote_type, voting_power);
        Ok(())
    }

    pub fn end_block_logic(&self, block_height: u32) {
        self.process_voting_conclusions(block_height);
        
        let params_updated = self.process_executions(block_height);

        if params_updated {
            self.refresh_params();
        }
    }

    fn process_voting_conclusions(&self, block_height: u32) {
        let active_proposals = match self.store.get_proposals_by_state(&ProposalState::VotingPeriod) {
            Ok(p) => p,
            Err(e) => {
                error!("Failed to retrieve active proposals from storage: {:?}", e);
                return;
            }
        };

        let total_stake = self.staking_module.get_total_bonded_supply();
        let params = self.gov_params.read();

        for mut proposal in active_proposals {
            if block_height >= proposal.voting_end_height {
                info!("Voting period concluded for Proposal {}. Tallying votes.", proposal.id);
                
                let old_state = proposal.state.clone();
                self.tally_votes(&mut proposal, total_stake, &params);

                if let Err(e) = self.store.update_proposal(&proposal, &old_state) {
                    error!("CRITICAL: Failed to update proposal state after tallying {}: {:?}", proposal.id, e);
                }
            }
        }
    }

    fn tally_votes(&self, proposal: &mut Proposal, total_stake: StakeAmount, params: &ProtocolParams) {
        let participating_stake = proposal.votes_yes
            .saturating_add(proposal.votes_no)
            .saturating_add(proposal.votes_abstain);

        if total_stake == 0 {
            proposal.state = ProposalState::Rejected;
            info!("Proposal {} REJECTED (Total stake is zero).", proposal.id);
            return;
        }

        let quorum_check_lhs = participating_stake.saturating_mul(BPS_MAX);
        let quorum_check_rhs = total_stake.saturating_mul(params.quorum_threshold_bps as u128);

        if quorum_check_lhs < quorum_check_rhs {
            proposal.state = ProposalState::Rejected;
            info!("Proposal {} REJECTED (Quorum not met).", proposal.id);
            return;
        }

        let voting_stake = participating_stake.saturating_sub(proposal.votes_abstain);
        
        if voting_stake == 0 {
            proposal.state = ProposalState::Rejected;
            info!("Proposal {} REJECTED (No Yes/No votes cast).", proposal.id);
            return;
        }
        
        let passing_check_lhs = proposal.votes_yes.saturating_mul(BPS_MAX);
        let passing_check_rhs = voting_stake.saturating_mul(params.passing_threshold_bps as u128);

        if passing_check_lhs > passing_check_rhs {
            proposal.state = ProposalState::ExecutionPending;
            info!("Proposal {} PASSED. Entering ExecutionPending state.", proposal.id);
        } else {
            proposal.state = ProposalState::Rejected;
            info!("Proposal {} REJECTED (Threshold not met).", proposal.id);
        }
    }

    fn process_executions(&self, block_height: u32) -> bool {
        let pending_proposals = match self.store.get_proposals_by_state(&ProposalState::ExecutionPending) {
            Ok(p) => p,
            Err(e) => {
                error!("Failed to retrieve pending proposals from storage: {:?}", e);
                return false;
            }
        };

        let mut params_updated = false;

        for mut proposal in pending_proposals {
            if block_height >= proposal.execution_height {
                let old_state = proposal.state.clone();
                
                let executed_param_change = self.execute_proposal(&mut proposal);
                
                if executed_param_change {
                    params_updated = true;
                }

                if let Err(e) = self.store.update_proposal(&proposal, &old_state) {
                    error!("CRITICAL: Failed to update proposal state after execution {}: {:?}", proposal.id, e);
                }
            }
        }
        params_updated
    }

    fn execute_proposal(&self, proposal: &mut Proposal) -> bool {
        info!("GOVERNANCE EXECUTION: Executing Proposal {}.", proposal.id);
        
        let mut param_change_executed = false;

        let result = match &proposal.action {
            ProposalAction::ParameterChange { param_name, new_value } => {
                match self.param_manager.update_parameter(param_name, new_value) {
                    Ok(_) => {
                        param_change_executed = true;
                        Ok(())
                    },
                    Err(e) => Err(format!("Parameter update failed: {:?}", e)),
                }
            },
        };

        if let Err(err_msg) = result {
            error!("CRITICAL: Failed to execute passed governance proposal {}. Error: {}", proposal.id, err_msg);
        } else {
            info!("Successfully executed Proposal {}.", proposal.id);
            proposal.state = ProposalState::Executed;
        }
        
        param_change_executed
    }
}