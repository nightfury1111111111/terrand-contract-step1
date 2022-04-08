use crate::state::Config;
use cosmwasm_std::Binary;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InstantiateMsg {
    pub drand_step2_contract_address: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    /// Get the config state
    Config {},
    /// Get the last randomness
    LatestDrand {},
    /// Get a specific randomness
    GetRandomness { round: u64 },
    /// Not used to be call directly
    Verify {
        signature: Binary,
        msg_g2: Binary,
        worker: String,
        round: u64,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    /// Add random from this
    Drand {
        round: u64,
        previous_signature: Binary,
        signature: Binary,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema, Default)]
pub struct GetRandomResponse {
    pub randomness: Binary,
    pub worker: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct LatestRandomResponse {
    pub round: u64,
    pub randomness: Binary,
    pub worker: String,
}

// We define a custom struct for each query response
pub type ConfigResponse = Config;

/// We currently take no arguments for migrations
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct MigrateMsg {}
