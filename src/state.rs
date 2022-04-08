use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{Binary, CanonicalAddr};
use cw_storage_plus::{Item, Map};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Config {
    pub drand_step2_contract_address: CanonicalAddr,
}

pub const CONFIG: Item<Config> = Item::new("config");

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct BeaconInfoState {
    pub round: u64,
    pub randomness: Binary,
    pub worker: CanonicalAddr,
}
pub const BEACONS: Map<&[u8], BeaconInfoState> = Map::new("beacons");
