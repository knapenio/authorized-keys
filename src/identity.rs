use crate::public_key::PublicKey;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt, str::FromStr};

#[derive(Deserialize, Serialize, Clone, Hash, Eq, PartialEq, Debug)]
#[serde(transparent)]
pub struct Identity(String);

pub struct ParseIdentityError;

impl Identity {
    pub fn new(identity: String) -> Self {
        Identity(identity)
    }
}

impl FromStr for Identity {
    type Err = ParseIdentityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.strip_prefix("@")
            .ok_or(ParseIdentityError)
            .map(|s| Identity::new(s.to_owned()))
    }
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "@{}", self.0)
    }
}

#[derive(Deserialize, Serialize, Clone, Default)]
#[serde(transparent)]
pub struct Identities(HashMap<Identity, Vec<PublicKey>>);

impl Identities {
    pub fn identities(&self) -> Vec<Identity> {
        self.0.keys().cloned().collect()
    }

    pub fn identity_for_key(&self, key: &PublicKey) -> Option<Identity> {
        self.0
            .iter()
            .find(|(_, keys)| keys.contains(key))
            .map(|(identity, _)| identity)
            .cloned()
    }

    pub fn keys_for_identity(&self, identity: &Identity) -> Option<Vec<PublicKey>> {
        self.0.get(identity).cloned()
    }
}
