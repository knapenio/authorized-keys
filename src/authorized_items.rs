use crate::{
    authorized_keys::AuthorizedKeys,
    identity::{Identities, Identity},
    public_key::PublicKey,
};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(untagged)]
pub enum AuthorizedItem {
    Identity(Identity),
    PublicKey(PublicKey),
}

// we're using a `Vec` instead of a `HashSet` for storage
// because we want to maintain any ordering of the authorized keys
#[derive(Serialize, Deserialize, Clone, Default, Debug)]
#[serde(transparent)]
pub struct AuthorizedItems(Vec<AuthorizedItem>);

impl AuthorizedItems {
    /// Appends an item to the authorized items.
    pub fn push(&mut self, item: AuthorizedItem) {
        if !self.0.contains(&item) {
            self.0.push(item)
        }
    }

    pub fn collect_authorized_keys(&self, identities: &Identities) -> AuthorizedKeys {
        let mut authorized_keys = AuthorizedKeys::default();

        for item in &self.0 {
            match item {
                AuthorizedItem::PublicKey(key) => authorized_keys.push(key.clone()),
                AuthorizedItem::Identity(identity) => {
                    for key in identities.keys_for_identity(identity).unwrap_or_default() {
                        authorized_keys.push(key);
                    }
                }
            }
        }

        authorized_keys
    }
}

#[derive(thiserror::Error, Debug)]
#[error("failed to parse item")]
pub struct ParseAuthorizedItemError;

impl FromStr for AuthorizedItem {
    type Err = ParseAuthorizedItemError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if let Ok(identity) = s.parse::<Identity>() {
            Ok(AuthorizedItem::Identity(identity))
        } else if let Ok(key) = s.parse::<PublicKey>() {
            Ok(AuthorizedItem::PublicKey(key))
        } else {
            Err(ParseAuthorizedItemError)
        }
    }
}

impl From<AuthorizedKeys> for AuthorizedItems {
    fn from(keys: AuthorizedKeys) -> Self {
        let mut authorized_items = AuthorizedItems::default();

        for key in keys {
            authorized_items.0.push(AuthorizedItem::PublicKey(key));
        }

        authorized_items
    }
}

impl Serialize for AuthorizedItem {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::PublicKey(key) => serializer.serialize_str(&key.to_string()),
            Self::Identity(identity) => serializer.serialize_str(&identity.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorized_keys() {
        let mut items = AuthorizedItems::default();
        items.push(AuthorizedItem::Identity("@foo".parse().unwrap()));
        items.push(AuthorizedItem::Identity("@bar".parse().unwrap()));
        items.push(AuthorizedItem::Identity("@baz".parse().unwrap()));
        assert_eq!(
            items.collect_authorized_keys(&test_identities()).sorted(),
            collect_keys(&["ssh-rsa foo", "ssh-rsa bar", "ssh-rsa baz"]).sorted()
        );
    }

    fn test_identities() -> Identities {
        let mut identities = Identities::default();
        identities.set_keys_for_identity(
            collect_keys(&["ssh-rsa foo", "ssh-rsa baz"]),
            &"@foo".parse().unwrap(),
        );
        identities.set_keys_for_identity(collect_keys(&["ssh-rsa bar"]), &"@bar".parse().unwrap());
        identities
    }

    fn collect_keys<I, T: ToString>(keys: I) -> AuthorizedKeys
    where
        I: IntoIterator<Item = T>,
    {
        let mut authorized_keys = AuthorizedKeys::default();
        for key in keys.into_iter() {
            authorized_keys.push(key.to_string().parse().unwrap());
        }
        authorized_keys
    }
}
