use crate::{authorized_keys::AuthorizedKeys, public_key::PublicKey};
use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer, Serialize,
};
use std::{collections::HashMap, fmt, str::FromStr};

#[derive(Serialize, Clone, Hash, Eq, PartialEq, Debug)]
#[serde(transparent)]
pub struct Identity(String);

#[derive(thiserror::Error, Debug)]
#[error("failed to parse identity")]
pub struct ParseIdentityError;

impl Identity {
    pub fn new(identity: String) -> Self {
        Identity(identity)
    }

    pub fn identity(&self) -> &str {
        self.0.as_str()
    }
}

impl FromStr for Identity {
    type Err = ParseIdentityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.strip_prefix('@')
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
pub struct Identities(HashMap<String, AuthorizedKeys>);

impl Identities {
    /// Returns the identity for a key.
    pub fn identity_for_key(&self, key: &PublicKey) -> Option<Identity> {
        self.0
            .iter()
            .find(|(_, keys)| keys.contains(key))
            .map(|(identity, _)| Identity::new(identity.clone()))
    }

    /// Returns the keys for an identity.
    pub fn keys_for_identity(&self, identity: &Identity) -> Option<AuthorizedKeys> {
        self.0.get(identity.identity()).cloned()
    }

    /// Set the public keys for an identity.
    #[cfg(test)]
    pub fn set_keys_for_identity(&mut self, keys: AuthorizedKeys, identity: &Identity) {
        self.0.insert(identity.identity().to_owned(), keys);
    }
}

impl<'de> Deserialize<'de> for Identity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(IdentityVisitor)
    }
}

struct IdentityVisitor;

impl<'de> Visitor<'de> for IdentityVisitor {
    type Value = Identity;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a valid @identity")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        FromStr::from_str(v).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_identity() {
        assert_eq!(
            "@tom".parse::<Identity>().unwrap(),
            Identity::new(String::from("tom"))
        );
        assert_eq!(
            "@foo-bar".parse::<Identity>().unwrap(),
            Identity::new(String::from("foo-bar"))
        );
        assert_eq!(
            "@@double-you".parse::<Identity>().unwrap(),
            Identity::new(String::from("@double-you"))
        );
        assert!("tom".parse::<Identity>().is_err());
        assert!("".parse::<Identity>().is_err());
    }

    #[test]
    fn identity_for_key() {
        let identities = test_identities();

        assert_eq!(
            identities.identity_for_key(&"ssh-rsa foo".parse().unwrap()),
            Some("@foo".parse().unwrap())
        );
        assert_eq!(
            identities.identity_for_key(&"ssh-rsa bar".parse().unwrap()),
            Some("@bar".parse().unwrap())
        );
        assert_eq!(
            identities.identity_for_key(&"ssh-rsa baz".parse().unwrap()),
            None
        );
    }

    #[test]
    fn keys_for_identity() {
        let identities = test_identities();
        assert_eq!(
            identities.keys_for_identity(&"@foo".parse().unwrap()),
            Some(authorized_keys("ssh-rsa foo"))
        );
        assert_eq!(
            identities.keys_for_identity(&"@bar".parse().unwrap()),
            Some(authorized_keys("ssh-rsa bar"))
        );
        assert!(identities
            .keys_for_identity(&"@baz".parse().unwrap())
            .is_none());
    }

    fn test_identities() -> Identities {
        let mut identities = Identities::default();
        identities
            .0
            .insert(String::from("foo"), authorized_keys("ssh-rsa foo"));
        identities
            .0
            .insert(String::from("bar"), authorized_keys("ssh-rsa bar"));
        identities
    }

    fn authorized_keys(key: &str) -> AuthorizedKeys {
        let mut keys = AuthorizedKeys::default();
        keys.insert(key.parse().unwrap());
        keys
    }
}
