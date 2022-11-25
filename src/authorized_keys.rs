use crate::{
    identity::{Identities, Identity},
    public_key::PublicKey,
};
use serde::{Deserialize, Serialize};
use std::fmt::Write;
use std::io::BufRead;
use std::str::FromStr;

type Result<T> = std::result::Result<T, anyhow::Error>;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(untagged)]
enum Item {
    Identity(Identity),
    PublicKey(PublicKey),
}

// we're using a `Vec` instead of a `HashSet` for storage
// because we want to maintain any ordering of the authorized keys
#[derive(Serialize, Deserialize, Clone, Default, Debug)]
#[serde(transparent)]
pub struct AuthorizedKeys(Vec<PublicKey>);

impl AuthorizedKeys {
    /// Read the authorized keys using `reader`.
    pub fn from_reader<R>(reader: R, identities: Option<&Identities>) -> Result<Self>
    where
        R: BufRead,
    {
        let mut authorized_keys = AuthorizedKeys::default();

        for line in reader.lines() {
            match line {
                Ok(line) => {
                    if line.is_empty() {
                        continue;
                    }

                    let item: Item = line.parse()?;

                    match item {
                        Item::Identity(identity) => {
                            let keys = identities
                                .and_then(|identities| identities.keys_for_identity(&identity))
                                .ok_or(ParseItemError)?; // TODO: return correct error
                            for key in keys {
                                authorized_keys.push(key);
                            }
                        }
                        Item::PublicKey(key) => authorized_keys.push(key),
                    }
                }
                Err(e) => return Err(e)?,
            }
        }

        Ok(authorized_keys)
    }

    /// Write the authorized keys using `writer`.
    pub fn to_writer<W>(&self, writer: &mut W, identities: Option<&Identities>) -> Result<()>
    where
        W: Write,
    {
        for key in &self.0 {
            writeln!(writer, "{}", key.to_string())?;
        }

        Ok(())
    }

    /// Appends a key to the authorized keys.
    fn push(&mut self, key: PublicKey) {
        self.0.push(key)
    }

    /// Returns the number of keys in the authorized keys.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the authorized keys contains no keys.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns `true` if the authorized keys contains the given key.
    pub fn contains(&self, key: &PublicKey) -> bool {
        self.0
            .iter()
            .any(|authorized| authorized.strip_comment() == key.strip_comment())
    }

    /// Returns a copy of `self` with any comments removed from the keys.
    fn strip_comments(&self) -> AuthorizedKeys {
        AuthorizedKeys(self.0.iter().map(PublicKey::strip_comment).collect())
    }

    /// Returns the difference, i.e., the keys that are in `self` but not in `other`.
    pub fn difference(&self, other: &AuthorizedKeys) -> AuthorizedKeys {
        let other_stripped = other.strip_comments();
        let difference = self
            .0
            .iter()
            .filter(|key| !other_stripped.contains(&key.strip_comment()))
            .cloned()
            .collect();

        AuthorizedKeys(difference)
    }
}

impl IntoIterator for AuthorizedKeys {
    type Item = PublicKey;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

#[derive(thiserror::Error, Debug)]
#[error("failed to parse item")]
struct ParseItemError;

impl FromStr for Item {
    type Err = ParseItemError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if let Ok(identity) = s.parse::<Identity>() {
            Ok(Item::Identity(identity))
        } else if let Ok(key) = s.parse::<PublicKey>() {
            Ok(Item::PublicKey(key))
        } else {
            Err(ParseItemError)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn authorized_keys_contains() {
        let cursor = Cursor::new("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCdWXdw3=\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+Ph5Mg=");
        let authorized_keys = AuthorizedKeys::from_reader(cursor, None).unwrap();

        assert!(authorized_keys.contains(
            &("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCdWXdw3="
                .parse()
                .unwrap())
        ));
        assert!(authorized_keys.contains(
            &("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+Ph5Mg="
                .parse()
                .unwrap())
        ));

        assert!(authorized_keys.contains(
            &("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCdWXdw3= random"
                .parse()
                .unwrap())
        ));
        assert!(authorized_keys.contains(
            &("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+Ph5Mg= comment"
                .parse()
                .unwrap())
        ));

        assert!(!authorized_keys.contains(
            &("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+Ph5Mj="
                .parse()
                .unwrap())
        ));
    }

    #[test]
    fn authorized_keys_difference() {}

    #[test]
    fn read_authorized_keys() {
        let cursor = Cursor::new("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCdWXdw3=\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+Ph5Mg=\n\n");
        let authorized_keys = AuthorizedKeys::from_reader(cursor, None).unwrap();

        assert_eq!(
            authorized_keys.0,
            vec![
                "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCdWXdw3="
                    .parse()
                    .unwrap(),
                "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+Ph5Mg="
                    .parse()
                    .unwrap()
            ]
        );
    }

    #[test]
    fn write_authorized_keys() {
        let authorized_keys = AuthorizedKeys(vec![
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+Ph5Mg="
                .parse()
                .unwrap(),
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCdWXdw3="
                .parse()
                .unwrap(),
        ]);

        let mut output = String::new();
        authorized_keys.to_writer(&mut output, None).unwrap();
        assert_eq!(output.as_str(), "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+Ph5Mg=\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCdWXdw3=\n");
    }
}
