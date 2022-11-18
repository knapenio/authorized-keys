use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::fmt::{self, Write};
use std::io::BufRead;
use std::str::FromStr;

type Result<T> = std::result::Result<T, anyhow::Error>;

#[derive(Serialize, Deserialize, Clone, Hash, Eq, PartialEq, Debug)]
#[serde(transparent)]
pub struct PublicKey(String);

// we're using a `Vec` instead of a `HashSet` for storage
// because we want to maintain any ordering of the authorized keys
#[derive(Serialize, Deserialize, Clone, Default, Debug)]
#[serde(transparent)]
pub struct AuthorizedKeys(Vec<PublicKey>);

impl FromStr for PublicKey {
    type Err = Infallible;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(PublicKey(s.to_owned()))
    }
}

impl PublicKey {
    pub fn new(key: String) -> Self {
        PublicKey(key)
    }

    /// Returns this public key's comment, if any.
    pub fn comment(&self) -> Option<&str> {
        let split: Vec<_> = self.0.splitn(3, ' ').collect();
        if split.len() != 3 {
            return None;
        }
        Some(split[2])
    }

    /// Strips the comment from this public key.
    pub fn strip_comment(&self) -> PublicKey {
        let key = match self.0.match_indices(' ').nth(1) {
            Some(pos) => &self.0[..pos.0],
            _ => &self.0,
        };
        PublicKey(key.to_owned())
    }
}

impl AuthorizedKeys {
    /// Read the authorized keys using `reader`.
    pub fn from_reader<R>(reader: R) -> Result<Self>
    where
        R: BufRead,
    {
        let mut keys = AuthorizedKeys::default();

        for line in reader.lines() {
            match line {
                Ok(line) => {
                    if !line.is_empty() {
                        keys.push(PublicKey::new(line));
                    }
                }
                Err(e) => return Err(e)?,
            }
        }

        Ok(keys)
    }

    /// Write the authorized keys using `writer`.
    pub fn to_writer<W>(&self, writer: &mut W) -> Result<()>
    where
        W: Write,
    {
        for key in &self.0 {
            writeln!(writer, "{}", key.0)?;
        }

        Ok(())
    }

    /// Appends a key to the authorized keys.
    pub fn push(&mut self, key: PublicKey) {
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
    pub fn contains(&self, key: PublicKey) -> bool {
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
            .filter(|key| !other_stripped.contains(key.strip_comment()))
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

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn public_key_comment() {
        assert_eq!(
            PublicKey::new(
                "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCdWXdw3eWCGNEO+FIx user@local".to_owned()
            )
            .comment(),
            Some("user@local")
        );
        assert_eq!(
            PublicKey::new(
                "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCdWXdw3eWCGNEO+FIx random comment"
                    .to_owned()
            )
            .comment(),
            Some("random comment")
        );
        assert_eq!(
            PublicKey::new("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+Ph3Mgju0wqHzXqX".to_owned())
                .comment(),
            None
        );
    }

    #[test]
    fn public_key_strip_comment() {
        assert_eq!(
            PublicKey::new(
                "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCdWXdw3eWCGNEO+FOx user@local".to_owned()
            )
            .strip_comment(),
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCdWXdw3eWCGNEO+FOx"
                .parse()
                .unwrap()
        );
        assert_eq!(
            PublicKey::new(
                "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCdWXdw3eWCGNEO+FIx random comment"
                    .to_owned()
            )
            .strip_comment(),
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCdWXdw3eWCGNEO+FIx"
                .parse()
                .unwrap()
        );
        assert_eq!(
            PublicKey::new("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+Ph5Mgju0wqHzXqX".to_owned())
                .strip_comment(),
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+Ph5Mgju0wqHzXqX"
                .parse()
                .unwrap()
        );
    }

    #[test]
    fn authorized_keys_contains() {
        let cursor = Cursor::new("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCdWXdw3=\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+Ph5Mg=");
        let authorized_keys = AuthorizedKeys::from_reader(cursor).unwrap();

        assert!(authorized_keys.contains(
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCdWXdw3="
                .parse()
                .unwrap()
        ));
        assert!(authorized_keys.contains(
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+Ph5Mg="
                .parse()
                .unwrap()
        ));

        assert!(authorized_keys.contains(
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCdWXdw3= random"
                .parse()
                .unwrap()
        ));
        assert!(authorized_keys.contains(
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+Ph5Mg= comment"
                .parse()
                .unwrap()
        ));

        assert!(!authorized_keys.contains(
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+Ph5Mj="
                .parse()
                .unwrap()
        ));
    }

    #[test]
    fn authorized_keys_difference() {}
}
