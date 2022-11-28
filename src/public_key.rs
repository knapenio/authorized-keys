use serde::{Deserialize, Serialize};
use std::fmt::{self};
use std::str::FromStr;

#[derive(Serialize, Deserialize, Clone, Hash, Eq, Debug, Ord, PartialOrd)]
#[serde(transparent)]
pub struct PublicKey(String);

#[derive(thiserror::Error, Debug)]
#[error("failed to parse public key")]
pub struct ParsePublicKeyError;

impl FromStr for PublicKey {
    type Err = ParsePublicKeyError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        // public keys consists of at least 2 parts separated by spaces
        if s.splitn(3, ' ').count() < 2 {
            return Err(ParsePublicKeyError);
        }

        Ok(PublicKey(s.to_owned()))
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.strip_comment().0 == other.strip_comment().0
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

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
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
}
