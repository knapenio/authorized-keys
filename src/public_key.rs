use serde::{Deserialize, Serialize};
use std::fmt;
use std::hash::Hash;
use std::str::FromStr;

#[derive(Serialize, Deserialize, Clone, Eq, Debug, Ord, PartialOrd)]
#[serde(transparent)]
pub struct PublicKey(String);

impl PublicKey {
    /// Returns the public key with the comment removed.
    fn strip_comment(&self) -> &str {
        self.0
            .match_indices(' ')
            .nth(1)
            .map_or(&self.0, |pos| &self.0[..pos.0])
    }

    /// Returns this public key's comment, if any.
    pub fn comment(&self) -> Option<&str> {
        self.0
            .match_indices(' ')
            .nth(1)
            .map(|pos| &self.0[pos.0 + 1..])
    }
}

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
        self.strip_comment() == other.strip_comment()
    }
}

impl Hash for PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.strip_comment().hash(state)
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
            PublicKey(
                "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCdWXdw3eWCGNEO+FIx user@local".to_owned()
            )
            .comment(),
            Some("user@local")
        );
        assert_eq!(
            PublicKey(
                "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCdWXdw3eWCGNEO+FIx random comment"
                    .to_owned()
            )
            .comment(),
            Some("random comment")
        );
        assert_eq!(
            PublicKey("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+Ph3Mgju0wqHzXqX".to_owned())
                .comment(),
            None
        );
    }

    #[test]
    fn public_key_strip_comment() {
        assert_eq!(
            PublicKey(
                "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCdWXdw3eWCGNEO+FOx user@local".to_owned()
            )
            .strip_comment(),
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCdWXdw3eWCGNEO+FOx"
        );
        assert_eq!(
            PublicKey(
                "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCdWXdw3eWCGNEO+FIx random comment"
                    .to_owned()
            )
            .strip_comment(),
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCdWXdw3eWCGNEO+FIx"
        );
        assert_eq!(
            PublicKey("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+Ph5Mgju0wqHzXqX".to_owned())
                .strip_comment(),
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+Ph5Mgju0wqHzXqX"
        );
    }
}
