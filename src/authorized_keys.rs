use crate::public_key::PublicKey;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt::Write;
use std::io::BufRead;

type Result<T> = anyhow::Result<T>;

#[derive(Serialize, Deserialize, Clone, Default, Debug, Eq, PartialEq)]
#[serde(transparent)]
pub struct AuthorizedKeys(HashSet<PublicKey>);

impl AuthorizedKeys {
    /// Read the authorized keys using `reader`.
    pub fn from_reader<R>(reader: R) -> Result<Self>
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

                    let key: PublicKey = line.parse()?;
                    authorized_keys.insert(key)
                }
                Err(e) => return Err(e)?,
            }
        }

        Ok(authorized_keys)
    }

    /// Write the authorized keys using `writer`.
    pub fn to_writer<W>(&self, writer: &mut W) -> Result<()>
    where
        W: Write,
    {
        for key in self.sorted_keys() {
            writeln!(writer, "{}", key)?;
        }

        Ok(())
    }

    /// Add a key to the authorized keys.
    pub fn insert(&mut self, key: PublicKey) {
        self.0.insert(key);
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
        self.0.contains(key)
    }

    /// Returns the difference,
    /// i.e., the keys that are in `self` but not in `other`.
    pub fn difference(&self, other: &AuthorizedKeys) -> AuthorizedKeys {
        let keys = self.0.difference(&other.0).cloned().collect();
        AuthorizedKeys(keys)
    }

    /// Returns `true` if `self` is a superset of another authorized keys,
    /// i.e., `self` contains at least all keys in `other`.
    pub fn is_superset(&self, other: &AuthorizedKeys) -> bool {
        self.0.is_superset(&other.0)
    }

    fn sorted_keys(&self) -> Vec<&PublicKey> {
        let mut keys: Vec<_> = self.0.iter().collect();
        keys.sort();
        keys
    }

    /// An iterator visiting all keys in arbitrary order.
    pub fn iter(&self) -> AuthorizedKeysIter {
        AuthorizedKeysIter(self.0.iter())
    }
}

use std::collections::hash_set;

pub struct AuthorizedKeysIter<'a>(hash_set::Iter<'a, PublicKey>);

impl<'a> Iterator for AuthorizedKeysIter<'a> {
    type Item = &'a PublicKey;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

impl IntoIterator for AuthorizedKeys {
    type Item = PublicKey;
    type IntoIter = hash_set::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn authorized_keys_contains() {
        let cursor = Cursor::new("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCdWXdw3=\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+Ph5Mg=");
        let authorized_keys = AuthorizedKeys::from_reader(cursor).unwrap();

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
        let authorized_keys = AuthorizedKeys::from_reader(cursor).unwrap();

        assert_eq!(
            authorized_keys.0,
            HashSet::from_iter(
                [
                    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCdWXdw3="
                        .parse()
                        .unwrap(),
                    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+Ph5Mg="
                        .parse()
                        .unwrap()
                ]
                .into_iter()
            )
        );
    }

    #[test]
    fn write_authorized_keys() {
        let authorized_keys = AuthorizedKeys(HashSet::from_iter(
            [
                "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+Ph5Mg="
                    .parse()
                    .unwrap(),
                "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCdWXdw3="
                    .parse()
                    .unwrap(),
            ]
            .into_iter(),
        ));

        let mut output = String::new();
        authorized_keys.to_writer(&mut output).unwrap();
        assert_eq!(output.as_str(), "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCdWXdw3=\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+Ph5Mg=\n");
    }
}
