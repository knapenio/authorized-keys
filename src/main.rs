mod authorized_items;
mod authorized_keys;
mod identity;
mod public_key;
mod ssh;

use crate::{authorized_keys::AuthorizedKeys, identity::Identities, ssh::SshConnection};
use authorized_items::{AuthorizedItem, AuthorizedItems};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::File,
    io::{BufReader, Cursor},
};

type Result<T> = anyhow::Result<T>;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
    #[arg(long, short)]
    config: String,
}

#[derive(Subcommand)]
enum Command {
    /// Push the authorized keys defined in the configuration file
    Push,
    /// Pull the authorized keys into the configuration file
    Pull,
    /// Audit the authorized keys stored on remote servers
    Audit,
}

#[derive(Deserialize, Serialize)]
struct Config {
    hosts: HashMap<String, Vec<Item>>,
    identities: Option<Identities>,
}

#[derive(Deserialize, Serialize)]
struct Item {
    user: String,
    path: String,
    #[serde(rename = "authorized_keys")]
    authorized_items: AuthorizedItems,
}

#[derive(thiserror::Error, Debug)]
enum Error {
    #[error("failed to read config file {path}")]
    ReadConfig { path: String, source: anyhow::Error },
    #[error("failed to write config file {path}")]
    WriteConfig { path: String, source: anyhow::Error },
    #[error("failed to read authorized keys")]
    ReadAuthorizedKeys(#[source] anyhow::Error),
    #[error("failed to write authorized keys")]
    WriteAuthorizedKeys(#[source] anyhow::Error),
    #[error("audit failed for {path} (via {user}@{hostname})")]
    AuditFailed {
        hostname: String,
        user: String,
        path: String,
    },
}

fn main() -> Result<()> {
    let cli: Cli = Cli::parse();

    match cli.command {
        Command::Push => push_config(cli.config)?,
        Command::Pull => pull_config(cli.config)?,
        Command::Audit => audit_config(cli.config)?,
    }

    Ok(())
}

fn push_config(path: String) -> Result<()> {
    let config = read_config(path)?;

    let identities = config.identities.unwrap_or_default();

    for (hostname, items) in config.hosts {
        for item in items {
            let connection = SshConnection::new(hostname.clone(), item.user.clone());
            let authorized_keys = item.collect_authorized_keys(&identities);
            write_authorized_keys(&connection, item.path, authorized_keys)?;
        }
    }

    Ok(())
}

fn pull_config(path: String) -> Result<()> {
    let mut config = read_config(path.clone())?;

    let identities = config.identities.clone().unwrap_or_default();

    for (hostname, items) in config.hosts.iter_mut() {
        for item in items {
            let connection = SshConnection::new(hostname.clone(), item.user.clone());
            let authorized_keys = read_authorized_keys(&connection, item.path.clone())?;
            item.set_authorized_items(authorized_keys, &identities);
        }
    }

    write_config(path, &config)?;

    Ok(())
}

fn audit_config(path: String) -> Result<()> {
    let config = read_config(path)?;

    let identities = config.identities.unwrap_or_default();

    for (hostname, items) in config.hosts {
        for item in items {
            let connection = SshConnection::new(hostname.clone(), item.user.clone());

            println!("Auditing {} (via {})...", item.path, connection);

            let authorized_keys = read_authorized_keys(&connection, item.path.clone())?;
            let known_keys = item.collect_authorized_keys(&identities);
            let unknown_keys = authorized_keys.difference(&known_keys);
            let missing_keys = known_keys.difference(&authorized_keys);

            if !unknown_keys.is_empty() || !missing_keys.is_empty() {
                for unknown_key in unknown_keys {
                    eprintln!("found unknown key {}", unknown_key);
                }

                for missing_key in missing_keys {
                    eprintln!("found missing key {}", missing_key);
                }

                return Err(Error::AuditFailed {
                    hostname,
                    user: item.user,
                    path: item.path,
                })?;
            } else {
                println!("OK");
            }
        }
    }

    Ok(())
}

fn read_config(path: String) -> Result<Config> {
    println!("reading configuration file {}... ", path);

    let file = File::open(&path)?;
    let config = serde_yaml::from_reader(BufReader::new(file)).map_err(|e| Error::ReadConfig {
        path,
        source: e.into(),
    })?;

    println!("OK");
    Ok(config)
}

fn write_config(path: String, config: &Config) -> Result<()> {
    println!("writing configuration file {}... ", path);

    let file = File::options()
        .write(true)
        .truncate(true)
        .create(true)
        .open(&path)?;
    serde_yaml::to_writer(file, config).map_err(|e| Error::WriteConfig {
        path,
        source: e.into(),
    })?;

    println!("OK");
    Ok(())
}

fn read_authorized_keys(connection: &SshConnection, path: String) -> Result<AuthorizedKeys> {
    println!(
        "reading authorized keys from {} (via {})...",
        path, connection
    );

    let contents = connection
        .read_file(path.clone())
        .map_err(|e| Error::ReadAuthorizedKeys(e.into()))?;
    let cursor = Cursor::new(contents);
    let authorized_keys = AuthorizedKeys::from_reader(cursor)?;

    println!(
        "successfully read {} authorized keys from {} (via {})",
        authorized_keys.len(),
        path,
        connection
    );

    Ok(authorized_keys)
}

fn write_authorized_keys(
    connection: &SshConnection,
    path: String,
    authorized_keys: AuthorizedKeys,
) -> Result<()> {
    println!(
        "writing authorized keys to {} (via {})...",
        path, connection
    );

    let mut text = String::new();
    authorized_keys.to_writer(&mut text)?;

    connection
        .write_file(path.clone(), text)
        .map_err(|e| Error::WriteAuthorizedKeys(e.into()))?;

    println!(
        "successfully wrote {} authorized keys to {} (via {})",
        authorized_keys.len(),
        path,
        connection
    );

    Ok(())
}

impl Item {
    pub fn collect_authorized_keys(&self, identities: &Identities) -> AuthorizedKeys {
        self.authorized_items.collect_authorized_keys(identities)
    }

    pub fn set_authorized_items(
        &mut self,
        authorized_keys: AuthorizedKeys,
        identities: &Identities,
    ) {
        let mut authorized_items = AuthorizedItems::default();

        for key in authorized_keys.iter().cloned() {
            if let Some(identity) = identities.identity_for_key(&key) {
                // only add the full identity if all of its keys are contained in `authorized_keys`
                // otherwise we only add this specific key
                let keys_for_identity = identities.keys_for_identity(&identity).unwrap_or_default();
                if authorized_keys.is_superset(&keys_for_identity) {
                    authorized_items.insert(AuthorizedItem::Identity(identity));
                } else {
                    authorized_items.insert(AuthorizedItem::PublicKey(key));
                }
            } else {
                authorized_items.insert(AuthorizedItem::PublicKey(key));
            }
        }

        self.authorized_items = authorized_items;
    }
}
