mod ssh;

use crate::ssh::SshConnection;
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{BufRead, BufReader, Cursor},
};

type Result<T> = std::result::Result<T, anyhow::Error>;

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
}

#[derive(Deserialize, Serialize)]
struct Item {
    user: String,
    path: String,
    authorized_keys: Vec<String>,
}

#[derive(thiserror::Error, Debug)]
enum Error {
    #[error("failed to read config file {path}")]
    ReadConfig { path: String },
    #[error("failed to write config file {path}")]
    WriteConfig { path: String },
    #[error("failed to read authorized keys")]
    ReadAuthorizedKeys(#[source] ssh::Error),
    #[error("failed to write authorized keys")]
    WriteAuthorizedKeys(#[source] ssh::Error),
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

    for (hostname, items) in config.hosts {
        for item in items {
            let connection = SshConnection::new(hostname.clone(), item.user);
            write_authorized_keys(connection, item.path, item.authorized_keys)?;
        }
    }

    Ok(())
}

fn pull_config(path: String) -> Result<()> {
    let mut config = read_config(path.clone())?;

    for (hostname, items) in config.hosts.iter_mut() {
        for item in items {
            let connection = SshConnection::new(hostname.clone(), item.user.clone());
            let authorized_keys = read_authorized_keys(connection, item.path.clone())?;
            item.authorized_keys = authorized_keys;
        }
    }

    write_config(path, &config)?;

    Ok(())
}

fn audit_config(path: String) -> Result<()> {
    let config = read_config(path)?;

    for (hostname, items) in config.hosts {
        for item in items {
            let connection = SshConnection::new(hostname.clone(), item.user.clone());
            let authorized_keys = read_authorized_keys(connection, item.path.clone())?;
            let authorized_keys: HashSet<_> = authorized_keys.into_iter().collect();
            let known_keys: HashSet<_> = item.authorized_keys.into_iter().collect();
            let unknown_keys: HashSet<_> = authorized_keys.difference(&known_keys).collect();
            let missing_keys: HashSet<_> = known_keys.difference(&authorized_keys).collect();

            if !unknown_keys.is_empty() || !missing_keys.is_empty() {
                for unknown_key in &unknown_keys {
                    eprintln!("found unknown key {}", unknown_key);
                }

                for missing_key in &missing_keys {
                    eprintln!("found missing key {}", missing_key);
                }

                return Err(Error::AuditFailed {
                    hostname: hostname.clone(),
                    user: item.user.clone(),
                    path: item.path.clone(),
                })?;
            }
        }
    }

    Ok(())
}

fn read_config(path: String) -> Result<Config> {
    let file = File::open(&path)?;
    let config =
        serde_yaml::from_reader(BufReader::new(file)).map_err(|_| Error::ReadConfig { path })?;
    Ok(config)
}

fn write_config(path: String, config: &Config) -> Result<()> {
    let file = File::options()
        .write(true)
        .truncate(true)
        .create(true)
        .open(&path)?;
    serde_yaml::to_writer(file, config).map_err(|_| Error::WriteConfig { path })?;
    Ok(())
}

fn read_authorized_keys(connection: SshConnection, path: String) -> Result<Vec<String>> {
    println!(
        "reading authorized keys from {} (via {})...",
        path, connection
    );

    let contents = connection
        .read_file(path.clone())
        .map_err(Error::ReadAuthorizedKeys)?;
    let cursor = Cursor::new(contents);
    let lines: Vec<_> = cursor
        .lines()
        .map(|res| res.unwrap())
        .filter(|line| !line.is_empty())
        .collect();

    println!(
        "successfully read {} authorized keys from {} (via {})",
        lines.len(),
        path,
        connection
    );

    Ok(lines)
}

fn write_authorized_keys(
    connection: SshConnection,
    path: String,
    authorized_keys: Vec<String>,
) -> Result<()> {
    println!(
        "writing authorized keys to {} (via {})...",
        path, connection
    );

    connection
        .write_file(path.clone(), authorized_keys.join("\n"))
        .map_err(Error::WriteAuthorizedKeys)?;

    println!(
        "successfully wrote {} authorized keys to {} (via {})",
        authorized_keys.len(),
        path,
        connection
    );

    Ok(())
}
