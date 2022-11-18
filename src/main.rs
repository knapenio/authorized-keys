use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{BufRead, BufReader, Cursor},
    process,
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
    hosts: HashMap<String, Vec<User>>,
}

#[derive(Deserialize, Serialize)]
struct User {
    #[serde(rename = "user")]
    name: String,
    identity_file: String,
    authorized_keys: Vec<String>,
}

#[derive(thiserror::Error, Debug)]
enum Error {
    #[error("failed to read config file {path}")]
    FailedToReadConfig { path: String },
    #[error("failed to write config file {path}")]
    FailedToWriteConfig { path: String },
    #[error("failed to read authorized keys from {path} (via {user}@{hostname})")]
    FailedToReadAuthorizedKeys {
        hostname: String,
        user: String,
        path: String,
    },
    #[error("failed to write authorized keys to {path} (via {user}@{hostname})")]
    FailedToWriteAuthorizedKeys {
        hostname: String,
        user: String,
        path: String,
    },
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

    for (hostname, users) in config.hosts {
        for user in users {
            write_authorized_keys(
                hostname.clone(),
                user.name,
                user.identity_file,
                user.authorized_keys,
            )?;
        }
    }

    Ok(())
}

fn pull_config(path: String) -> Result<()> {
    let mut config = read_config(path.clone())?;

    for (hostname, users) in config.hosts.iter_mut() {
        for user in users {
            let authorized_keys = read_authorized_keys(
                hostname.clone(),
                user.name.clone(),
                user.identity_file.clone(),
            )?;
            user.authorized_keys = authorized_keys;
        }
    }

    write_config(path, &config)?;

    Ok(())
}

fn audit_config(path: String) -> Result<()> {
    let config = read_config(path)?;

    for (hostname, users) in config.hosts {
        for user in users {
            let authorized_keys = read_authorized_keys(
                hostname.clone(),
                user.name.clone(),
                user.identity_file.clone(),
            )?;
            let authorized_keys: HashSet<_> = authorized_keys.into_iter().collect();
            let known_keys: HashSet<_> = user.authorized_keys.into_iter().collect();
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
                    user: user.name.clone(),
                    path: user.identity_file.clone(),
                })?;
            }
        }
    }

    Ok(())
}

fn read_config(path: String) -> Result<Config> {
    let file = File::open(&path)?;
    let config = serde_yaml::from_reader(BufReader::new(file))
        .map_err(|_| Error::FailedToReadConfig { path })?;
    Ok(config)
}

fn write_config(path: String, config: &Config) -> Result<()> {
    let file = File::options()
        .write(true)
        .truncate(true)
        .create(true)
        .open(&path)?;
    serde_yaml::to_writer(file, config).map_err(|_| Error::FailedToWriteConfig { path })?;
    Ok(())
}

fn read_authorized_keys(
    hostname: String,
    user: String,
    identity_file: String,
) -> Result<Vec<String>> {
    let command = format!("cat \"{}\"", identity_file);

    let output = process::Command::new("ssh")
        .arg(format!("{}@{}", user, hostname))
        .arg(command)
        .output()
        .map_err(|_| Error::FailedToReadAuthorizedKeys {
            hostname: hostname.clone(),
            user: user.clone(),
            path: identity_file.clone(),
        })?;

    println!(
        "successfully read authorized keys from {} (via {}@{})",
        identity_file, user, hostname
    );

    let cursor = Cursor::new(output.stdout);
    let lines = cursor.lines();

    Ok(lines
        .into_iter()
        .map(|res| res.unwrap_or_default())
        .filter(|line| !line.is_empty())
        .collect())
}

fn write_authorized_keys(
    hostname: String,
    user: String,
    identity_file: String,
    authorized_keys: Vec<String>,
) -> Result<()> {
    let command = format!(
        "cat > \"{}\" <<EOT\n{}\nEOT",
        identity_file,
        authorized_keys.join("\n")
    );

    let status = process::Command::new("ssh")
        .arg(format!("{}@{}", user, hostname))
        .arg(command)
        .status();

    match status {
        Ok(status) if status.success() => {
            println!(
                "successfully wrote authorized keys to {} (via {}@{})",
                identity_file, user, hostname
            )
        }
        _ => {
            return Err(Error::FailedToWriteAuthorizedKeys {
                hostname,
                user,
                path: identity_file,
            })?
        }
    };

    Ok(())
}
