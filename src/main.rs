use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
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
}

fn main() -> Result<()> {
    let cli: Cli = Cli::parse();

    match cli.command {
        Command::Push => push_config(cli.config)?,
        Command::Pull => pull_config(cli.config)?,
    }

    Ok(())
}

fn push_config(path: String) -> Result<()> {
    let config = read_config(path)?;

    for (hostname, items) in config.hosts {
        for item in items {
            write_authorized_keys(hostname.clone(), item.user, item.path, item.authorized_keys)?;
        }
    }

    Ok(())
}

fn pull_config(path: String) -> Result<()> {
    let mut config = read_config(path.clone())?;

    for (hostname, items) in config.hosts.iter_mut() {
        for item in items {
            let authorized_keys =
                read_authorized_keys(hostname.clone(), item.user.clone(), item.path.clone())?;
            item.authorized_keys = authorized_keys;
        }
    }

    write_config(path, &config)?;

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

fn read_authorized_keys(hostname: String, user: String, path: String) -> Result<Vec<String>> {
    let command = format!("cat \"{}\"", path);

    let output = process::Command::new("ssh")
        .arg(format!("{}@{}", user, hostname))
        .arg(command)
        .output()
        .map_err(|_| Error::FailedToReadAuthorizedKeys {
            hostname: hostname.clone(),
            user: user.clone(),
            path: path.clone(),
        })?;

    println!(
        "successfully read authorized keys from {} (via {}@{})",
        path, user, hostname
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
    path: String,
    authorized_keys: Vec<String>,
) -> Result<()> {
    let command = format!(
        "cat > \"{}\" <<EOT\n{}\nEOT",
        path,
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
                path, user, hostname
            )
        }
        _ => {
            return Err(Error::FailedToWriteAuthorizedKeys {
                hostname,
                user,
                path: path,
            })?
        }
    };

    Ok(())
}
