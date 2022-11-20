use std::{
    fmt,
    process::{Command, Output},
};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("SSH command failed: {command} ({error})")]
    CommandFailed { command: String, error: String },
    #[error("SSH failed to read file {path}")]
    ReadFile { path: String },
    #[error("SSH failed to write file {path}")]
    WriteFile { path: String },
}

type Result<T> = std::result::Result<T, Error>;

pub struct SshConnection {
    hostname: String,
    user: String,
}

impl SshConnection {
    pub fn new(hostname: String, user: String) -> Self {
        SshConnection { hostname, user }
    }

    fn execute(&self, command: String) -> Result<Output> {
        let output = Command::new("ssh")
            .arg(format!("{}@{}", self.user, self.hostname))
            .arg(&command)
            .output()
            .map_err(|e| Error::CommandFailed {
                command: command.clone(),
                error: e.to_string(),
            })?;

        if !output.status.success() {
            return Err(Error::CommandFailed {
                command,
                error: String::from_utf8(output.stderr).unwrap_or_default(),
            });
        }

        Ok(output)
    }

    pub fn read_file(&self, path: String) -> Result<String> {
        let command = format!("cat \"{}\"", path);
        let output = self.execute(command)?;
        let text = String::from_utf8(output.stdout).map_err(|_| Error::ReadFile { path })?;
        Ok(text)
    }

    pub fn write_file(&self, path: String, text: String) -> Result<()> {
        let command = format!("cat > \"{}\" <<EOT\n{}\nEOT", path, text);
        self.execute(command)
            .map(|_| ())
            .map_err(|_| Error::WriteFile { path })
    }
}

impl fmt::Display for SshConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.user, self.hostname)
    }
}
