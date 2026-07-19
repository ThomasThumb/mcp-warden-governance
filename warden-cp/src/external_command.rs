use serde::{de::DeserializeOwned, Serialize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;
use wait_timeout::ChildExt;

const MAX_COMMAND_STDOUT_BYTES: usize = 1024 * 1024;
const MAX_COMMAND_STDERR_BYTES: usize = 64 * 1024;

#[derive(Clone)]
pub struct ExternalCommand {
    program: PathBuf,
    args: Vec<String>,
    env: HashMap<String, String>,
    timeout: Duration,
}

impl ExternalCommand {
    pub fn from_env(
        command_var: &str,
        args_var: &str,
        env_from_var: &str,
        timeout_var: &str,
        default_timeout_ms: u64,
    ) -> anyhow::Result<Option<Self>> {
        let Some(program) = std::env::var(command_var)
            .ok()
            .filter(|value| !value.trim().is_empty())
        else {
            return Ok(None);
        };
        let program = PathBuf::from(program);
        if !program.is_absolute() {
            anyhow::bail!("{command_var} must be an absolute executable path");
        }
        let args = std::env::var(args_var)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(|value| serde_json::from_str::<Vec<String>>(&value))
            .transpose()
            .map_err(|e| anyhow::anyhow!("{args_var} must be a JSON string array: {e}"))?
            .unwrap_or_default();
        let env_from = std::env::var(env_from_var)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(|value| serde_json::from_str::<HashMap<String, String>>(&value))
            .transpose()
            .map_err(|e| anyhow::anyhow!("{env_from_var} must be a JSON string map: {e}"))?
            .unwrap_or_default();
        let mut env = HashMap::new();
        for (child_name, parent_name) in env_from {
            validate_env_name(&child_name)?;
            validate_env_name(&parent_name)?;
            let value = std::env::var(&parent_name).map_err(|_| {
                anyhow::anyhow!(
                    "{env_from_var} requires missing parent environment variable {parent_name}"
                )
            })?;
            env.insert(child_name, value);
        }
        let timeout_ms = match std::env::var(timeout_var) {
            Ok(value) => value.parse::<u64>().map_err(|_| {
                anyhow::anyhow!("{timeout_var} must be an integer number of milliseconds")
            })?,
            Err(std::env::VarError::NotPresent) => default_timeout_ms,
            Err(e) => return Err(e.into()),
        };
        if !(1..=30_000).contains(&timeout_ms) {
            anyhow::bail!("{timeout_var} must be between 1 and 30000 milliseconds");
        }
        Ok(Some(Self {
            program,
            args,
            env,
            timeout: Duration::from_millis(timeout_ms),
        }))
    }

    pub fn run_json<Req, Resp>(&self, request: &Req) -> anyhow::Result<Resp>
    where
        Req: Serialize,
        Resp: DeserializeOwned,
    {
        let mut child = Command::new(&self.program)
            .args(&self.args)
            .env_clear()
            .envs(&self.env)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow::anyhow!("starting external command {:?}: {e}", self.program))?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("external command stdout was not piped"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| anyhow::anyhow!("external command stderr was not piped"))?;
        // Drain both pipes concurrently. Waiting before reading lets an
        // untrusted adapter deadlock the parent by filling an OS pipe buffer.
        let stdout_reader =
            std::thread::spawn(move || read_limited(stdout, MAX_COMMAND_STDOUT_BYTES));
        let stderr_reader =
            std::thread::spawn(move || read_limited(stderr, MAX_COMMAND_STDERR_BYTES));

        {
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| anyhow::anyhow!("external command stdin was not piped"))?;
            serde_json::to_writer(&mut stdin, request)?;
            stdin.write_all(b"\n")?;
        }

        let wait_result = child.wait_timeout(self.timeout)?;
        let timed_out = wait_result.is_none();
        let status = match wait_result {
            Some(status) => status,
            None => {
                let _ = child.kill();
                child.wait()?
            }
        };
        let stdout = stdout_reader
            .join()
            .map_err(|_| anyhow::anyhow!("external command stdout reader panicked"))??;
        let stderr = stderr_reader
            .join()
            .map_err(|_| anyhow::anyhow!("external command stderr reader panicked"))??;

        if timed_out {
            anyhow::bail!(
                "external command {:?} timed out after {} ms",
                self.program,
                self.timeout.as_millis()
            );
        }
        if !status.success() {
            anyhow::bail!(
                "external command {:?} exited with {status}: {}",
                self.program,
                String::from_utf8_lossy(&stderr).trim()
            );
        }

        serde_json::from_slice(&stdout)
            .map_err(|e| anyhow::anyhow!("external command returned invalid JSON: {e}"))
    }
}

fn read_limited(reader: impl Read, limit: usize) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(limit.min(16 * 1024));
    reader
        .take(limit.saturating_add(1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("external command output exceeds the {limit}-byte limit"),
        ));
    }
    Ok(bytes)
}

fn validate_env_name(value: &str) -> anyhow::Result<()> {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        anyhow::bail!("environment variable name must not be empty");
    };
    if !(first.is_ascii_alphabetic() || first == b'_')
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        anyhow::bail!("invalid environment variable name '{value}'");
    }
    Ok(())
}
