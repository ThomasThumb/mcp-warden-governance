use serde::{de::DeserializeOwned, Serialize};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;
use wait_timeout::ChildExt;

#[derive(Clone)]
pub struct ExternalCommand {
    program: PathBuf,
    args: Vec<String>,
    timeout: Duration,
}

impl ExternalCommand {
    pub fn from_env(
        command_var: &str,
        args_var: &str,
        timeout_var: &str,
        default_timeout_ms: u64,
    ) -> anyhow::Result<Option<Self>> {
        let Some(program) = std::env::var(command_var)
            .ok()
            .filter(|value| !value.trim().is_empty())
        else {
            return Ok(None);
        };
        let args = std::env::var(args_var)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(|value| serde_json::from_str::<Vec<String>>(&value))
            .transpose()
            .map_err(|e| anyhow::anyhow!("{args_var} must be a JSON string array: {e}"))?
            .unwrap_or_default();
        let timeout_ms = std::env::var(timeout_var)
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(default_timeout_ms);
        Ok(Some(Self {
            program: PathBuf::from(program),
            args,
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
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow::anyhow!("starting external command {:?}: {e}", self.program))?;

        {
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| anyhow::anyhow!("external command stdin was not piped"))?;
            serde_json::to_writer(&mut stdin, request)?;
            stdin.write_all(b"\n")?;
        }

        match child.wait_timeout(self.timeout)? {
            Some(status) if status.success() => {}
            Some(status) => {
                let output = child.wait_with_output()?;
                anyhow::bail!(
                    "external command {:?} exited with {status}: {}",
                    self.program,
                    String::from_utf8_lossy(&output.stderr).trim()
                );
            }
            None => {
                let _ = child.kill();
                let _ = child.wait();
                anyhow::bail!(
                    "external command {:?} timed out after {} ms",
                    self.program,
                    self.timeout.as_millis()
                );
            }
        }

        let output = child.wait_with_output()?;
        serde_json::from_slice(&output.stdout)
            .map_err(|e| anyhow::anyhow!("external command returned invalid JSON: {e}"))
    }
}
