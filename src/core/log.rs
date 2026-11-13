use super::private_directory;
use anyhow::{Context, Result, ensure};
use std::{
    fs::OpenOptions,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::PathBuf,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

const LIMIT: u64 = 10 * 1024 * 1024;

pub(super) struct Log {
    directory: PathBuf,
    file: tokio::fs::File,
    size: u64,
}

impl Log {
    pub(super) fn open(directory: PathBuf) -> Result<Self> {
        private_directory(&directory)?;
        let path = directory.join("current");
        if let Ok(metadata) = std::fs::symlink_metadata(&path) {
            ensure!(
                metadata.file_type().is_file(),
                "core log must be a regular file"
            );
        }
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(path)
            .context("open core log")?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        let size = file.metadata()?.len();
        Ok(Self {
            directory,
            file: tokio::fs::File::from_std(file),
            size,
        })
    }

    async fn write(&mut self, mut data: &[u8]) -> Result<()> {
        while !data.is_empty() {
            if self.size >= LIMIT {
                self.file.flush().await?;
                tokio::fs::rename(
                    self.directory.join("current"),
                    self.directory.join("previous"),
                )
                .await?;
                *self = Self::open(self.directory.clone())?;
            }
            let n = data.len().min((LIMIT - self.size) as usize);
            self.file.write_all(&data[..n]).await?;
            self.file.flush().await?;
            self.size += n as u64;
            data = &data[n..];
        }
        Ok(())
    }

    pub(super) async fn capture(
        mut self,
        mut stdout: impl AsyncRead + Unpin,
        mut stderr: impl AsyncRead + Unpin,
    ) {
        let (mut out, mut err) = ([0; 8192], [0; 8192]);
        let (mut out_open, mut err_open) = (true, true);
        let mut writable = true;
        while out_open || err_open {
            let read = tokio::select! {
                result = stdout.read(&mut out), if out_open => (result, true),
                result = stderr.read(&mut err), if err_open => (result, false),
            };
            match read {
                (Ok(0), true) => out_open = false,
                (Ok(0), false) => err_open = false,
                (Ok(n), is_out) if writable => {
                    if let Err(error) = self.write(if is_out { &out[..n] } else { &err[..n] }).await
                    {
                        tracing::error!(error=%format!("{error:#}"), "Cannot write core log; discarding core output until restart");
                        writable = false;
                    }
                }
                (Ok(_), _) => {}
                (Err(error), is_out) => {
                    tracing::warn!(%error, "Cannot read core output");
                    if is_out {
                        out_open = false;
                    } else {
                        err_open = false;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn captures_both_streams_and_preserves_logs_across_restarts() {
        let dir = tempfile::tempdir().unwrap();
        let mut child = tokio::process::Command::new("sh")
            .args(["-c", "printf 'core stdout\\n'; printf 'core stderr\\n' >&2"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let log = Log::open(dir.path().to_owned()).unwrap();
        log.capture(child.stdout.take().unwrap(), child.stderr.take().unwrap())
            .await;
        assert!(child.wait().await.unwrap().success());
        let mut log = Log::open(dir.path().to_owned()).unwrap();
        log.write(b"restart\n").await.unwrap();
        let text = std::fs::read_to_string(dir.path().join("current")).unwrap();
        assert!(
            text.contains("core stdout\n")
                && text.contains("core stderr\n")
                && text.ends_with("restart\n")
        );
        assert_eq!(
            std::fs::metadata(dir.path().join("current"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[tokio::test]
    async fn rotates_both_files_at_ten_megabytes_and_keeps_latest_output() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = Log::open(dir.path().to_owned()).unwrap();
        log.write(&vec![b'a'; LIMIT as usize]).await.unwrap();
        log.write(&vec![b'b'; LIMIT as usize]).await.unwrap();
        log.write(b"latest\n").await.unwrap();
        assert_eq!(
            std::fs::read(dir.path().join("previous")).unwrap(),
            vec![b'b'; LIMIT as usize]
        );
        assert_eq!(
            std::fs::read(dir.path().join("current")).unwrap(),
            b"latest\n"
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
    }
}
