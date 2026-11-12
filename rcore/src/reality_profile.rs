//! Bounded target/SNI/ALPN probe cache; failures complete with safe fallback values.
use crate::reality_probe::ProbeResult;
use std::{
    collections::HashMap,
    future::Future,
    sync::{Arc, LazyLock, Mutex},
    time::Duration,
};
use tokio::sync::{OnceCell, Semaphore};

#[derive(Clone, Default)]
pub struct Profiles(Arc<Mutex<ProfileMap>>);
type ProfileMap = HashMap<(String, String, u8), Arc<OnceCell<ProbeResult>>>;

static PROBE_SLOTS: LazyLock<Semaphore> = LazyLock::new(|| Semaphore::new(8));

impl Profiles {
    fn cell(&self, dest: &str, name: &str, alpn: u8) -> Arc<OnceCell<ProbeResult>> {
        self.0
            .lock()
            .expect("probe cache lock")
            .entry((dest.to_owned(), name.to_owned(), alpn))
            .or_default()
            .clone()
    }

    pub async fn get(&self, dest: &str, name: &str, alpn: u8) -> ProbeResult {
        let cell = self.cell(dest, name, alpn);
        resolve(&cell, async {
            let _slot = PROBE_SLOTS.acquire().await?;
            crate::reality_probe::probe(dest, name, alpn).await
        })
        .await
    }
}

async fn resolve(
    cell: &OnceCell<ProbeResult>,
    probe: impl Future<Output = anyhow::Result<ProbeResult>>,
) -> ProbeResult {
    resolve_with_timeout(cell, probe, Duration::from_secs(12)).await
}

async fn resolve_with_timeout(
    cell: &OnceCell<ProbeResult>,
    probe: impl Future<Output = anyhow::Result<ProbeResult>>,
    limit: Duration,
) -> ProbeResult {
    let initialization = cell.get_or_init(|| async {
        match tokio::time::timeout(limit, probe).await {
            Ok(Ok(profile)) => profile,
            Ok(Err(error)) => {
                tracing::debug!(%error,"REALITY target probing failed");
                ProbeResult::default()
            }
            Err(_) => {
                tracing::debug!("REALITY target probing timed out");
                ProbeResult::default()
            }
        }
    });
    match tokio::time::timeout(limit, initialization).await {
        Ok(profile) => profile.clone(),
        Err(_) => {
            let fallback = ProbeResult::default();
            // A canceled initializer releases the cell; preserve a completed failure for future clients.
            let _ = cell.set(fallback.clone());
            fallback
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };
    #[tokio::test]
    async fn concurrent_clients_probe_once_and_failures_are_cached() {
        let cache = Profiles::default();
        let calls = Arc::new(AtomicUsize::new(0));
        let profile = cache.cell("target", "test", 2);
        let a = calls.clone();
        let b = calls.clone();
        let make = |count: Arc<AtomicUsize>| async move {
            count.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(5)).await;
            anyhow::bail!("offline")
        };
        let (first, second) = tokio::join!(resolve(&profile, make(a)), resolve(&profile, make(b)));
        assert!(first.records.is_empty() && second.records.is_empty());
        assert_eq!(first.max_ccs, 32);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(!Arc::ptr_eq(&profile, &cache.cell("target", "test", 1)));
        assert!(!Arc::ptr_eq(&profile, &cache.cell("target", "other", 2)));
        assert!(Arc::ptr_eq(&profile, &cache.cell("target", "test", 2)));
        assert!(!Arc::ptr_eq(
            &profile,
            &cache.cell("different-target", "test", 2)
        ));
    }
    #[tokio::test]
    async fn probe_timeout_does_not_leave_clients_waiting() {
        let cell = Arc::new(OnceCell::new());
        let result =
            resolve_with_timeout(&cell, std::future::pending(), Duration::from_millis(5)).await;
        assert_eq!(result.max_ccs, 32);
        assert!(cell.initialized());
    }
    #[tokio::test]
    async fn waiter_keeps_its_own_deadline_during_another_initialization() {
        let cell = Arc::new(OnceCell::new());
        let initializing = cell.clone();
        let (entered, started) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            resolve_with_timeout(
                &initializing,
                async {
                    entered.send(()).unwrap();
                    std::future::pending().await
                },
                Duration::from_secs(100),
            )
            .await
        });
        started.await.unwrap();
        let result = tokio::time::timeout(
            Duration::from_millis(50),
            resolve_with_timeout(&cell, std::future::pending(), Duration::from_millis(5)),
        )
        .await;
        task.abort();
        assert!(result.is_ok(), "waiter ignored its own probe deadline");
    }
}
