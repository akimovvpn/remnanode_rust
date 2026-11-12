//! Port of xray-core app/stats: named counters and per-user online IP maps.
use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicI64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Default)]
pub struct Counter(AtomicI64);

impl Counter {
    pub fn add(&self, delta: i64) {
        self.0.fetch_add(delta, Ordering::Relaxed);
    }
    pub fn value(&self) -> i64 {
        self.0.load(Ordering::Relaxed)
    }
    /// Sets a new value and returns the previous one (Go Counter.Set).
    pub fn set(&self, value: i64) -> i64 {
        self.0.swap(value, Ordering::Relaxed)
    }
}

#[derive(Default)]
pub struct OnlineMap {
    entries: Mutex<HashMap<String, (i32, i64)>>,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

impl OnlineMap {
    pub fn add_ip(&self, ip: &str) {
        // Go skips "127.0.0.1" and "[::1]" (net.Address.String of IPv6 loopback).
        if ip == "127.0.0.1" || ip == "[::1]" {
            return;
        }
        let mut entries = self.entries.lock().unwrap();
        let entry = entries.entry(ip.to_owned()).or_insert((0, 0));
        entry.0 += 1;
        entry.1 = now();
    }
    pub fn remove_ip(&self, ip: &str) {
        let mut entries = self.entries.lock().unwrap();
        if let Some(entry) = entries.get_mut(ip) {
            entry.0 -= 1;
            if entry.0 <= 0 {
                entries.remove(ip);
            }
        }
    }
    pub fn count(&self) -> usize {
        self.entries.lock().unwrap().len()
    }
    pub fn ips(&self) -> Vec<(String, i64)> {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .map(|(ip, (_, seen))| (ip.clone(), *seen))
            .collect()
    }
}

#[derive(Default)]
pub struct Stats {
    counters: RwLock<BTreeMap<String, Arc<Counter>>>,
    online: RwLock<BTreeMap<String, Arc<OnlineMap>>>,
}

impl Stats {
    pub fn counter(&self, name: &str) -> Arc<Counter> {
        if let Some(counter) = self.counters.read().unwrap().get(name) {
            return counter.clone();
        }
        self.counters
            .write()
            .unwrap()
            .entry(name.to_owned())
            .or_default()
            .clone()
    }
    pub fn get_counter(&self, name: &str) -> Option<Arc<Counter>> {
        self.counters.read().unwrap().get(name).cloned()
    }
    pub fn counters(&self) -> Vec<(String, Arc<Counter>)> {
        self.counters
            .read()
            .unwrap()
            .iter()
            .map(|(name, c)| (name.clone(), c.clone()))
            .collect()
    }
    pub fn online_map(&self, name: &str) -> Arc<OnlineMap> {
        if let Some(map) = self.online.read().unwrap().get(name) {
            return map.clone();
        }
        self.online
            .write()
            .unwrap()
            .entry(name.to_owned())
            .or_default()
            .clone()
    }
    pub fn get_online_map(&self, name: &str) -> Option<Arc<OnlineMap>> {
        self.online.read().unwrap().get(name).cloned()
    }
    pub fn online_maps(&self) -> Vec<(String, Arc<OnlineMap>)> {
        self.online
            .read()
            .unwrap()
            .iter()
            .map(|(name, m)| (name.clone(), m.clone()))
            .collect()
    }
}

/// Keeps a user's source IP in its online map for the life of a session (Go trackOnlineIP).
pub struct OnlineGuard {
    map: Arc<OnlineMap>,
    ip: String,
}

impl OnlineGuard {
    pub fn new(stats: &Stats, email: &str, ip: String) -> Self {
        let map = stats.online_map(&format!("user>>>{email}>>>online"));
        map.add_ip(&ip);
        Self { map, ip }
    }
}

impl Drop for OnlineGuard {
    fn drop(&mut self) {
        self.map.remove_ip(&self.ip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn online_map_refcounts_and_skips_loopback() {
        let stats = Stats::default();
        let a = OnlineGuard::new(&stats, "u", "1.2.3.4".into());
        let b = OnlineGuard::new(&stats, "u", "1.2.3.4".into());
        let _l = OnlineGuard::new(&stats, "u", "127.0.0.1".into());
        let map = stats.get_online_map("user>>>u>>>online").unwrap();
        assert_eq!(map.count(), 1);
        drop(a);
        assert_eq!(map.count(), 1);
        drop(b);
        assert_eq!(map.count(), 0);
        let c = stats.counter("x");
        c.add(5);
        assert_eq!(c.set(0), 5);
        assert_eq!(c.value(), 0);
    }
}
