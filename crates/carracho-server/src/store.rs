//! Persistent server data: settings, accounts and news, kept as JSON files in
//! the data directory. Text is stored decoded from Mac Roman.

use std::fs;
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use anyhow::Context;
use carracho_proto::{macroman, mactime};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// Server settings (protocol.md, 4.12). Defaults match a fresh original
/// server.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub name: String,
    pub location: String,
    pub operator: String,
    pub description: String,
    /// Shown to users at login; empty for none.
    pub agreement: String,
    pub port: u16,
    /// Time of day to expire old newsgroup articles, `(hour << 8) | minute`, GMT.
    pub news_expire_time: u16,
    pub max_transfers: u16,
    pub max_transfers_per_user: u16,
    pub max_users: u16,
    pub max_connections_per_ip: u16,
    /// Deepest folder level included in folder downloads.
    pub folder_depth: i16,
    pub ip_rules: Vec<IpRule>,
    pub trackers: Vec<TrackerEntry>,
    pub tracker_flags: u32,
    pub tracker_description: String,
    pub banner_url: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            name: "Carracho Server".into(),
            location: "unknown".into(),
            operator: "unknown".into(),
            description: String::new(),
            agreement: String::new(),
            port: carracho_proto::packet::PORT,
            news_expire_time: 0,
            max_transfers: 20,
            max_transfers_per_user: 1,
            max_users: 100,
            max_connections_per_ip: 5,
            folder_depth: 1,
            ip_rules: Vec::new(),
            trackers: Vec::new(),
            tracker_flags: 0,
            tracker_description: String::new(),
            banner_url: String::new(),
        }
    }
}

/// One entry of the IP allow/deny list.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IpRule {
    pub address: Ipv4Addr,
    pub mask: Ipv4Addr,
    pub deny: bool,
}

impl Settings {
    /// Whether a connection from `ip` is allowed: the first matching rule
    /// decides, and addresses matching no rule are allowed.
    pub fn allows(&self, ip: Ipv4Addr) -> bool {
        let ip = u32::from(ip);
        for rule in &self.ip_rules {
            if ip & u32::from(rule.mask) == u32::from(rule.address) {
                return !rule.deny;
            }
        }
        true
    }
}

/// A tracker the server registers with.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrackerEntry {
    pub name: String,
    pub host: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Account {
    pub login: String,
    pub real_name: String,
    /// Stored as given: the login protocol needs the plain password.
    pub password: String,
    pub created: u32,
    pub modified: u32,
    pub last_login: u32,
    pub privileges: u64,
}

impl Account {
    pub fn to_record(&self) -> carracho_proto::account::Record {
        carracho_proto::account::Record {
            login: macroman::encode(&self.login),
            real_name: macroman::encode(&self.real_name),
            password: macroman::encode(&self.password),
            created: self.created,
            modified: self.modified,
            last_login: self.last_login,
            privileges: self.privileges,
        }
    }
}

/// The accounts a fresh original server ships with.
fn default_accounts() -> Vec<Account> {
    let now = mactime::now();
    let account = |login: &str, real_name: &str, privileges| Account {
        login: login.into(),
        real_name: real_name.into(),
        password: String::new(),
        created: now,
        modified: now,
        last_login: 0,
        privileges,
    };
    vec![
        account("admin", "Administrator", 0x803f_ffc8_7daf_8000),
        account("anonymous", "Guest", 0x0030_0008_0001_8000),
    ]
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Newsgroup {
    pub name: String,
    pub expiry: u32,
    pub permissions: u16,
    pub next_id: u32,
    pub articles: Vec<Article>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Article {
    pub id: u32,
    /// Parent article, or `0xFFFFFFFF` for a new thread.
    pub parent: u32,
    pub subject: String,
    pub author: String,
    pub date: u32,
    pub text: String,
    /// Text styles in the Mac OS `styl` format, passed through unchanged.
    pub styles: Vec<u8>,
}

/// Newsgroup permission bits (protocol.md, 4.18).
pub mod group_perm {
    pub const ADMIN_POST: u16 = 0x8000;
    pub const ADMIN_READ: u16 = 0x4000;
    pub const HOLDER_POST: u16 = 0x2000;
    pub const HOLDER_READ: u16 = 0x1000;
    pub const GUEST_POST: u16 = 0x0800;
    pub const GUEST_READ: u16 = 0x0400;
}

pub struct Store {
    dir: PathBuf,
    pub settings: Settings,
    pub accounts: Vec<Account>,
    pub flat_news: Vec<String>,
    pub newsgroups: Vec<Newsgroup>,
}

const SETTINGS: &str = "settings.json";
const ACCOUNTS: &str = "accounts.json";
const FLAT_NEWS: &str = "flatnews.json";
const NEWSGROUPS: &str = "newsgroups.json";
const BANNER: &str = "banner.png";

impl Store {
    /// Load the store from `dir`, creating any missing file with defaults.
    pub fn open(dir: &Path) -> anyhow::Result<Self> {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        let store = Self {
            dir: dir.to_path_buf(),
            settings: load_or(dir, SETTINGS, Settings::default)?,
            accounts: load_or(dir, ACCOUNTS, default_accounts)?,
            flat_news: load_or(dir, FLAT_NEWS, Vec::new)?,
            newsgroups: load_or(dir, NEWSGROUPS, Vec::new)?,
        };
        store.save_settings()?;
        store.save_accounts()?;
        Ok(store)
    }

    pub fn save_settings(&self) -> anyhow::Result<()> {
        save(&self.dir, SETTINGS, &self.settings)
    }

    pub fn save_accounts(&self) -> anyhow::Result<()> {
        save(&self.dir, ACCOUNTS, &self.accounts)
    }

    pub fn save_flat_news(&self) -> anyhow::Result<()> {
        save(&self.dir, FLAT_NEWS, &self.flat_news)
    }

    pub fn save_newsgroups(&self) -> anyhow::Result<()> {
        save(&self.dir, NEWSGROUPS, &self.newsgroups)
    }

    /// Account by login name, compared case-insensitively as the original
    /// does.
    pub fn account(&self, login: &str) -> Option<&Account> {
        self.accounts.iter().find(|a| a.login.eq_ignore_ascii_case(login))
    }

    pub fn account_mut(&mut self, login: &str) -> Option<&mut Account> {
        self.accounts.iter_mut().find(|a| a.login.eq_ignore_ascii_case(login))
    }

    pub fn newsgroup(&self, name: &str) -> Option<&Newsgroup> {
        self.newsgroups.iter().find(|g| g.name.eq_ignore_ascii_case(name))
    }

    pub fn newsgroup_mut(&mut self, name: &str) -> Option<&mut Newsgroup> {
        self.newsgroups.iter_mut().find(|g| g.name.eq_ignore_ascii_case(name))
    }

    pub fn banner(&self) -> Option<Vec<u8>> {
        fs::read(self.dir.join(BANNER)).ok()
    }

    pub fn set_banner(&self, png: &[u8]) -> anyhow::Result<()> {
        write_atomic(&self.dir.join(BANNER), png)
    }
}

fn load_or<T: DeserializeOwned>(dir: &Path, name: &str, default: impl FnOnce() -> T) -> anyhow::Result<T> {
    let path = dir.join(name);
    match fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(default()),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

fn save<T: Serialize>(dir: &Path, name: &str, value: &T) -> anyhow::Result<()> {
    let json = serde_json::to_vec_pretty(value)?;
    write_atomic(&dir.join(name), &json)
}

/// Write via a temporary file and rename, so a crash never leaves a
/// half-written file. Files are private to the server's user: the accounts
/// file holds passwords.
fn write_atomic(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(&tmp).with_context(|| format!("writing {}", tmp.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_store_has_default_accounts_and_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(dir.path()).unwrap();
        assert_eq!(store.settings.name, "Carracho Server");
        assert!(store.account("ADMIN").is_some(), "logins compare case-insensitively");
        store.settings.location = "Basement".into();
        store.save_settings().unwrap();
        let again = Store::open(dir.path()).unwrap();
        assert_eq!(again.settings.location, "Basement");
        assert_eq!(again.accounts.len(), 2);
    }

    #[test]
    fn first_matching_ip_rule_decides() {
        let mut s = Settings::default();
        assert!(s.allows(Ipv4Addr::new(10, 0, 0, 1)));
        s.ip_rules = vec![
            IpRule { address: Ipv4Addr::new(10, 0, 0, 1), mask: Ipv4Addr::BROADCAST, deny: false },
            IpRule { address: Ipv4Addr::new(10, 0, 0, 0), mask: Ipv4Addr::new(255, 0, 0, 0), deny: true },
        ];
        assert!(s.allows(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!s.allows(Ipv4Addr::new(10, 9, 9, 9)));
        assert!(s.allows(Ipv4Addr::new(192, 168, 0, 1)));
    }
}
