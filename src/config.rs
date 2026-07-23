//! Operator configuration: where the relay lives. One small TOML file —
//! `<OS config dir>/b2p/config.toml` — written by `b2p relay set`, read by
//! the default receive/send path. Env (`B2P_RELAY`, `B2P_RELAY_TOKEN`) and
//! `--relay` override it; a host embedded in a `b2p://` code overrides
//! everything except the flag (both peers must meet at the SAME relay, and
//! the code says where the receiver actually is).

use crate::transport::relay::normalize_relay_url;
use anyhow::Context;
use std::path::PathBuf;

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
pub struct Config {
    pub relay: Option<String>,
    pub relay_token: Option<String>,
}

#[derive(Debug)]
pub struct RelayCfg {
    pub url: String,
    pub token: Option<String>,
}

pub fn path() -> anyhow::Result<PathBuf> {
    let dirs = directories::ProjectDirs::from("", "", "b2p")
        .context("cannot determine the OS config directory")?;
    Ok(dirs.config_dir().join("config.toml"))
}

pub fn load() -> anyhow::Result<Config> {
    let p = path()?;
    match std::fs::read_to_string(&p) {
        Ok(s) => toml::from_str(&s).with_context(|| format!("parsing {}", p.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
        Err(e) => Err(e).with_context(|| format!("reading {}", p.display())),
    }
}

pub fn save(cfg: &Config) -> anyhow::Result<PathBuf> {
    let p = path()?;
    std::fs::create_dir_all(p.parent().expect("has parent"))?;
    std::fs::write(&p, toml::to_string_pretty(cfg)?)?;
    Ok(p)
}

/// URL precedence: `--relay` flag > host embedded in the code > `B2P_RELAY`
/// env > config file > a clear error. Token precedence: env > file.
pub fn resolve_relay(
    flag: Option<&str>,
    code_host: Option<&str>,
    env_url: Option<&str>,
    env_token: Option<&str>,
    file: &Config,
) -> anyhow::Result<RelayCfg> {
    let url = if let Some(f) = flag {
        normalize_relay_url(f)?
    } else if let Some(h) = code_host {
        let h = if h.contains("://") {
            h.to_string()
        } else {
            format!("wss://{h}")
        };
        normalize_relay_url(&h)?
    } else if let Some(e) = env_url {
        normalize_relay_url(e)?
    } else if let Some(f) = &file.relay {
        normalize_relay_url(f)?
    } else {
        anyhow::bail!(
            "no relay configured — deploy relay-worker/ once (npx wrangler deploy), then run: \
             b2p relay set wss://<your-worker>.workers.dev  (or pass --relay / set B2P_RELAY)"
        );
    };
    let token = env_token
        .map(str::to_string)
        .or_else(|| file.relay_token.clone());
    Ok(RelayCfg { url, token })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precedence_flag_beats_code_beats_env_beats_file() {
        let file = Config {
            relay: Some("wss://file.example".into()),
            relay_token: Some("ft".into()),
        };
        let r = resolve_relay(
            Some("wss://flag.example"),
            Some("code.example"),
            Some("wss://env.example"),
            None,
            &file,
        )
        .unwrap();
        assert_eq!(r.url, "wss://flag.example");
        let r = resolve_relay(
            None,
            Some("code.example"),
            Some("wss://env.example"),
            None,
            &file,
        )
        .unwrap();
        assert_eq!(r.url, "wss://code.example");
        let r = resolve_relay(None, None, Some("wss://env.example"), None, &file).unwrap();
        assert_eq!(r.url, "wss://env.example");
        let r = resolve_relay(None, None, None, None, &file).unwrap();
        assert_eq!(r.url, "wss://file.example");
        assert_eq!(r.token.as_deref(), Some("ft"));
    }

    #[test]
    fn env_token_beats_file_token() {
        let file = Config {
            relay: Some("wss://x".into()),
            relay_token: Some("ft".into()),
        };
        let r = resolve_relay(None, None, None, Some("et"), &file).unwrap();
        assert_eq!(r.token.as_deref(), Some("et"));
    }

    #[test]
    fn unconfigured_is_a_clear_error() {
        let e = resolve_relay(None, None, None, None, &Config::default()).unwrap_err();
        assert!(e.to_string().contains("b2p relay set"), "got: {e}");
    }

    #[test]
    fn https_is_normalized_and_garbage_rejected() {
        let file = Config::default();
        let r = resolve_relay(Some("https://x.dev/"), None, None, None, &file).unwrap();
        assert_eq!(r.url, "wss://x.dev");
        assert!(resolve_relay(Some("ftp://x"), None, None, None, &file).is_err());
    }

    #[test]
    fn config_round_trips_toml() {
        let c = Config {
            relay: Some("wss://a".into()),
            relay_token: None,
        };
        let s = toml::to_string(&c).unwrap();
        let back: Config = toml::from_str(&s).unwrap();
        assert_eq!(back.relay.as_deref(), Some("wss://a"));
    }
}
