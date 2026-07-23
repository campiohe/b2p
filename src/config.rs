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
/// env > config file > a clear error. Token precedence: env > file — but the
/// token is attached ONLY when the winning URL is one the user configured
/// themselves (flag/env/file), or a code-embedded host that MATCHES their
/// configured relay. A `b2p://` code names an arbitrary host chosen by
/// whoever produced the code; sending the user's bearer token there would
/// hand it to a stranger's server.
pub fn resolve_relay(
    flag: Option<&str>,
    code_host: Option<&str>,
    env_url: Option<&str>,
    env_token: Option<&str>,
    file: &Config,
) -> anyhow::Result<RelayCfg> {
    // The user's own relay, if any (flag > env > file) — both a resolution
    // fallback and the only destination the token may travel to.
    let own: Option<String> = if let Some(f) = flag {
        Some(normalize_relay_url(f)?)
    } else if let Some(e) = env_url {
        Some(normalize_relay_url(e)?)
    } else if let Some(f) = &file.relay {
        Some(normalize_relay_url(f)?)
    } else {
        None
    };

    let (url, trusted) = if let Some(f) = flag {
        (normalize_relay_url(f)?, true)
    } else if let Some(h) = code_host {
        let h = if h.contains("://") {
            h.to_string()
        } else {
            format!("wss://{h}")
        };
        let url = normalize_relay_url(&h)?;
        let matches_own = own.as_deref() == Some(url.as_str());
        (url, matches_own)
    } else if let Some(own) = own.clone() {
        (own, true)
    } else {
        anyhow::bail!(
            "no relay configured — deploy relay-worker/ once (npx wrangler deploy), then run: \
             b2p relay set wss://<your-worker>.workers.dev  (or pass --relay / set B2P_RELAY)"
        );
    };
    let token = if trusted {
        env_token
            .map(str::to_string)
            .or_else(|| file.relay_token.clone())
    } else {
        None
    };
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
    fn token_never_travels_to_a_foreign_code_host() {
        // A b2p:// code names a host chosen by whoever made the code — the
        // user's configured bearer token must not be sent there.
        let file = Config {
            relay: Some("wss://my.relay".into()),
            relay_token: Some("secret".into()),
        };
        let foreign = resolve_relay(None, Some("attacker.example"), None, None, &file).unwrap();
        assert_eq!(foreign.url, "wss://attacker.example");
        assert_eq!(foreign.token, None, "token leaked to a code-chosen host");
        // ...but a code naming the user's OWN relay keeps the token.
        let own = resolve_relay(None, Some("my.relay"), None, None, &file).unwrap();
        assert_eq!(own.url, "wss://my.relay");
        assert_eq!(own.token.as_deref(), Some("secret"));
        // env token with no configured URL: still never to a code host.
        let bare = Config::default();
        let r = resolve_relay(None, Some("x.example"), None, Some("et"), &bare).unwrap();
        assert_eq!(r.token, None);
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
