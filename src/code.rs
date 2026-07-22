use crate::crypto::Secret;
use anyhow::{bail, Context};
use url::Url;

pub struct Code {
    pub base_url: Url,
    pub secret: Secret,
}

impl Code {
    pub fn new(base_url: Url, secret: Secret) -> Self {
        Code { base_url, secret }
    }

    pub fn parse(s: &str) -> anyhow::Result<Code> {
        let (url_part, frag) = s
            .trim()
            .split_once('#')
            .context("code must look like <url>#<secret>")?;
        let base_url: Url = url_part.parse().context("invalid URL in code")?;
        if base_url.scheme() != "https" && base_url.scheme() != "http" {
            bail!("code URL must be http(s), got {}", base_url.scheme());
        }
        let secret = Secret::from_base58(frag)?;
        Ok(Code { base_url, secret })
    }
}

impl std::fmt::Display for Code {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let url = self.base_url.as_str().trim_end_matches('/');
        write!(f, "{url}#{}", self.secret.to_base58())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Secret;

    #[test]
    fn round_trip() {
        let secret = Secret::generate();
        let code = Code::new("https://foo.trycloudflare.com".parse().unwrap(), secret.clone());
        let s = code.to_string();
        assert!(s.starts_with("https://foo.trycloudflare.com"));
        assert!(s.contains('#'));
        let parsed = Code::parse(&s).unwrap();
        assert_eq!(parsed.base_url.as_str(), "https://foo.trycloudflare.com/");
        assert_eq!(parsed.secret.0, secret.0);
    }

    #[test]
    fn rejects_missing_fragment() {
        assert!(Code::parse("https://foo.trycloudflare.com").is_err());
    }

    #[test]
    fn rejects_non_http_scheme() {
        assert!(Code::parse("ftp://host#3yZe7B4vN9pQ2sKfTgWxUm").is_err());
    }

    #[test]
    fn rejects_bad_secret() {
        assert!(Code::parse("https://foo.trycloudflare.com#nope").is_err());
    }

    #[test]
    fn direct_http_code_works() {
        let secret = Secret::generate();
        let code = Code::new("http://192.168.0.5:40123".parse().unwrap(), secret);
        let parsed = Code::parse(&code.to_string()).unwrap();
        assert_eq!(parsed.base_url.port(), Some(40123));
    }
}
