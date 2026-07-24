use std::path::PathBuf;

/// TLS trust options shared by every outbound TLS connection b2p makes.
/// The OS certificate store is always trusted (via rustls-native-certs,
/// which also honors SSL_CERT_FILE / SSL_CERT_DIR); `cafile` adds extra
/// PEM roots on top — e.g. a TLS-inspecting proxy's CA. Consumed by the
/// relay transport's rustls connector (see `transport::relay`).
#[derive(Clone, Default)]
pub struct TlsOpts {
    pub cafile: Option<PathBuf>,
}
