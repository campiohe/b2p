//! Transport layer: moves the encrypted payload between the two peers.
//! Since v0.4.0 there is one transport — the relay (`relay::RelayChannel`),
//! reached over an outbound WebSocket from both sides.

#[cfg(test)]
pub mod mock;
pub mod relay;
