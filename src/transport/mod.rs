//! Transport layer: moves the encrypted payload once peers have met on the
//! rendezvous. P1d ships the WebRTC data-channel transport; the tunnel path
//! (P0) keeps its own code and is selected by code form in P1e.

#[cfg(test)]
pub mod mock;
pub mod relay;
pub mod webrtc;
