// This file is part of Rundler.
//
// Rundler is free software: you can redistribute it and/or modify it under the
// terms of the GNU Lesser General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later version.
//
// Rundler is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with Rundler.
// If not, see https://www.gnu.org/licenses/.

//! Utilities for working with Ethereum Network Records (ENRs).
//!
//! Adapted from https://github.com/sigp/lighthouse/blob/stable/beacon_node/lighthouse_network/src/discovery/enr_ext.rs

use discv5::{
    enr::{k256, CombinedKey, CombinedPublicKey, EnrBuilder},
    Enr,
};
use libp2p::{
    identity::{ed25519, secp256k1, PublicKey},
    multiaddr::Protocol,
    Multiaddr, PeerId,
};

use crate::Config;

/// Build an ENR from the given configuration.
pub fn build_enr(config: &Config) -> (Enr, CombinedKey) {
    let enr_key: CombinedKey =
        k256::ecdsa::SigningKey::from_slice(&hex::decode(&config.private_key).unwrap())
            .unwrap()
            .into();

    let enr = EnrBuilder::new("v4")
        .ip(config.listen_address.ip())
        .tcp4(config.listen_address.port())
        .udp4(config.listen_address.port() + 1)
        .build(&enr_key)
        .unwrap();

    (enr, enr_key)
}

/// Extension trait for ENR.
pub trait EnrExt {
    /// Returns the multiaddr of the ENR.
    fn multiaddr(&self) -> Vec<Multiaddr>;

    /// Returns the peer id of the ENR.
    fn peer_id(&self) -> PeerId;
}

impl EnrExt for Enr {
    fn multiaddr(&self) -> Vec<Multiaddr> {
        let mut multiaddrs: Vec<Multiaddr> = Vec::new();
        if let Some(ip) = self.ip4() {
            if let Some(udp) = self.udp4() {
                let mut multiaddr: Multiaddr = ip.into();
                multiaddr.push(Protocol::Udp(udp));
                multiaddrs.push(multiaddr);
            }
            if let Some(tcp) = self.tcp4() {
                let mut multiaddr: Multiaddr = ip.into();
                multiaddr.push(Protocol::Tcp(tcp));
                multiaddrs.push(multiaddr);
            }
        }
        multiaddrs
    }

    fn peer_id(&self) -> PeerId {
        self.public_key().as_peer_id()
    }
}

/// Extension trait for CombinedPublicKey
pub trait CombinedKeyPublicExt {
    /// Converts the publickey into a peer id, without consuming the key.
    fn as_peer_id(&self) -> PeerId;
}

impl CombinedKeyPublicExt for CombinedPublicKey {
    /// Converts the publickey into a peer id, without consuming the key.
    fn as_peer_id(&self) -> PeerId {
        match self {
            Self::Secp256k1(pk) => {
                let pk_bytes = pk.to_sec1_bytes();
                let libp2p_pk: PublicKey = secp256k1::PublicKey::try_from_bytes(&pk_bytes)
                    .expect("valid public key")
                    .into();
                PeerId::from_public_key(&libp2p_pk)
            }
            Self::Ed25519(pk) => {
                let pk_bytes = pk.to_bytes();
                let libp2p_pk: PublicKey = ed25519::PublicKey::try_from_bytes(&pk_bytes)
                    .expect("valid public key")
                    .into();
                PeerId::from_public_key(&libp2p_pk)
            }
        }
    }
}
