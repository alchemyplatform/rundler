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

use libp2p::{
    identify,
    swarm::{keep_alive, NetworkBehaviour},
};

use crate::rpc;

#[derive(NetworkBehaviour)]
pub(crate) struct Behaviour {
    // TODO(danc): temp, remove when not needed
    pub(crate) keep_alive: keep_alive::Behaviour,
    // Request/response protocol
    pub(crate) rpc: rpc::Behaviour,
    // Identity protocol
    pub(crate) identify: identify::Behaviour,
}
