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

pub(crate) mod message;
mod snappy;
use libp2p::gossipsub;
pub(crate) use snappy::SnappyTransform;
pub(crate) mod topic;

use crate::Config;

pub(crate) fn gossipsub_config(config: &Config) -> gossipsub::Config {
    gossipsub::ConfigBuilder::default()
        .max_transmit_size(config.gossip_max_size)
        .validate_messages()
        .validation_mode(gossipsub::ValidationMode::Anonymous)
        // TODO fast message id
        .message_id_fn(message::message_id)
        .build()
        .expect("valid gossipsub config")
}
