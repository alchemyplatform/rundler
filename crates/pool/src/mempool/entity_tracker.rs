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

use rundler_types::EntityType;

/// Object to track count and type of entity in mempool

#[derive(Debug, Default)]
pub(crate) struct EntityCountTracker {
    sender: usize,
    paymaster: usize,
    aggregator: usize,
    factory: usize,
}

impl EntityCountTracker {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn total(&self) -> usize {
        self.sender + self.paymaster + self.aggregator + self.factory
    }

    pub(crate) fn sender(&self) -> usize {
        self.sender
    }

    pub(crate) fn increment_entity(&mut self, entity: &EntityType) -> Option<usize> {
        match entity {
            EntityType::Account => self.sender.checked_add(1),
            EntityType::Paymaster => self.paymaster.checked_add(1),
            EntityType::Aggregator => self.aggregator.checked_add(1),
            EntityType::Factory => self.factory.checked_add(1),
        }
    }

    pub(crate) fn decrement(&mut self, entity: &EntityType) -> Option<usize> {
        match entity {
            EntityType::Account => self.sender.checked_sub(1),
            EntityType::Paymaster => self.paymaster.checked_sub(1),
            EntityType::Aggregator => self.aggregator.checked_sub(1),
            EntityType::Factory => self.factory.checked_sub(1),
        }
    }

    pub(crate) fn includes_non_sender(&self) -> bool {
        (self.paymaster + self.aggregator + self.factory) > 0
    }
}
