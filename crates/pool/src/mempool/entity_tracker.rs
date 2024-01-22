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
pub(crate) struct EntityCounter {
    sender: usize,
    paymaster: usize,
    aggregator: usize,
    factory: usize,
}

impl EntityCounter {
    pub(crate) fn total(&self) -> usize {
        self.sender + self.paymaster + self.aggregator + self.factory
    }

    pub(crate) fn sender(&self) -> usize {
        self.sender
    }

    pub(crate) fn increment_entity_count(&mut self, entity: &EntityType) {
        match entity {
            EntityType::Account => self.sender = self.sender.saturating_add(1),
            EntityType::Paymaster => self.paymaster = self.paymaster.saturating_add(1),
            EntityType::Aggregator => self.aggregator = self.aggregator.saturating_add(1),
            EntityType::Factory => self.factory = self.factory.saturating_add(1),
        }
    }

    pub(crate) fn decrement_entity_count(&mut self, entity: &EntityType) {
        match entity {
            EntityType::Account => self.sender = self.sender.saturating_sub(1),
            EntityType::Paymaster => self.paymaster = self.paymaster.saturating_sub(1),
            EntityType::Aggregator => self.aggregator = self.aggregator.saturating_sub(1),
            EntityType::Factory => self.factory = self.factory.saturating_sub(1),
        }
    }

    pub(crate) fn includes_non_sender(&self) -> bool {
        (self.paymaster + self.aggregator + self.factory) > 0
    }
}

#[cfg(test)]
mod tests {
    use super::EntityCounter;

    #[test]
    fn test_includes_non_sender() {
        let mut entity_counter = EntityCounter::default();

        entity_counter.increment_entity_count(&rundler_types::EntityType::Account);
        assert!(!entity_counter.includes_non_sender());
        entity_counter.increment_entity_count(&rundler_types::EntityType::Paymaster);
        assert!(entity_counter.includes_non_sender());
    }
}
