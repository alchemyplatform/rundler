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

use std::fmt::Display;

use rundler_builder::BuilderEvent;
use rundler_pool::PoolEvent;

#[derive(Clone, Debug)]
pub enum Event {
    PoolEvent(PoolEvent),
    BuilderEvent(BuilderEvent),
}

impl From<PoolEvent> for Event {
    fn from(event: PoolEvent) -> Self {
        Self::PoolEvent(event)
    }
}

impl From<BuilderEvent> for Event {
    fn from(event: BuilderEvent) -> Self {
        Self::BuilderEvent(event)
    }
}

impl Display for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Event::PoolEvent(event) => event.fmt(f),
            Event::BuilderEvent(event) => event.fmt(f),
        }
    }
}
