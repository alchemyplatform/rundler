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

use parse_display::Display;
use serde::{Deserialize, Serialize};

/// Builder bundling mode
#[derive(Display, Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[display(style = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum BundlingMode {
    /// Manual bundling mode for debugging.
    ///
    /// Bundles will only be sent when `debug_send_bundle_now` is called.
    Manual,
    /// Auto bundling mode for normal operation.
    ///
    /// Bundles will be sent automatically.
    Auto,
}
