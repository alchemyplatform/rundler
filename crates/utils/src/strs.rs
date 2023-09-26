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

//! Formatting helpers for strings

use std::{borrow::Cow, fmt::Debug};

/// Given an `Option`, converts the contents of the `Option` to a `String`,
/// returning the provided default `&str` if the option is `None`. Returns a
/// `Cow` in order to avoid allocation in the latter case.
pub fn to_string_or(x: Option<impl ToString>, default: &str) -> Cow<'_, str> {
    x.map(|x| Cow::Owned(x.to_string()))
        .unwrap_or(Cow::Borrowed(default))
}

/// Like `to_string_or`, but uses debug formatting.
pub fn to_debug_or(x: Option<impl Debug>, default: &str) -> Cow<'_, str> {
    x.map(|x| Cow::Owned(format!("{x:?}")))
        .unwrap_or(Cow::Borrowed(default))
}

/// Converts an option to a string, returning an empty string if the option is None.
pub fn to_string_or_empty(x: Option<impl ToString>) -> String {
    x.map(|x| x.to_string()).unwrap_or_default()
}
