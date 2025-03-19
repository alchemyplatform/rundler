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

use std::fmt::{Display, Formatter};

/// An error that occurs when a user operation violates a spec rule.
#[derive(Debug, thiserror::Error)]
pub enum ViolationError<T> {
    /// A list of known simulation violations
    Violations(Vec<T>),

    /// Other error that occurs during simulation
    Other(#[from] anyhow::Error),
}

impl<T> Clone for ViolationError<T>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        match self {
            ViolationError::Violations(violations) => {
                ViolationError::Violations(violations.clone())
            }
            ViolationError::Other(error) => {
                ViolationError::Other(anyhow::anyhow!(error.to_string()))
            }
        }
    }
}

impl<T> From<Vec<T>> for ViolationError<T> {
    fn from(violations: Vec<T>) -> Self {
        Self::Violations(violations)
    }
}

impl<T: Display> Display for ViolationError<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ViolationError::Violations(violations) => {
                if violations.len() == 1 {
                    Display::fmt(&violations[0], f)
                } else {
                    f.write_str("multiple violations: ")?;
                    for violation in violations {
                        Display::fmt(violation, f)?;
                        f.write_str("; ")?;
                    }
                    Ok(())
                }
            }
            ViolationError::Other(error) => Display::fmt(error, f),
        }
    }
}
