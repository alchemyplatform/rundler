use std::fmt::{Display, Formatter};

#[derive(Debug, thiserror::Error)]
pub enum ViolationError<T> {
    Violations(Vec<T>),
    Other(#[from] anyhow::Error),
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
