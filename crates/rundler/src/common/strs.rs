use std::{borrow::Cow, fmt::Debug};

// Formatting helpers

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

pub fn to_string_or_empty(x: Option<impl ToString>) -> String {
    x.map(|x| x.to_string()).unwrap_or_default()
}
