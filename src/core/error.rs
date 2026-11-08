//! RET's tagged error algebra.
//!
//! Analysis failures are not shapeless: each error carries a stable code and
//! enough structure to render as JSON for agents, YAML for scripts, or text
//! for humans — while preserving partial facts where analysis could continue.

use serde::Serialize;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ErrorKind {
    /// The input path does not exist.
    NotFound,
    /// A permission/ownership problem while reading or walking.
    AccessDenied,
    /// The input is not parseable as the claimed format.
    Malformed { detail: String },
    /// A required external provider (engine/binary) is unavailable.
    ProviderMissing { provider: String, hint: String },
    /// A bound was exceeded (size, depth, counts) to protect the host.
    LimitExceeded { limit: String },
    /// I/O error from the OS.
    Io,
    /// A user-supplied argument was invalid.
    InvalidArgument { detail: String },
    /// An internal invariant was violated. Never expected in normal use.
    Internal { detail: String },
}

#[derive(Clone, Serialize)]
pub struct Error {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<ErrorKind>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub context: Vec<String>,
}impl Error {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        let code = match &kind {
            ErrorKind::NotFound => "NOT_FOUND",
            ErrorKind::AccessDenied => "ACCESS_DENIED",
            ErrorKind::Malformed { .. } => "MALFORMED",
            ErrorKind::ProviderMissing { .. } => "PROVIDER_MISSING",
            ErrorKind::LimitExceeded { .. } => "LIMIT_EXCEEDED",
            ErrorKind::Io => "IO",
            ErrorKind::InvalidArgument { .. } => "INVALID_ARGUMENT",
            ErrorKind::Internal { .. } => "INTERNAL",
        }
        .to_string();
        Error {
            code,
            message: message.into(),
            kind: Some(kind),
            context: Vec::new(),
        }
    }

    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::NotFound, msg)
    }
    pub fn malformed(msg: impl Into<String>) -> Self {
        let m = msg.into();
        Self::new(ErrorKind::Malformed { detail: m.clone() }, m)
    }
    pub fn provider_missing(provider: impl Into<String>, hint: impl Into<String>) -> Self {
        let (provider, hint) = (provider.into(), hint.into());
        Self::new(
            ErrorKind::ProviderMissing {
                provider: provider.clone(),
                hint: hint.clone(),
            },
            format!("provider '{provider}' is not available"),
        )
    }
    pub fn limit(limit: impl Into<String>) -> Self {
        Self::new(ErrorKind::LimitExceeded { limit: limit.into() }, "limit exceeded")
    }
    pub fn invalid_arg(msg: impl Into<String>) -> Self {
        let m = msg.into();
        Self::new(ErrorKind::InvalidArgument { detail: m.clone() }, m)
    }
    pub fn internal(msg: impl Into<String>) -> Self {
        let m = msg.into();
        Self::new(ErrorKind::Internal { detail: m.clone() }, m)
    }

    /// Push narrative context; used to say *about which path* a failure happened.
    pub fn ctx(mut self, context: impl Into<String>) -> Self {
        self.context.push(context.into());
        self
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.context.is_empty() {
            write!(f, "{}: {}", self.code, self.message)
        } else {
            write!(f, "{}: {} ({})", self.code, self.message, self.context.join("; "))
        }
    }
}

impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        match e.kind() {
            std::io::ErrorKind::NotFound => {
                Error::new(ErrorKind::NotFound, format!("io: {e}"))
            }
            std::io::ErrorKind::PermissionDenied => {
                Error::new(ErrorKind::AccessDenied, format!("io: {e}"))
            }
            _ => Error::new(ErrorKind::Io, format!("io: {e}")),
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::malformed(format!("json: {e}"))
    }
}
