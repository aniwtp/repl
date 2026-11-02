use crate::msg::FaultCode;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("capnp: {0}")]
    Capnp(#[from] capnp::Error),
    #[error("tls: {0}")]
    Tls(String),
    #[error("db: {0}")]
    Db(#[from] db_wrapper::DbError),
    #[error("protocol: {0}")]
    Proto(String),
    #[error("peer fault {code:?}: {msg}")]
    Fault { code: FaultCode, msg: String },
    #[error("timeout: {0}")]
    Timeout(&'static str),
    #[error("config: {0}")]
    Config(String),
    #[error("connection closed")]
    Closed,
}

impl From<rustls::Error> for Error {
    fn from(e: rustls::Error) -> Self {
        Error::Tls(e.to_string())
    }
}
