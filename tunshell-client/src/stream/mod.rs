use futures::{AsyncRead, AsyncWrite};

mod aes_stream;
mod crypto;
mod relay_stream;

pub use aes_stream::*;
pub use relay_stream::*;

pub trait TunnelStream: AsyncRead + AsyncWrite + Send + Unpin {}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::io::Cursor;

    impl TunnelStream for Cursor<Vec<u8>> {}
}
