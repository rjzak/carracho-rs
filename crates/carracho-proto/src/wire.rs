//! Low-level big-endian reading and writing shared by the protocol modules.

/// Errors produced when parsing protocol data.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("unexpected end of data (needed {needed} more bytes)")]
    Truncated { needed: usize },
    #[error("bad magic number")]
    BadMagic,
    #[error("{field} is {len} bytes, the limit is {max}")]
    TooLong { field: &'static str, len: usize, max: usize },
}

/// A cursor over a byte slice.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let remaining = self.buf.len() - self.pos;
        if remaining < n {
            return Err(DecodeError::Truncated { needed: n - remaining });
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        Ok(self.bytes(N)?.try_into().expect("length checked"))
    }

    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.array::<1>()?[0])
    }

    pub fn u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    pub fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// A string inside a structure: a `u16` length followed by that many
    /// bytes (`Stream::WriteString` in the originals).
    pub fn string(&mut self) -> Result<&'a [u8], DecodeError> {
        let len = self.u16()? as usize;
        self.bytes(len)
    }

    /// A Pascal string: a length byte followed by that many bytes.
    pub fn pstr(&mut self) -> Result<&'a [u8], DecodeError> {
        let len = self.u8()? as usize;
        self.bytes(len)
    }
}

/// Append a Pascal string, truncating it to 255 bytes.
pub(crate) fn put_pstr(out: &mut Vec<u8>, s: &[u8]) {
    let s = &s[..s.len().min(255)];
    out.push(s.len() as u8);
    out.extend_from_slice(s);
}

/// Append a big-endian `u16`.
pub fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// Append a big-endian `u32`.
pub fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// Append a big-endian `u64`.
pub fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// Append a string as it appears inside structures: a `u16` length and the
/// bytes. Strings over 65535 bytes are truncated.
pub fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    let s = &s[..s.len().min(u16::MAX as usize)];
    put_u16(out, s.len() as u16);
    out.extend_from_slice(s);
}
