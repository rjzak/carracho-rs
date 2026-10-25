//! Packets on the main client/server connection. Specified in
//! `docs/protocol.md`, section 4.3.

use crate::crypto::FrameCipher;
use crate::wire::Reader;
use crate::DecodeError;

/// Default TCP port of the main connection. The data connection uses the
/// next port up.
pub const PORT: u16 = 6700;

/// First 11 bytes of the cleartext greeting both sides send (section 4.1).
pub const GREETING_MAGIC: [u8; 11] = *b"TCPCARRACHO";
/// Protocol version in the client's greeting.
pub const CLIENT_VERSION: u16 = 1;
/// Protocol version in the server's greeting. The original client accepts
/// only this value.
pub const SERVER_VERSION: u16 = 2;

/// The 13-byte greeting: the magic followed by a `u16` version.
pub fn greeting(version: u16) -> [u8; 13] {
    let mut out = [0u8; 13];
    out[..11].copy_from_slice(&GREETING_MAGIC);
    out[11..].copy_from_slice(&version.to_be_bytes());
    out
}

/// Parse a greeting, returning its version.
pub fn parse_greeting(bytes: &[u8; 13]) -> Result<u16, DecodeError> {
    if bytes[..11] != GREETING_MAGIC {
        return Err(DecodeError::BadMagic);
    }
    Ok(u16::from_be_bytes([bytes[11], bytes[12]]))
}

/// Header size in bytes.
pub const HEADER_LEN: usize = 18;

/// Largest packet body the original server accepts (128 KiB).
pub const MAX_BODY_LEN: usize = 0x2_0000;

/// One tagged field: `u32 tag, u16 length, data`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    pub tag: u32,
    pub data: Vec<u8>,
}

impl Field {
    pub fn new(tag: u32, data: impl Into<Vec<u8>>) -> Self {
        Self { tag, data: data.into() }
    }

    pub fn u8(tag: u32, v: u8) -> Self {
        Self::new(tag, [v])
    }

    pub fn u16(tag: u32, v: u16) -> Self {
        Self::new(tag, v.to_be_bytes())
    }

    pub fn u32(tag: u32, v: u32) -> Self {
        Self::new(tag, v.to_be_bytes())
    }

    pub fn as_u8(&self) -> Option<u8> {
        <[u8; 1]>::try_from(self.data.as_slice()).ok().map(|[b]| b)
    }

    pub fn as_u16(&self) -> Option<u16> {
        self.data.as_slice().try_into().ok().map(u16::from_be_bytes)
    }

    pub fn as_u32(&self) -> Option<u32> {
        self.data.as_slice().try_into().ok().map(u32::from_be_bytes)
    }
}

/// A decoded packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    pub command: u32,
    /// Chosen by the requester and echoed in the reply, so replies can be
    /// matched to requests. Zero for unsolicited packets.
    pub task: u32,
    /// Header bytes 12..16. The original programs never set them (they hold
    /// whatever was on the stack), so they carry no meaning.
    pub reserved: u32,
    pub fields: Vec<Field>,
}

impl Packet {
    pub fn new(command: u32, task: u32, fields: Vec<Field>) -> Self {
        Self { command, task, reserved: 0, fields }
    }

    /// First field with this tag.
    pub fn field(&self, tag: u32) -> Option<&Field> {
        self.fields.iter().find(|f| f.tag == tag)
    }

    pub fn encode(&self) -> Vec<u8> {
        let body_len: usize = self.fields.iter().map(|f| 6 + f.data.len()).sum();
        let mut out = Vec::with_capacity(HEADER_LEN + body_len);
        out.extend_from_slice(&self.command.to_be_bytes());
        out.extend_from_slice(&self.task.to_be_bytes());
        out.extend_from_slice(&(body_len as u32).to_be_bytes());
        out.extend_from_slice(&self.reserved.to_be_bytes());
        out.extend_from_slice(&(self.fields.len() as u16).to_be_bytes());
        for f in &self.fields {
            out.extend_from_slice(&f.tag.to_be_bytes());
            out.extend_from_slice(&(f.data.len() as u16).to_be_bytes());
            out.extend_from_slice(&f.data);
        }
        out
    }

    /// Encode and encrypt a packet as a frame: a cleartext `u32` length
    /// followed by the encrypted, padded packet.
    pub fn to_frame(&self, cipher: &FrameCipher) -> Vec<u8> {
        let sealed = cipher.seal(&self.encode());
        let mut out = Vec::with_capacity(4 + sealed.len());
        out.extend_from_slice(&(sealed.len() as u32).to_be_bytes());
        out.extend_from_slice(&sealed);
        out
    }

    /// Decode a decrypted frame. Bytes after the body (padding) are ignored.
    pub fn decode(frame: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(frame);
        let command = r.u32()?;
        let task = r.u32()?;
        let body_len = r.u32()? as usize;
        let reserved = r.u32()?;
        let count = r.u16()?;
        if body_len > MAX_BODY_LEN {
            return Err(DecodeError::TooLong { field: "packet body", len: body_len, max: MAX_BODY_LEN });
        }
        let mut body = Reader::new(r.bytes(body_len)?);
        let mut fields = Vec::with_capacity(count.min(1024) as usize);
        for _ in 0..count {
            let tag = body.u32()?;
            let len = body.u16()? as usize;
            fields.push(Field { tag, data: body.bytes(len)?.to_vec() });
        }
        Ok(Self { command, task, reserved, fields })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let p = Packet::new(
            3,
            7,
            vec![Field::new(2, b"Retro".to_vec()), Field::u16(0x21, 5), Field::u32(1, 42)],
        );
        let bytes = p.encode();
        assert_eq!(&bytes[8..12], &(11u32 + 8 + 10).to_be_bytes(), "body length");
        assert_eq!(&bytes[16..18], &[0, 3], "field count");
        let back = Packet::decode(&bytes).unwrap();
        assert_eq!(back, p);
        assert_eq!(back.field(0x21).and_then(Field::as_u16), Some(5));
        assert_eq!(back.field(1).and_then(Field::as_u32), Some(42));
    }

    #[test]
    fn ignores_padding() {
        let mut bytes = Packet::new(0, 1, vec![Field::u16(1, 100)]).encode();
        bytes.extend_from_slice(&[0; 6]);
        assert_eq!(Packet::decode(&bytes).unwrap().field(1).unwrap().as_u16(), Some(100));
    }

    #[test]
    fn rejects_fields_overrunning_body() {
        let mut bytes = Packet::new(0, 1, vec![Field::u16(1, 100)]).encode();
        bytes[8..12].copy_from_slice(&7u32.to_be_bytes());
        bytes.push(0);
        assert!(matches!(Packet::decode(&bytes), Err(DecodeError::Truncated { .. })));
    }
}
