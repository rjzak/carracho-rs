//! Account records as they travel in the account commands. Specified in
//! `docs/protocol.md`, section 4.14.

use crate::DecodeError;

/// Size of a full account record.
pub const RECORD_LEN: usize = 0xd6;
/// Size of an account list entry.
pub const LIST_ENTRY_LEN: usize = 0x88;
/// Longest login name.
pub const MAX_LOGIN_LEN: usize = 31;
/// First password byte meaning "keep the current password" in an edit.
pub const KEEP_PASSWORD: u8 = 0xAD;

const LOGIN: (usize, usize) = (0x00, 64);
const REAL_NAME: (usize, usize) = (0x40, 65);
const PASSWORD: (usize, usize) = (0x81, 65);
const CREATED: usize = 0xc2;
const MODIFIED: usize = 0xc6;
const LAST_LOGIN: usize = 0xca;
const PRIVILEGES: usize = 0xce;

/// A decoded account record. Text fields are raw Mac Roman bytes.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Record {
    pub login: Vec<u8>,
    pub real_name: Vec<u8>,
    pub password: Vec<u8>,
    pub created: u32,
    pub modified: u32,
    pub last_login: u32,
    pub privileges: u64,
}

fn cstr(field: &[u8]) -> Vec<u8> {
    field[..field.iter().position(|&b| b == 0).unwrap_or(field.len())].to_vec()
}

fn put_cstr(buf: &mut [u8], (offset, size): (usize, usize), s: &[u8]) {
    let n = s.len().min(size - 1);
    buf[offset..offset + n].copy_from_slice(&s[..n]);
}

fn be32(buf: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(buf[at..at + 4].try_into().unwrap())
}

impl Record {
    /// Decode a record. The password is returned as sent: scrambled, when it
    /// comes from a client (see [`scramble`]).
    pub fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        if buf.len() < RECORD_LEN {
            return Err(DecodeError::Truncated { needed: RECORD_LEN - buf.len() });
        }
        let field = |(o, s): (usize, usize)| cstr(&buf[o..o + s]);
        Ok(Self {
            login: field(LOGIN),
            real_name: field(REAL_NAME),
            password: field(PASSWORD),
            created: be32(buf, CREATED),
            modified: be32(buf, MODIFIED),
            last_login: be32(buf, LAST_LOGIN),
            privileges: u64::from_be_bytes(buf[PRIVILEGES..PRIVILEGES + 8].try_into().unwrap()),
        })
    }

    /// Encode the record with its password replaced by `0xA5` bytes of the
    /// same length, as the server sends it.
    pub fn encode_masked(&self) -> Vec<u8> {
        let mut buf = vec![0u8; RECORD_LEN];
        put_cstr(&mut buf, LOGIN, &self.login);
        put_cstr(&mut buf, REAL_NAME, &self.real_name);
        put_cstr(&mut buf, PASSWORD, &vec![0xA5; self.password.len()]);
        buf[CREATED..CREATED + 4].copy_from_slice(&self.created.to_be_bytes());
        buf[MODIFIED..MODIFIED + 4].copy_from_slice(&self.modified.to_be_bytes());
        buf[LAST_LOGIN..LAST_LOGIN + 4].copy_from_slice(&self.last_login.to_be_bytes());
        buf[PRIVILEGES..PRIVILEGES + 8].copy_from_slice(&self.privileges.to_be_bytes());
        buf
    }

    /// Encode the record as a client sends it, with the password scrambled.
    pub fn encode_for_server(&self) -> Vec<u8> {
        let mut buf = self.encode_masked();
        buf[PASSWORD.0..PASSWORD.0 + PASSWORD.1].fill(0);
        put_cstr(&mut buf, PASSWORD, &scramble(&self.password));
        buf
    }

    /// The 136-byte account list entry.
    pub fn list_entry(&self) -> Vec<u8> {
        let mut buf = vec![0u8; LIST_ENTRY_LEN];
        put_cstr(&mut buf, (0x00, 64), &self.login);
        put_cstr(&mut buf, (0x40, 66), &self.real_name);
        buf[0x82..0x86].copy_from_slice(&self.last_login.to_be_bytes());
        buf[0x86] = account_class(self.privileges);
        buf
    }
}

/// The user class from privilege bits 0 and 1: 2 administrator, 1 account
/// holder, 0 guest.
pub fn account_class(privileges: u64) -> u8 {
    if privileges & (1 << 63) != 0 {
        2
    } else if privileges & (1 << 62) != 0 {
        1
    } else {
        0
    }
}

/// The original's `EncryptDecryptPassword`: XOR with 0x88, 0x44, 0x12 in
/// turn, stopping at the first zero byte. It is its own inverse.
pub fn scramble(password: &[u8]) -> Vec<u8> {
    const KEY: [u8; 3] = [0x88, 0x44, 0x12];
    password.iter().take_while(|&&b| b != 0).enumerate().map(|(i, &b)| b ^ KEY[i % 3]).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_round_trip() {
        let r = Record {
            login: b"guest".to_vec(),
            real_name: b"Guest".to_vec(),
            password: b"pw".to_vec(),
            created: 1,
            modified: 2,
            last_login: 3,
            privileges: 0x0030_0008_0001_8000,
        };
        let masked = Record::decode(&r.encode_masked()).unwrap();
        assert_eq!(masked.password, vec![0xA5, 0xA5]);
        assert_eq!(Record { password: r.password.clone(), ..masked }, r);
        let sent = Record::decode(&r.encode_for_server()).unwrap();
        assert_eq!(scramble(&sent.password), b"pw");
        let entry = r.list_entry();
        assert_eq!(&entry[..5], b"guest");
        assert_eq!(entry[0x86], 0);
    }

    /// The shipped `Accounts` file: `admin` with privileges 803fffc8 7daf8000.
    #[test]
    fn decodes_privileges_at_0xce() {
        let mut buf = vec![0u8; RECORD_LEN];
        buf[..5].copy_from_slice(b"admin");
        buf[0xce..0xd6].copy_from_slice(&[0x80, 0x3f, 0xff, 0xc8, 0x7d, 0xaf, 0x80, 0x00]);
        let r = Record::decode(&buf).unwrap();
        assert_eq!(r.privileges, 0x803f_ffc8_7daf_8000);
        assert_eq!(account_class(r.privileges), 2);
    }
}
