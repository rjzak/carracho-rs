//! Connection encryption and login authentication. Specified in
//! `docs/protocol.md`, section 4.2.

use blowfish::cipher::{Array, BlockCipherDecrypt, BlockCipherEncrypt};
use blowfish::Blowfish;
use md5::{Digest, Md5};

/// Key every connection starts with, until login succeeds.
pub const INITIAL_KEY: &[u8] = b"YOYO";

/// Length of the random challenge the server sends before login.
pub const CHALLENGE_LEN: usize = 12;

/// Whitening applied to the first word of each block after encryption.
const WHITEN_L: u32 = 0x1057_6419;
/// Whitening applied to the second word of each block before encryption.
const WHITEN_R: u32 = 0x5802_2919;

/// Blowfish as Carracho uses it: ECB over 8-byte blocks with a fixed XOR on
/// each half of the block, and a key of any length.
#[derive(Clone)]
pub struct FrameCipher {
    bf: Blowfish,
}

impl FrameCipher {
    pub fn new(key: &[u8]) -> Self {
        assert!(!key.is_empty(), "Blowfish key must not be empty");
        let mut bf = Blowfish::bc_init_state();
        bf.bc_expand_key(key);
        Self { bf }
    }

    /// Pad and encrypt a frame body, returning the bytes that follow the
    /// frame's length word. The original always adds 1 to 8 zero bytes of
    /// padding, so a body that is already a multiple of 8 grows by 8.
    pub fn seal(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut buf = plaintext.to_vec();
        buf.resize(plaintext.len() + 8 - plaintext.len() % 8, 0);
        self.encrypt(&mut buf);
        buf
    }

    /// Encrypt in place. Trailing bytes that don't fill a block are left as
    /// they are, so callers pad first.
    pub fn encrypt(&self, buf: &mut [u8]) {
        for block in buf.chunks_exact_mut(8) {
            let (l, r) = words(block);
            let mut b = Array::from(join(l, r ^ WHITEN_R));
            self.bf.encrypt_block(&mut b);
            let (l, r) = words(&b);
            block.copy_from_slice(&join(l ^ WHITEN_L, r));
        }
    }

    /// Encrypt data-connection blocks in place (section 4.16). The data
    /// connection applies the whitening the other way round from frames: L
    /// before Blowfish, R after. Trailing bytes that don't fill a block are
    /// left as they are, so callers pad first.
    pub fn encrypt_transfer(&self, buf: &mut [u8]) {
        for block in buf.chunks_exact_mut(8) {
            let (l, r) = words(block);
            let mut b = Array::from(join(l ^ WHITEN_L, r));
            self.bf.encrypt_block(&mut b);
            let (l, r) = words(&b);
            block.copy_from_slice(&join(l, r ^ WHITEN_R));
        }
    }

    /// Decrypt data-connection blocks in place; the inverse of
    /// [`encrypt_transfer`](Self::encrypt_transfer).
    pub fn decrypt_transfer(&self, buf: &mut [u8]) {
        for block in buf.chunks_exact_mut(8) {
            let (l, r) = words(block);
            let mut b = Array::from(join(l, r ^ WHITEN_R));
            self.bf.decrypt_block(&mut b);
            let (l, r) = words(&b);
            block.copy_from_slice(&join(l ^ WHITEN_L, r));
        }
    }

    /// Decrypt a frame body in place. Trailing bytes that don't fill a block
    /// are left as they are; the original never sends any.
    pub fn open(&self, ciphertext: &mut [u8]) {
        for block in ciphertext.chunks_exact_mut(8) {
            let (l, r) = words(block);
            let mut b = Array::from(join(l ^ WHITEN_L, r));
            self.bf.decrypt_block(&mut b);
            let (l, r) = words(&b);
            block.copy_from_slice(&join(l, r ^ WHITEN_R));
        }
    }
}

fn words(block: &[u8]) -> (u32, u32) {
    (
        u32::from_be_bytes(block[..4].try_into().unwrap()),
        u32::from_be_bytes(block[4..8].try_into().unwrap()),
    )
}

fn join(l: u32, r: u32) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[..4].copy_from_slice(&l.to_be_bytes());
    out[4..].copy_from_slice(&r.to_be_bytes());
    out
}

/// The secret both sides derive from the password and the server's challenge.
/// It is hashed for the login response and then becomes the session key.
///
/// Byte pairs `(password[i] ^ 0x21, challenge[i])` for as long as both last.
/// If the password is shorter than the challenge, the password side is filled
/// with a counter (1, 2, 3, ...) XORed with 0x21; if it is longer, the challenge
/// side is filled with a counter instead. The result is
/// `2 * max(password.len(), 12)` bytes.
pub fn session_secret(password: &[u8], challenge: &[u8; CHALLENGE_LEN]) -> Vec<u8> {
    let n = password.len().max(CHALLENGE_LEN);
    let mut out = Vec::with_capacity(2 * n);
    for i in 0..n {
        let p = match password.get(i) {
            Some(&b) => b,
            None => (i + 1 - password.len()) as u8,
        };
        let c = match challenge.get(i) {
            Some(&b) => b,
            None => (i + 1 - CHALLENGE_LEN) as u8,
        };
        out.push(p ^ 0x21);
        out.push(c);
    }
    out
}

/// The login response: MD5 of the session secret as 32 lowercase hex digits.
pub fn login_response(secret: &[u8]) -> String {
    Md5::digest(secret).iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// Raw Blowfish block encryption, without Carracho's whitening.
    fn raw_encrypt(key: &[u8], block: &str) -> String {
        let c = FrameCipher::new(key);
        let mut b = Array::from(<[u8; 8]>::try_from(hex(block)).unwrap());
        c.bf.encrypt_block(&mut b);
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Vectors produced by running the original server's `Tlci`/`Tlce` under
    /// emulation (`tools/pefemu.py`).
    #[test]
    fn blowfish_matches_original_code() {
        assert_eq!(raw_encrypt(b"YOYO", "0000000000000000"), "b60c10119d46db8a");
        assert_eq!(raw_encrypt(b"YOYO", "0123456789abcdef"), "4c67591203b8681f");
        let key: Vec<u8> = (1..=24).collect();
        assert_eq!(raw_encrypt(&key, "0000000000000000"), "f02f9a581b3f401e");
        assert_eq!(raw_encrypt(&key, "0123456789abcdef"), "876c60946048dab2");
    }

    #[test]
    fn seal_pads_and_round_trips() {
        let c = FrameCipher::new(INITIAL_KEY);
        for len in [0, 1, 7, 8, 9, 18, 24] {
            let plain: Vec<u8> = (0..len as u8).collect();
            let mut sealed = c.seal(&plain);
            assert_eq!(sealed.len(), len + 8 - len % 8, "padding for {len}");
            c.open(&mut sealed);
            assert_eq!(&sealed[..len], &plain[..]);
            assert!(sealed[len..].iter().all(|&b| b == 0));
        }
    }

    #[test]
    fn whitening_is_applied() {
        // One zero block: R is whitened before encryption, L after.
        let c = FrameCipher::new(INITIAL_KEY);
        let sealed = c.seal(&[0u8; 7]);
        let mut expect = Array::from(join(0, WHITEN_R));
        c.bf.encrypt_block(&mut expect);
        let (l, r) = words(&expect);
        assert_eq!(sealed, join(l ^ WHITEN_L, r));
    }

    #[test]
    fn transfer_whitening_is_reversed() {
        // Data connection: L is whitened before encryption, R after.
        let c = FrameCipher::new(INITIAL_KEY);
        let mut sealed = [0u8; 16];
        sealed[..8].copy_from_slice(&join(1, 2));
        sealed[8..].copy_from_slice(&join(3, 4));
        c.encrypt_transfer(&mut sealed);
        let mut expect = Array::from(join(1 ^ WHITEN_L, 2));
        c.bf.encrypt_block(&mut expect);
        let (l, r) = words(&expect);
        assert_eq!(sealed[..8], join(l, r ^ WHITEN_R));
        c.decrypt_transfer(&mut sealed);
        assert_eq!((words(&sealed[..8]), words(&sealed[8..])), ((1, 2), (3, 4)));
    }

    /// Vectors produced by running the original client's interleaving code
    /// (0x7770-0x795c) under emulation with challenge 10 11 12 ... 1b.
    #[test]
    fn session_secret_matches_original_code() {
        let challenge: [u8; 12] = std::array::from_fn(|i| 0x10 + i as u8);
        assert_eq!(
            session_secret(b"", &challenge),
            hex("2010231122122513241427152616291728182b192a1a2d1b")
        );
        assert_eq!(
            session_secret(b"secret", &challenge),
            hex("5210441142125313441455152016231722182519241a271b")
        );
        assert_eq!(
            session_secret(b"averylongpassword!", &challenge),
            hex("401057114412531358144d154e164f1746185119401a521b520156024e03530445050006")
        );
    }

    #[test]
    fn login_response_is_md5_hex() {
        assert_eq!(login_response(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
    }
}
