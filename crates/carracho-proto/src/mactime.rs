//! Mac OS dates: unsigned seconds since 1904-01-01 00:00 GMT.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Seconds from 1904-01-01 to 1970-01-01.
pub const UNIX_OFFSET: u64 = 2_082_844_800;

/// Convert a system time to a Mac OS date, clamping to the representable
/// range (1904 to 2040).
pub fn from_system(t: SystemTime) -> u32 {
    let secs = match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() + UNIX_OFFSET,
        Err(e) => UNIX_OFFSET.saturating_sub(e.duration().as_secs()),
    };
    secs.min(u32::MAX as u64) as u32
}

/// Convert a Mac OS date to a system time.
pub fn to_system(mac: u32) -> SystemTime {
    let mac = mac as u64;
    if mac >= UNIX_OFFSET {
        UNIX_EPOCH + Duration::from_secs(mac - UNIX_OFFSET)
    } else {
        UNIX_EPOCH - Duration::from_secs(UNIX_OFFSET - mac)
    }
}

/// The current time as a Mac OS date.
pub fn now() -> u32 {
    from_system(SystemTime::now())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_known_value() {
        // Observed from the original server: 3875796631 is 2026-10-25 22:10:31 GMT.
        let t = to_system(3_875_796_631);
        assert_eq!(t.duration_since(UNIX_EPOCH).unwrap().as_secs(), 1_792_951_831);
        assert_eq!(from_system(t), 3_875_796_631);
        assert_eq!(from_system(UNIX_EPOCH), UNIX_OFFSET as u32);
    }
}
