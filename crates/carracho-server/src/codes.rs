//! Command numbers, error codes and privilege bits (protocol.md, 4.5–4.6).

/// Command numbers.
pub mod cmd {
    pub const ERROR: u32 = 0x00;
    pub const CHALLENGE: u32 = 0x01;
    pub const LOGIN: u32 = 0x02;
    pub const LOGIN_ACCEPTED: u32 = 0x03;
    pub const KICK: u32 = 0x04;
    pub const BAN: u32 = 0x05;
    pub const PRIVATE_MESSAGE: u32 = 0x06;
    pub const USER_JOINED: u32 = 0x07;
    pub const USER_LEFT: u32 = 0x08;
    pub const LIST_FOLDER: u32 = 0x09;
    pub const DECLINE_INVITATION: u32 = 0x0c;
    pub const SET_MEMBER_MODE: u32 = 0x0f;
    pub const CREATE_FOLDER: u32 = 0x10;
    pub const DELETE: u32 = 0x11;
    pub const GET_FILE_INFO: u32 = 0x12;
    pub const SET_FILE_INFO: u32 = 0x13;
    /// Move request, and also the reply to `GET_FILE_INFO`.
    pub const MOVE: u32 = 0x14;
    pub const EMPTY_TRASH: u32 = 0x15;
    pub const SET_EXTENDED_INFO: u32 = 0x16;
    pub const GET_USER_INFO: u32 = 0x17;
    pub const CHANGE_NICK: u32 = 0x18;
    pub const SEARCH: u32 = 0x40;
    pub const JOIN_CHANNEL: u32 = 0x80;
    pub const LEAVE_CHANNEL: u32 = 0x81;
    pub const CHAT: u32 = 0x82;
    pub const CHANNEL_SETTINGS: u32 = 0x84;
    pub const CHANNEL_LIST: u32 = 0x86;
    pub const CHANNEL_USER_JOINED: u32 = 0x87;
    pub const CHANNEL_USER_LEFT: u32 = 0x88;
    pub const INVITE: u32 = 0x89;
    pub const LIST_NEWSGROUPS: u32 = 0xa0;
    pub const NEWSGROUP_REPLY: u32 = 0xa1;
    pub const READ_ARTICLE: u32 = 0xa2;
    pub const ADMIN_NEWSGROUP_REPLY: u32 = 0xa4;
    pub const ADD_NEWSGROUP: u32 = 0xa5;
    pub const DELETE_NEWSGROUP: u32 = 0xa6;
    pub const CHANGE_NEWSGROUP: u32 = 0xa7;
    pub const ADMIN_LIST_NEWSGROUPS: u32 = 0xa8;
    pub const DELETE_ARTICLE: u32 = 0xa9;
    pub const NEWSGROUP_CHANGED: u32 = 0xaa;
    pub const SETTINGS_REPLY: u32 = 0xc0;
    pub const GET_SETTINGS: u32 = 0xc1;
    pub const SET_SETTINGS: u32 = 0xc2;
    pub const SERVER_INFO: u32 = 0xc3;
    pub const ACCOUNT_REPLY: u32 = 0xca;
    pub const SAVE_ACCOUNT: u32 = 0xcb;
    pub const GET_ACCOUNT: u32 = 0xcc;
    pub const LIST_ACCOUNTS: u32 = 0xcd;
    pub const ACCOUNT_CHANGED: u32 = 0xce;
    pub const DELETE_ACCOUNT: u32 = 0xcf;
    pub const BROADCAST: u32 = 0xd0;
    pub const TRANSFERS: u32 = 0xe0;
    pub const TASK_COMPLETE: u32 = 0xff;
    pub const POST_NEWS: u32 = 0xFD_0000;
    pub const GET_NEWS: u32 = 0xFD_0001;
    pub const DELETE_NEWS: u32 = 0xFD_0002;
    pub const DELETE_ALL_NEWS: u32 = 0xFD_0003;
    pub const USER_STATE: u32 = 0xF000_0000;
    pub const KEEPALIVE: u32 = 0xFFFF_FFFF;
}

/// Error codes sent in command 0, tag 1.
pub mod err {
    pub const NO_PRIVILEGE: u16 = 2;
    pub const LOW_MEMORY: u16 = 4;
    pub const INCORRECT_LOGIN: u16 = 0x64;
    pub const USER_NOT_FOUND: u16 = 0x65;
    pub const NO_SUCH_ACCOUNT: u16 = 0x66;
    pub const INVALID_LOGIN_NAME: u16 = 0x67;
    pub const SERVER_FULL: u16 = 0x69;
    pub const ACCOUNT_EXISTS: u16 = 0x6a;
    pub const CHANNEL_NOT_FOUND: u16 = 0xc8;
    pub const WRONG_CHANNEL_PASSWORD: u16 = 0xca;
    pub const MODERATED: u16 = 0xcb;
    pub const NOT_OPERATOR: u16 = 0xcc;
    pub const TOPIC_OPERATORS_ONLY: u16 = 0xcd;
    pub const ALREADY_IN_CHANNEL: u16 = 0xce;
    pub const NOT_A_MEMBER: u16 = 0xcf;
    pub const NOT_IN_CHANNEL: u16 = 0xd0;
    pub const TOO_MANY_CHANNELS: u16 = 0xd1;
    pub const NOT_FOUND: u16 = 0x12c;
    pub const IN_DROP_BOX: u16 = 0x12d;
    pub const NO_DOWNLOAD_PRIVILEGE: u16 = 0x12e;
    pub const DESTINATION_NOT_FOUND: u16 = 0x131;
    pub const NO_REPLACE_PRIVILEGE: u16 = 0x133;
    pub const NO_UPLOAD_PRIVILEGE: u16 = 0x134;
    pub const NOT_UPLOAD_FOLDER: u16 = 0x135;
    pub const DOWNLOAD_FROM_DROP_BOX: u16 = 0x138;
    pub const NO_FILE_COMMENT_PRIVILEGE: u16 = 0x13c;
    pub const NO_FOLDER_COMMENT_PRIVILEGE: u16 = 0x13d;
    pub const BUSY: u16 = 0x13e;
    pub const NO_SUCH_ARTICLE: u16 = 0x192;
    pub const UNKNOWN_COMMAND: u16 = 0x3e7;
}

/// Privilege bits, numbered as Mac OS `BitTst` does: bit 0 is the most
/// significant bit of the 64-bit mask.
pub mod privs {
    pub const ADMIN: u32 = 0x00;
    pub const ACCOUNT_HOLDER: u32 = 0x01;
    pub const NESTED_HOME: u32 = 0x03;
    pub const HOME_IS_ROOT: u32 = 0x04;
    pub const DOWNLOAD: u32 = 0x0a;
    pub const UPLOAD: u32 = 0x0b;
    pub const UPLOAD_ANYWHERE: u32 = 0x0c;
    pub const VIEW_DROP_BOXES: u32 = 0x0d;
    pub const CHANGE_FOLDER_MODE: u32 = 0x0e;
    pub const MOVE_FILES: u32 = 0x0f;
    pub const DELETE_FILES: u32 = 0x10;
    pub const RENAME_FILES: u32 = 0x11;
    pub const COMMENT_FILES: u32 = 0x12;
    pub const CREATE_FOLDERS: u32 = 0x13;
    pub const MOVE_FOLDERS: u32 = 0x14;
    pub const RENAME_FOLDERS: u32 = 0x15;
    pub const DELETE_FOLDERS: u32 = 0x16;
    pub const COMMENT_FOLDERS: u32 = 0x17;
    pub const KICK: u32 = 0x18;
    pub const EXTENDED_USER_INFO: u32 = 0x19;
    pub const CHAT: u32 = 0x1c;
    pub const ACCOUNTS: u32 = 0x21;
    pub const NEWS_ADMIN: u32 = 0x22;
    pub const VIEW_LOG: u32 = 0x23;
    pub const SERVER_INFO: u32 = 0x24;
    pub const STATISTICS: u32 = 0x25;
    pub const EMPTY_TRASH: u32 = 0x27;
    pub const BROADCAST: u32 = 0x28;
    pub const BAN: u32 = 0x2a;
    pub const AGREEMENT: u32 = 0x2c;
    pub const ADVANCED_SETTINGS: u32 = 0x2d;
    pub const TRACKERS: u32 = 0x2e;
    pub const SEARCH: u32 = 0x2f;
    pub const POST_NEWS: u32 = 0x30;

    /// Whether `mask` has privilege `bit`.
    pub fn has(mask: u64, bit: u32) -> bool {
        mask & (1u64 << (63 - bit)) != 0
    }

    /// The mask with only `bit` set.
    pub fn bit(bit: u32) -> u64 {
        1u64 << (63 - bit)
    }
}

#[cfg(test)]
mod tests {
    use super::privs::*;

    #[test]
    fn bit_numbering_is_msb_first() {
        let admin = 0x803f_ffc8_7daf_8000u64;
        assert!(has(admin, ADMIN));
        assert!(!has(admin, ACCOUNT_HOLDER));
        assert!(has(admin, BROADCAST));
        let guest = 0x0030_0008_0001_8000u64;
        assert!(has(guest, DOWNLOAD) && has(guest, UPLOAD) && has(guest, CHAT));
        assert!(has(guest, SEARCH) && has(guest, POST_NEWS));
        assert!(!has(guest, UPLOAD_ANYWHERE));
        assert_eq!(bit(0x30), 0x8000);
    }
}
