//! Baked update-signing public keys (ed25519, 32 bytes each).
//!
//! Private keys NEVER enter the repo — they live offline with the release
//! manager (see docs/UPDATER_SECURITY.md). Rotation: keep the previous key
//! alongside the primary during the rotation window; verification accepts
//! any listed key, and the window closes by removing the old entry.
//!
//! Key 0: generated 2026-10-05 via `update-tool gen-key` on the release
//! manager machine; public half below (`qIa4woC9NAQ033ULzG+5pLSoxiRYuYSzLupT5KTEVwc=`).
//! Retained so any artifact signed with it still verifies during the rotation
//! window; it is not used to sign new releases.
//! Key 1: generated 2026-11-07 via `update-tool gen-key`; public half
//! (`w0xD17RKn3mJpDGTgryogUU7iJYuAOg8PBVP/eKrHzU=`). Active signing key for
//! releases from the 0.2.2 re-issue onward.
/// Accepted release-signing key(s).
pub const UPDATE_SIGNING_KEYS: [[u8; 32]; 2] = [
    [
        0xa8, 0x86, 0xb8, 0xc2, 0x80, 0xbd, 0x34, 0x04, 0x34, 0xdf, 0x75, 0x0b, 0xcc, 0x6f, 0xb9,
        0xa4, 0xb4, 0xa8, 0xc6, 0x24, 0x58, 0xb9, 0x84, 0xb3, 0x2e, 0xea, 0x53, 0xe4, 0xa4, 0xc4,
        0x57, 0x07,
    ],
    [
        0xc3, 0x4c, 0x43, 0xd7, 0xb4, 0x4a, 0x9f, 0x79, 0x89, 0xa4, 0x31, 0x93, 0x82, 0xbc, 0xa8,
        0x81, 0x45, 0x3b, 0x88, 0x96, 0x2e, 0x00, 0xe8, 0x3c, 0x3c, 0x15, 0x4f, 0xfd, 0xe2, 0xab,
        0x1f, 0x35,
    ],
];
