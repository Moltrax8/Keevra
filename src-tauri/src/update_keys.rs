//! Baked update-signing public keys (ed25519, 32 bytes each).
//!
//! Private keys NEVER enter the repo — they live offline with the release
//! manager (see docs/UPDATER_SECURITY.md). Rotation: keep the previous key
//! alongside the primary during the rotation window; verification accepts
//! any listed key, and the window closes by removing the old entry.
//!
//! Key 0: generated 2026-10-05 via `update-tool gen-key` on the release
//! manager machine; public half below (`qIa4woC9NAQ033ULzG+5pLSoxiRYuYSzLupT5KTEVwc=`).
/// Primary release-signing key(s).
pub const UPDATE_SIGNING_KEYS: [[u8; 32]; 1] = [[
    0xa8, 0x86, 0xb8, 0xc2, 0x80, 0xbd, 0x34, 0x04, 0x34, 0xdf, 0x75, 0x0b, 0xcc, 0x6f, 0xb9, 0xa4,
    0xb4, 0xa8, 0xc6, 0x24, 0x58, 0xb9, 0x84, 0xb3, 0x2e, 0xea, 0x53, 0xe4, 0xa4, 0xc4, 0x57, 0x07,
]];
