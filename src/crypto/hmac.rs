// SPDX-FileCopyrightText: 2026 Ivan Zorin <creator@localzet.com> (Localzet contributions)
// SPDX-License-Identifier: AGPL-3.0
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub fn hs256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_4231_test_case_one() {
        assert_eq!(
            hs256(&[0x0b; 20], b"Hi There"),
            [
                0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
                0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
                0x2e, 0x32, 0xcf, 0xf7
            ]
        );
    }
}
