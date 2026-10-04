const BLOCK_SIZE: usize = 64;

pub fn hs256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut k = [0u8; BLOCK_SIZE];

    if key.len() > BLOCK_SIZE {
        let hashed = sha256(key);
        k[..32].copy_from_slice(&hashed);
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5cu8; BLOCK_SIZE];

    for i in 0..BLOCK_SIZE {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }

    let mut inner = Vec::with_capacity(BLOCK_SIZE + message.len());

    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(message);

    let inner_hash = sha256(&inner);

    let mut outer = Vec::with_capacity(BLOCK_SIZE + inner_hash.len());

    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);

    sha256(&outer)
}
