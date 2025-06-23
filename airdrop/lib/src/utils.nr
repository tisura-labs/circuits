use crate::constants::{PROXY_PUBKEY_X, PROXY_PUBKEY_Y};
use chacha20::ChaCha20;
use keccak256::keccak256;
use std::ecdsa_secp256k1::verify_signature;

pub struct JsonSlice<let MAX_JSON_LENGTH: u32> {
    json: str<MAX_JSON_LENGTH>,
    start: u32,
    end: u32,
}

pub fn search_json<let MAX_LEN: u32, let MAX_JSON_LENGTH: u32>(
    decrypted: BoundedVec<u8, MAX_LEN>,
    json_slice: JsonSlice<MAX_JSON_LENGTH>,
) {
    for i in 0..MAX_JSON_LENGTH {
        if i + json_slice.start < json_slice.end {
            assert(
                decrypted.get(i + json_slice.start) == json_slice.json.as_bytes()[i],
                "JSON does not match expected value.",
            );
        }
    }
}

fn verify_proxy_sig<let max_record_len: u32>(
    encrypted_record: BoundedVec<u8, max_record_len>,
    proxy_pubkey_x: [u8; 32],
    proxy_pubkey_y: [u8; 32],
    encrypted_record_signature: [u8; 64],
) {
    // DEV: Is using ciphertext.storage() safe?
    let encrypted_record_hash = keccak256(encrypted_record.storage(), encrypted_record.len());
    let is_verified = verify_signature(
        proxy_pubkey_x,
        proxy_pubkey_y,
        encrypted_record_signature,
        encrypted_record_hash,
    );
    assert(proxy_pubkey_x == PROXY_PUBKEY_X, "Unexpected proxy public key X!");
    assert(proxy_pubkey_y == PROXY_PUBKEY_Y, "Unexpected proxy public key Y!");
    assert(is_verified, "proxy did not sign encrypted_record_hash!");
}

fn decrypt_record<let max_record_len: u32>(
    mut key: [u32; 8],
    ctr: u32,
    mut nonce: [u32; 3],
    encrypted_record: BoundedVec<u8, max_record_len>,
) -> BoundedVec<u8, max_record_len> {
    let chacha20 = ChaCha20::new(&mut key, ctr, &mut nonce);
    let decrypted_record: BoundedVec<u8, max_record_len> = chacha20.decrypt(encrypted_record);
    decrypted_record
}

fn get_proxy_pubkeys() -> ([u8; 32], [u8; 32]) {
    (PROXY_PUBKEY_X, PROXY_PUBKEY_Y)
}

#[test]
fn test_search_json() {
    let decrypted: BoundedVec<u8, 200> = BoundedVec::from_array([
        13, 10, 13, 10, 123, 34, 100, 97, 116, 97, 34, 58, 123, 34, 114, 101, 112, 111, 115, 105,
        116, 111, 114, 121, 34, 58, 123, 34, 110, 97, 109, 101, 34, 58, 34, 109, 111, 110, 111, 34,
        44, 34, 111, 119, 110, 101, 114, 34, 58, 123, 34, 108, 111, 103, 105, 110, 34, 58, 34, 116,
        105, 115, 117, 114, 97, 45, 108, 97, 98, 115, 34, 125, 44, 34, 100, 101, 102, 97, 117, 108,
        116, 66, 114, 97, 110, 99, 104, 82, 101, 102, 34, 58, 123, 34, 116, 97, 114, 103, 101, 116,
        34, 58, 123, 34, 104, 105, 115, 116, 111, 114, 121, 34, 58, 123, 34, 116, 111, 116, 97, 108,
        67, 111, 117, 110, 116, 34, 58, 53, 48, 125, 125, 125, 125, 125, 125, 23, 239, 191, 189,
        239, 191, 189, 70, 239, 191, 189, 36, 239, 191, 189, 239, 191, 189, 53, 239, 191, 189, 47,
        62, 77, 79, 239, 191, 189, 239, 191, 189, 73, 239, 191, 189, 98, 125, 239, 191, 189, 239,
        191, 189, 239, 191, 189, 239, 191, 189, 239, 191, 189, 239, 191, 189, 239, 191, 189, 84, 57,
        35, 239, 191, 189,
    ]);

    // Example JSON in string format padded with empty spaces.
    let json: str<160> = "{\"data\":{\"repository\":{\"name\":\"mono\",\"owner\":{\"login\":\"tisura-labs\"},\"defaultBranchRef\":{\"target\":{\"history\":{\"totalCount\":50}}}}}}                             ";
    let start: u32 = 4; // Start index of the JSON in the decrypted response.
    let end: u32 = 135; // End index of the JSON in the decrypted response.
    let jsonSlice = JsonSlice { json, start, end };

    search_json(decrypted, jsonSlice);
}
