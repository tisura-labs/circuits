use airdrop::{constants::{PROXY_PUBKEY_X, PROXY_PUBKEY_Y}, utils::{check_json, JsonSlice}};
use chacha20::ChaCha20;
use json_parser::{JSON, JSON512b};
use keccak256::keccak256;

global MAX_OWNERSHIP_CIPHERTEXT_LEN: u32 = 160;
global MAX_JSON_LENGTH: u32 = 32; // In Ownership, len of JSON is always 32.
global NODE_ID_LEN: u32 = 12;

// TODO: Refactor to implement a struct.

fn main(
    mut key: [u32; 8],
    ctr: u32,
    mut nonce: [u32; 3],
    ciphertext: pub BoundedVec<u8, MAX_OWNERSHIP_CIPHERTEXT_LEN>,
    node_id: pub str<NODE_ID_LEN>,
    json_slice: pub JsonSlice<MAX_JSON_LENGTH>,
    ciphertext_hash_signed: pub [u8; 64],
) {
    let record_hash: [u8; 32] = keccak256(ciphertext.storage(), ciphertext.len());
    // Check for trusted proxy signature to be sure the response comes from a gh graphql endpoint.
    let valid_signature = std::ecdsa_secp256k1::verify_signature(
        PROXY_PUBKEY_X,
        PROXY_PUBKEY_Y,
        ciphertext_hash_signed,
        record_hash,
    );
    assert(valid_signature);

    let chacha20 = ChaCha20::new(&mut key, ctr, &mut nonce);
    // `ciphertext` is the encrypted response of the gh graphql endpoint.
    let decrypted: BoundedVec<u8, MAX_OWNERSHIP_CIPHERTEXT_LEN> = chacha20.decrypt(ciphertext);

    // Check if the decrypted response contains the expected JSON.
    check_json(decrypted, json_slice);

    // Check if the parsed node id is the expected value.
    check_ownership(json_slice.json, node_id);
}

fn check_ownership(json_str: str<MAX_JSON_LENGTH>, expected_node_id: str<NODE_ID_LEN>) {
    /*
    Expected JSON schema:
    {
        "viewer": {
            "id": "<node_id>"
        }
    }
    Where <node_id> is a 12 character string.
    */

    // Parse decrypted API response.
    let json: JSON512b = JSON::parse_json_from_string(json_str);
    let viewer: JSON512b = json.get_object_unchecked("viewer".as_bytes());
    let id: BoundedVec<u8, MAX_OWNERSHIP_CIPHERTEXT_LEN> =
        viewer.get_string_unchecked("id".as_bytes());

    // Assert `id` is the expected value.
    assert(id == BoundedVec::from_array(expected_node_id.as_bytes()));
}

// DEV: Please extend the test suite with additional test cases, do not modify the existing tests.

#[test]
fn test_main() {
    let mut key: [u32; 8] = [
        0x00000001, 0x00000002, 0x00000003, 0x00000004, 0x00000005, 0x00000006, 0x00000007,
        0x00000008,
    ];
    let ctr: u32 = 0x00000001;
    let mut nonce: [u32; 3] = [0x00000001, 0x00000002, 0x00000003];
    let plaintext: str<MAX_OWNERSHIP_CIPHERTEXT_LEN> = "{\"data\":{\"viewer\":{\"id\":\"U_xxxxxxxxxx\"}}}xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    let node_id: str<NODE_ID_LEN> = "U_xxxxxxxxxx";

    // Calculate ciphertext.
    let mut plaintext_vec: BoundedVec<u8, MAX_OWNERSHIP_CIPHERTEXT_LEN> = BoundedVec::new();
    plaintext_vec.extend_from_array(plaintext.as_bytes());
    let chacha = ChaCha20::new(&mut key, ctr, &mut nonce);
    let ciphertext = chacha.encrypt(plaintext_vec);
    println(ciphertext);

    // TODO: test for \\r\\n\\r\\n.
    let json: str<MAX_JSON_LENGTH> = "{\"viewer\":{\"id\":\"U_xxxxxxxxxx\"}}";
    let start: u32 = 8; // Start index of the JSON in the decrypted response.
    let end: u32 = MAX_OWNERSHIP_CIPHERTEXT_LEN; // End index of the JSON in the decrypted response.
    let json_slice = JsonSlice { json, start, end };
    let ciphertext_hash_signed: [u8; 64] = [
        254, 208, 153, 65, 105, 112, 138, 143, 146, 22, 214, 166, 182, 89, 210, 206, 83, 95, 91,
        186, 90, 2, 25, 76, 236, 94, 226, 143, 74, 185, 134, 85, 48, 59, 106, 99, 187, 119, 25, 249,
        175, 209, 255, 185, 24, 215, 51, 106, 21, 197, 17, 56, 66, 154, 230, 177, 51, 252, 249, 247,
        243, 247, 223, 131,
    ]; // Removed the last 0x01 which is the recovery id.

    main(
        key,
        ctr,
        nonce,
        ciphertext,
        node_id,
        json_slice,
        ciphertext_hash_signed,
    );
}

/*
    Helper.
*/
#[test]
fn test_generate_ciphertext() {
    let mut key: [u32; 8] = [
        0x00000001, 0x00000002, 0x00000003, 0x00000004, 0x00000005, 0x00000006, 0x00000007,
        0x00000008,
    ];
    let ctr: u32 = 0x00000001;
    let mut nonce: [u32; 3] = [0x00000001, 0x00000002, 0x00000003];
    let plaintext: str<MAX_OWNERSHIP_CIPHERTEXT_LEN> = "{\"data\":{\"viewer\":{\"id\":\"U_xxxxxxxxxx\"}}}, xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

    let mut plaintext_vec: BoundedVec<u8, MAX_OWNERSHIP_CIPHERTEXT_LEN> = BoundedVec::new();
    plaintext_vec.extend_from_array(plaintext.as_bytes());
    let chacha = ChaCha20::new(&mut key, ctr, &mut nonce);
    let ciphertext = chacha.encrypt(plaintext_vec);

    println(ciphertext);
}
