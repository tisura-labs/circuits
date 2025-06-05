use airdrop::{check_json, JsonSlice};
use chacha20::ChaCha20;
use json_parser::{JSON, JSON512b};

global MAX_OWNERSHIP_CIPHERTEXT_LEN: u32 = 160;
global MAX_JSON_LENGTH: u32 = 41; // In Ownership, len of JSON is always 41.
global NODE_ID_LEN: u32 = 12;

// TODO: Refactor to implement a struct.

fn main(
    mut key: [u32; 8],
    ctr: u32,
    mut nonce: [u32; 3],
    ciphertext: pub BoundedVec<u8, MAX_OWNERSHIP_CIPHERTEXT_LEN>,
    node_id: pub str<NODE_ID_LEN>,
    json_slice: pub JsonSlice<MAX_JSON_LENGTH>,
) {
    // TODO: Check for trusted proxy signature.
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
        "data": {
            "viewer": {
                "id": "<node_id>"
            }
        }
    }

    Where <node_id> is a 12 character string.
    */

    // Parse decrypted API response.
    let json: JSON512b = JSON::parse_json_from_string(json_str);
    let data: JSON512b = json.get_object_unchecked("data".as_bytes());
    let viewer: JSON512b = data.get_object_unchecked("viewer".as_bytes());
    let id: BoundedVec<u8, MAX_OWNERSHIP_CIPHERTEXT_LEN> =
        viewer.get_string_unchecked("id".as_bytes());

    // Assert `id` is the expected value.
    assert(id == BoundedVec::from_array(expected_node_id.as_bytes()));
}

#[test]
fn test_main() {
    let mut key: [u32; 8] = [
        0x00000001, 0x00000002, 0x00000003, 0x00000004, 0x00000005, 0x00000006, 0x00000007,
        0x00000008,
    ];
    let ctr: u32 = 0x00000001;
    let mut nonce: [u32; 3] = [0x00000001, 0x00000002, 0x00000003];

    // Example ciphertext from a close to reality GitHub GraphQL API response.
    let plaintext: str<MAX_OWNERSHIP_CIPHERTEXT_LEN> = r#"\r\n\r\n{"data":{"viewer":{"id":"U_XXXXXXXXXX"}}}��F�$��5�/>MO��I��������}���������T#��������"#;
    let node_id: str<NODE_ID_LEN> = "U_XXXXXXXXXX";

    // Calculate ciphertext.
    let mut plaintext_vec: BoundedVec<u8, MAX_OWNERSHIP_CIPHERTEXT_LEN> = BoundedVec::new();
    plaintext_vec.extend_from_array(plaintext.as_bytes());
    let chacha = ChaCha20::new(&mut key, ctr, &mut nonce);
    let ciphertext = chacha.encrypt(plaintext_vec);
    println(ciphertext);

    let json: str<MAX_JSON_LENGTH> = r#"{"data":{"viewer":{"id":"U_XXXXXXXXXX"}}}"#;
    let start: u32 = 8; // Start index of the JSON in the decrypted response.
    let end: u32 = 49; // End index of the JSON in the decrypted response.
    let jsonSlice = JsonSlice { json, start, end };
    main(key, ctr, nonce, ciphertext, node_id, jsonSlice);
}
