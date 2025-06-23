use airdrop::constants::{
    MAX_OWNERSHIP_JSON_LENGTH, MAX_OWNERSHIP_RECORD_LEN, NODE_ID_LEN, PROXY_PUBKEY_X,
    PROXY_PUBKEY_Y,
};
use airdrop::utils::{decrypt_record, JsonSlice, search_json, verify_proxy_sig};
use json_parser::{JSON, JSON512b};

fn main(
    mut key: [u32; 8],
    ctr: u32,
    mut nonce: [u32; 3],
    encrypted_record: pub BoundedVec<u8, MAX_OWNERSHIP_RECORD_LEN>,
    node_id: pub str<NODE_ID_LEN>,
    graphql_response: pub JsonSlice<MAX_OWNERSHIP_JSON_LENGTH>,
    encrypted_record_signed: pub [u8; 64],
) {
    // 1. Verify encrypted_record comes from the trusted proxy.
    verify_proxy_sig(
        encrypted_record,
        PROXY_PUBKEY_X,
        PROXY_PUBKEY_Y,
        encrypted_record_signed,
    );

    // 2. Decrypt the encrypted_record.
    let decrypted_record: BoundedVec<u8, MAX_OWNERSHIP_RECORD_LEN> =
        decrypt_record(key, ctr, nonce, encrypted_record);

    // 3. Search for the expected GraphQL response in the decrypted record, the response is in JSON format.
    search_json(decrypted_record, graphql_response);

    // 4. Check for the node id in the GraphQL response.
    check_ownership(graphql_response.json, node_id);
}

fn check_ownership(json_str: str<MAX_OWNERSHIP_JSON_LENGTH>, expected_node_id: str<NODE_ID_LEN>) {
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
    let id: BoundedVec<u8, MAX_OWNERSHIP_RECORD_LEN> = viewer.get_string_unchecked("id".as_bytes());

    // Assert `id` is the expected value.
    let expected_node_id_vec: BoundedVec<u8, MAX_OWNERSHIP_RECORD_LEN> =
        BoundedVec::from_array(expected_node_id.as_bytes());
    assert(id == expected_node_id_vec);
}

// DEV: Please extend the test suite with additional test cases, do not modify the existing tests.

#[test]
fn test_main() {
    let (mut key, ctr, mut nonce) = get_test_key_ctr_nonce();
    let plaintext: str<MAX_OWNERSHIP_RECORD_LEN> = "{\"data\":{\"viewer\":{\"id\":\"U_xxxxxxxxxx\"}}}xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    let node_id: str<NODE_ID_LEN> = "U_xxxxxxxxxx";

    // Calculate ciphertext.
    let mut plaintext_vec: BoundedVec<u8, MAX_OWNERSHIP_RECORD_LEN> = BoundedVec::new();
    plaintext_vec.extend_from_array(plaintext.as_bytes());
    let ciphertext = decrypt_record(key, ctr, nonce, plaintext_vec); // decrypt_record encrypts plaintext.

    // TODO: test for \\r\\n\\r\\n.
    let json: str<MAX_OWNERSHIP_JSON_LENGTH> = "{\"viewer\":{\"id\":\"U_xxxxxxxxxx\"}}";
    let start: u32 = 8; // Start index of the JSON in the decrypted response.
    let end: u32 = MAX_OWNERSHIP_RECORD_LEN; // End index of the JSON in the decrypted response.
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
    Test helpers.
*/

fn get_test_key_ctr_nonce() -> ([u32; 8], u32, [u32; 3]) {
    let key: [u32; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    let ctr: u32 = 1;
    let mut nonce: [u32; 3] = [1, 2, 3];
    (key, ctr, nonce)
}
