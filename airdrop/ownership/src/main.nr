use airdrop::constants::{
    MAX_OWNERSHIP_JSON_LEN, MAX_OWNERSHIP_RECORD_LEN, NODE_ID_LEN, OWNERSHIP_JSON_LEN,
};
use airdrop::utils::{
    check_encrypted_json_ownership, decrypt_record, encrypt_record, encrypt_substring,
    get_proxy_pubkeys, JsonSlice, str_to_bounded_vec, verify_proxy_sig,
};
use json_parser::{JSON, JSON512b};

pub struct SignaturePayload {
    pub encrypted_record: BoundedVec<u8, MAX_OWNERSHIP_RECORD_LEN>,
    pub encrypted_record_signed: [u8; 64],
    pub proxy_pubkey_x: [u8; 32],
    pub proxy_pubkey_y: [u8; 32],
}

pub struct AirdropPayload {
    pub node_id: str<NODE_ID_LEN>,
    pub graphql_response: JsonSlice<MAX_OWNERSHIP_JSON_LEN>,
}

impl SignaturePayload {
    pub fn verify_proxy_sig(self) {
        verify_proxy_sig(
            self.encrypted_record,
            self.proxy_pubkey_x,
            self.proxy_pubkey_y,
            self.encrypted_record_signed,
        );
    }
}

impl AirdropPayload {
    pub fn check_ownership(self) {
        check_ownership(self.graphql_response.json, self.node_id);
    }
}

fn main(
    mut key: [u32; 8],
    ctr: u32,
    mut nonce: [u32; 3],
    signature_payload: pub SignaturePayload,
    airdrop_payload: pub AirdropPayload,
) {
    // 1. Verify encrypted_record comes from the trusted proxy.
    signature_payload.verify_proxy_sig();

    // 2. Encrypt the substring of the GraphQL response on the specific keystream offset (start of the JSON in the full encrypted record).
    let encrypted_subtring: BoundedVec<u8, MAX_OWNERSHIP_JSON_LEN> = encrypt_substring(
        key,
        ctr,
        nonce,
        airdrop_payload.graphql_response.json,
        airdrop_payload.graphql_response.start,
    );

    // 3. Check whether the encrypted substring (JSON) is present in the full encrypted record.
    check_encrypted_json_ownership(
        signature_payload.encrypted_record,
        encrypted_subtring,
        airdrop_payload.graphql_response.start,
    );

    // 4. Check for the node id in the GraphQL response.
    airdrop_payload.check_ownership();
}

fn check_ownership(json_str: str<MAX_OWNERSHIP_JSON_LEN>, expected_node_id: str<NODE_ID_LEN>) {
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
    let id: BoundedVec<u8, NODE_ID_LEN> = viewer.get_string_unchecked("id".as_bytes());

    // Assert `id` is the expected value.
    let expected_node_id_vec: BoundedVec<u8, NODE_ID_LEN> = str_to_bounded_vec(expected_node_id);
    assert(id == expected_node_id_vec);
}

#[test]
fn test_main() {
    let (mut key, ctr, mut nonce) = get_test_key_ctr_nonce();
    let node_id: str<NODE_ID_LEN> = "U_kgDOAGMfIw";

    // Calculate ciphertext.
    // let plaintext: str<MAX_OWNERSHIP_JSON_LEN> =
    //     r#"xxxxxxxxxxxxxxxx{"viewer":{"id":"U_xxxxxxxxxx"}}xxxxxxxxxxxxxxxx"#;
    // let mut plaintext_vec: BoundedVec<u8, MAX_OWNERSHIP_RECORD_LEN> = BoundedVec::new();
    // plaintext_vec.extend_from_array(plaintext.as_bytes());
    // let encrypted_record = encrypt_record(key, ctr, nonce, plaintext_vec);
    let encrypt_record_array = [
        85, 188, 5, 209, 92, 186, 46, 246, 214, 185, 57, 215, 134, 204, 135, 99, 160, 52, 89, 63,
        42, 254, 175, 229, 11, 116, 15, 49, 4, 135, 95, 214, 234, 242, 41, 187, 211, 108, 8, 216,
        158, 25, 140, 208, 202, 176, 110, 235, 83, 102, 130, 151, 234, 185, 163, 228, 110, 20, 122,
        230, 42, 57, 63, 182, 230, 74, 40, 110, 206, 118, 129, 210, 46, 49, 35, 168, 74, 223, 32,
        115, 195, 198, 40, 51, 193, 59, 112, 65, 1, 35, 239, 111, 38, 209, 97, 60, 217, 24, 138,
        116, 69, 65, 167, 121, 21, 226, 91, 172, 128, 111, 94, 51, 92, 190, 44, 214, 193, 6, 134,
        254, 118, 181, 182, 59, 236, 42, 128, 111, 220, 9, 230, 188, 39, 187, 112, 20, 132, 28, 241,
        34, 29, 185, 27, 126, 213, 145, 103, 166, 185, 231, 178, 60, 44, 89, 91, 53, 217, 173, 106,
        121, 42, 143, 145, 10, 204, 188, 56, 188, 246, 130, 183, 196, 143, 206, 238, 28, 150, 248,
        106, 154, 226, 35, 169, 218, 56, 1, 220, 4, 121, 251, 183, 224, 78, 142, 149, 19, 128, 35,
        29, 250, 211, 209, 77, 149, 156, 196, 217, 168, 91, 203, 108, 252, 50, 140, 20, 222, 178,
        203, 92, 103, 227, 131, 116, 111, 194, 96, 194, 118, 100, 163, 106, 59, 72, 152, 59, 45,
        161, 62, 75, 104, 87, 114, 213, 60, 216, 182, 21, 14, 247, 60, 164, 107, 194, 33, 2, 218,
        133, 83, 138, 154, 212, 178, 239, 85, 220, 145, 251, 35, 109, 227, 168, 154, 26, 193, 185,
        9, 190, 120, 163, 248, 207, 228, 241, 227, 160, 217, 8, 107, 207, 100, 255, 58, 130, 92, 93,
        157, 74, 203, 216, 166, 138, 51, 254, 99, 239, 65, 77, 246, 195, 21, 23, 193, 117, 173, 34,
        98, 52, 239, 171, 91, 195, 163, 16, 209, 169, 47, 149, 252, 217, 149, 1, 255, 192, 199, 80,
        220, 41, 7, 225, 166, 52, 108, 254, 181, 133, 244, 82, 146, 114, 218, 162, 64, 174, 220,
        223, 104, 170, 83, 169, 60, 185, 32, 86, 12, 40, 87, 43, 77, 181, 184, 11, 119, 133, 127,
        240, 99, 99, 207, 99, 202, 148, 97, 120, 150, 178, 106, 27, 7, 144, 63, 226, 58, 49, 163,
        235, 100, 195, 94, 225, 123, 79, 244, 227, 227, 179, 191, 23, 54, 98, 102, 68, 249, 167,
        121, 38, 157, 214, 252, 213, 163, 8, 2, 150, 182, 80, 159, 11, 187, 20, 85, 84, 8, 8, 165,
        29, 89, 4, 53, 65, 219, 136, 29, 12, 183, 163, 140, 107, 90, 106, 166, 19, 133, 143, 255,
        63, 111, 168, 8, 44, 77, 45, 253, 99, 61, 190, 255, 188, 5, 121, 63, 213, 32, 252, 255, 71,
        183, 89, 11, 63, 187, 229, 21, 30, 187, 101, 10, 238, 168, 88, 16, 26, 157, 153, 187, 144,
        226, 23, 72, 251, 3, 141, 125, 232, 250, 78, 230, 15, 163, 200, 90, 245, 54, 58, 46, 225,
        161, 156, 187, 189, 145, 102, 82, 23, 5, 34, 109, 228, 148, 92, 217, 156, 86, 86, 214, 40,
        174, 32, 10, 203, 78, 100, 170, 213, 228, 12, 74, 35, 114, 54, 207, 65, 178, 211, 156, 6,
        156, 81, 90, 45, 65, 64, 103, 65, 115, 113, 233, 183, 191, 23, 28, 251, 67, 154, 198, 147,
        134, 68, 7, 38, 58, 253, 5, 219, 100, 90, 82, 222, 88, 186, 213, 104, 173, 119, 54, 133, 71,
        65, 32, 113, 199, 73, 237, 196, 39, 51, 73, 213, 174, 245, 124, 48, 147, 203, 55, 188, 25,
        133, 79, 5, 118, 171, 91, 113, 102, 154, 219, 208, 181, 231, 82, 149, 169, 41, 90, 83, 202,
        136, 113, 1, 208, 87, 145, 69, 231, 165, 159, 141, 227, 127, 0, 223, 85, 55, 198, 43, 3,
        242, 182, 41, 219, 229, 237, 224, 72, 123, 242, 27, 77, 205, 78, 206, 127, 169, 6, 114, 186,
        85, 143, 55, 121, 105, 11, 227, 96, 165, 136, 189, 27, 254, 49, 97, 125, 122, 71, 34, 212,
        41, 252, 105, 186, 135, 70, 68, 33, 204, 29, 251, 92, 3, 4, 24, 236, 203, 223, 39, 95, 146,
        37, 111, 214, 81, 150, 246, 148, 215, 71, 198, 140, 193, 228, 55, 238, 148, 253, 110, 37,
        40, 240, 44, 175, 162, 234, 210, 38, 50, 87, 156, 189, 112, 35, 175, 166, 210, 55, 95, 23,
        2, 41, 107, 157, 182, 52, 44, 74, 240, 230, 225, 27, 87, 215, 4, 225, 210, 95, 81, 85, 115,
        69, 43, 108, 129, 207, 55, 166, 109, 101, 12, 14, 139, 214, 144, 139, 186, 4, 212, 66, 212,
        223, 121, 40, 193, 125, 72, 184, 25, 160, 121, 157, 246, 153, 110, 126, 47, 128, 50, 108,
        26, 174, 215, 220, 207, 104, 40, 97, 175, 93, 220, 148, 153, 57, 37, 88, 87, 4, 80, 139,
        228, 22, 139, 240, 215, 126, 59, 181, 96, 47, 195, 72, 200, 90, 226, 189, 93, 118, 16, 117,
        147, 99, 93, 156, 59, 244, 245, 198, 102, 171, 189, 43, 206, 183, 114, 173, 203, 39, 88,
        197, 203, 43, 184, 123, 0, 136, 55, 228, 35, 76, 136, 251, 181, 70, 195, 71, 238, 103, 207,
        216, 241, 64, 69, 245, 28, 67, 199, 36, 129, 252, 227, 151, 169, 97, 217, 38, 118, 29, 212,
        218, 177, 182, 210, 28, 168, 242, 206, 109, 125, 155, 84, 211, 146, 156, 192, 89, 185, 70,
        76, 35, 70, 246, 44, 198, 189, 214, 121, 82, 210, 10, 244, 212, 164, 4, 106, 179, 90, 149,
        115, 14, 103, 159, 105, 141, 128, 117, 158, 87, 105, 14, 22, 207, 164, 1, 104, 177, 43, 118,
        158, 98, 122, 234, 86, 206, 51, 10, 168, 117, 239, 138, 255, 157, 78, 8, 237, 2, 126, 11,
        143, 171, 239, 112, 239, 132, 155, 57, 225, 178, 125, 148, 72, 195, 193, 222, 233, 160, 100,
        195, 114, 63, 64, 143, 50, 142, 25, 155, 68, 176, 244, 173, 194, 49, 207, 91, 202, 116, 78,
        225, 3, 236, 253, 225, 47, 250, 217, 94, 245, 177, 15, 199, 129, 171, 14, 200, 232, 58, 173,
        1, 51, 238, 253, 253, 241, 231, 210, 57, 19, 213, 98, 205, 234, 68, 33, 129, 204, 11, 238,
        59, 109, 205, 255, 204, 186, 139, 114, 207, 59, 25, 166, 228, 7, 156, 187, 74, 114, 255,
        129, 230, 2, 157, 58, 25, 141, 56, 81, 132, 234, 54, 86, 108, 23, 39, 216, 14, 28, 120, 160,
        227, 30, 86, 37, 37, 74, 211, 243, 233, 140, 196, 56, 72, 12, 113, 25, 77, 4, 172, 202, 128,
        225, 25, 53, 176, 94, 75, 125, 83, 211, 118, 77, 201, 178, 169, 220, 123, 45, 18, 234, 190,
        29, 161, 129, 46, 223, 76, 211, 78, 152, 39, 134, 20, 253, 54, 9, 114, 38, 194, 125, 225, 4,
        0, 131, 139, 173, 47, 56, 142, 107, 57, 67, 43, 152, 194, 107, 206, 65, 224, 124, 251, 29,
        214, 191, 156, 218, 2, 122, 198, 70, 218, 151, 68, 17, 125, 187, 60, 172, 222, 106, 40, 73,
        23, 163, 196, 212, 184, 17, 142, 49, 55, 178, 19, 109, 3, 130, 61, 89, 38, 231, 132, 125,
        190, 202, 167, 198, 65, 68, 136, 196,
    ];
    let mut encrypted_record: BoundedVec<u8, MAX_OWNERSHIP_RECORD_LEN> = BoundedVec::new();
    encrypted_record.extend_from_array(encrypt_record_array);

    // DEV: we pad `json` with empty spaces because any other character will make JSON parsing [l. 55] fail.
    let json: str<MAX_OWNERSHIP_JSON_LEN> =
        r#"{"viewer":{"id":"U_kgDOAGMfIw"}}                                "#;
    let start: u32 = 1193; // Start index of the JSON in the decrypted response.
    let end: u32 = OWNERSHIP_JSON_LEN + start; // End index of the JSON in the decrypted response.
    let json_slice = JsonSlice { json, start, end };

    let encrypted_record_signed: [u8; 64] = [
        187, 69, 180, 13, 231, 237, 11, 71, 239, 107, 34, 244, 32, 144, 14, 36, 3, 248, 60, 62, 224,
        202, 194, 60, 43, 151, 207, 108, 127, 90, 32, 169, 54, 19, 78, 158, 158, 186, 144, 103, 33,
        40, 200, 60, 34, 170, 138, 16, 100, 141, 12, 64, 210, 170, 42, 253, 216, 83, 185, 105, 111,
        238, 119, 26,
    ]; // Removed the last 0x01 which is the recovery id.
    let (proxy_pubkey_x, proxy_pubkey_y) = get_proxy_pubkeys();

    let signature_payload = SignaturePayload {
        encrypted_record,
        encrypted_record_signed,
        proxy_pubkey_x,
        proxy_pubkey_y,
    };

    let airdrop_payload = AirdropPayload { graphql_response: json_slice, node_id };

    main(key, ctr, nonce, signature_payload, airdrop_payload);
}

/*
    Test helpers.
*/

fn get_test_key_ctr_nonce() -> ([u32; 8], u32, [u32; 3]) {
    let key: [u32; 8] = [
        319062342, 3477468091, 2613547938, 3219018586, 3076792630, 3435854548, 631382744,
        1781285851,
    ];
    let ctr: u32 = 1;
    let mut nonce: [u32; 3] = [3662699372, 1616680427, 3314891395];
    (key, ctr, nonce)
}
