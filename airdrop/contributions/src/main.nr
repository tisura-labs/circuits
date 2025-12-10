use airdrop::constants::{
    MAX_CONTRIBUTIONS_JSON_LEN, MAX_CONTRIBUTIONS_RECORD_LEN, MAX_REPO_NAME_LEN, MAX_REPO_OWNER_LEN,
};
use airdrop::utils::{
    check_encrypted_json_contributions, decrypt_record, encrypt_substring, get_proxy_pubkeys,
    JsonSlice, verify_proxy_sig,
};
use json_parser::{JSON, JSON512b};

pub struct SignaturePayload {
    pub encrypted_record: BoundedVec<u8, MAX_CONTRIBUTIONS_RECORD_LEN>,
    pub encrypted_record_signed: [u8; 64],
    pub proxy_pubkey_x: [u8; 32],
    pub proxy_pubkey_y: [u8; 32],
}

pub struct AirdropPayload {
    pub repo_name: BoundedVec<u8, MAX_REPO_NAME_LEN>,
    pub repo_owner: BoundedVec<u8, MAX_REPO_OWNER_LEN>,
    pub n_contributions: u64,
    pub graphql_response: JsonSlice<MAX_CONTRIBUTIONS_JSON_LEN>,
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
    pub fn check_contributions(self) {
        check_contributions(
            self.graphql_response.json,
            self.repo_name,
            self.repo_owner,
            self.n_contributions,
        );
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
    let encrypted_subtring: BoundedVec<u8, MAX_CONTRIBUTIONS_JSON_LEN> = encrypt_substring(
        key,
        ctr,
        nonce,
        airdrop_payload.graphql_response.json,
        airdrop_payload.graphql_response.start,
    );

    // 3. Check whether the encrypted substring (JSON) is present in the full encrypted record.
    check_encrypted_json_contributions(
        signature_payload.encrypted_record,
        encrypted_subtring,
        airdrop_payload.graphql_response.start,
        airdrop_payload.graphql_response.end,
    );

    // 4. Check for the number of contributions in the GraphQL response.
    airdrop_payload.check_contributions();
}

fn check_contributions(
    json_str: str<MAX_CONTRIBUTIONS_JSON_LEN>,
    expected_repo_name: BoundedVec<u8, MAX_REPO_NAME_LEN>,
    expected_repo_owner: BoundedVec<u8, MAX_REPO_OWNER_LEN>,
    n_contributions: u64,
) {
    /*
    Expected JSON schema:
    {
        "repository":{
            "name":<repository_name>,
            "owner":{
                "login":<repository_owner>,
            },
            "defaultBranchRef":{
                "target":{
                    "history":{
                        "totalCount":<n>
                    }
                }
            }
        }
    }

    Where <n> is the number commits in the repo's default branch.
    */

    let json: JSON512b = JSON::parse_json_from_string(json_str);
    let repo: JSON512b = json.get_object_unchecked("repository".as_bytes());

    // Parse decrypted API response to get `repo_name` and `repo_owner`.
    let repo_name: BoundedVec<u8, MAX_REPO_NAME_LEN> = repo.get_string_unchecked("name".as_bytes());
    let owner: JSON512b = repo.get_object_unchecked("owner".as_bytes());
    let repo_owner: BoundedVec<u8, MAX_REPO_OWNER_LEN> =
        owner.get_string_unchecked("login".as_bytes());

    // Assert we're on the correct repo, identified by the name and owner.
    assert(repo_name == expected_repo_name, "Unexpected repo name!");
    assert(repo_owner == expected_repo_owner, "Unexpected repo owner!");

    // Parse decrypted API response to get `n_contributions`.
    let default_branch_ref: JSON512b = repo.get_object_unchecked("defaultBranchRef".as_bytes());
    let target: JSON512b = default_branch_ref.get_object_unchecked("target".as_bytes());
    let history: JSON512b = target.get_object_unchecked("history".as_bytes());
    let total_count: u64 = history.get_number_unchecked("totalCount".as_bytes());

    // Assert `totalCount` is the expected value.
    assert(total_count == n_contributions, "Unexpected number of contributions!");
}

#[test]
fn test_main() {
    let (mut key, ctr, mut nonce) = get_test_key_ctr_nonce();
    let plaintext: str<128> = r#"xxxx{"repository":{"name":"mono","owner":{"login":"tisura-labs"},"defaultBranchRef":{"target":{"history":{"totalCount":50}}}}}xx"#;
    let (repo_name, repo_owner, n_contributions) = get_test_repo_name_owner_n_contributions();

    // Calculate ciphertext.
    // let mut plaintext_vec: BoundedVec<u8, MAX_CONTRIBUTIONS_RECORD_LEN> = BoundedVec::new();
    // plaintext_vec.extend_from_array(plaintext.as_bytes());
    // let encrypted_record = decrypt_record(key, ctr, nonce, plaintext_vec); // decrypt_record encrypts plaintext.
    let encrypted_record_arr = [
        109, 24, 73, 221, 26, 212, 200, 158, 152, 115, 225, 159, 83, 201, 110, 59, 131, 149, 47,
        103, 89, 57, 182, 214, 247, 119, 17, 151, 56, 151, 237, 0, 201, 40, 90, 229, 107, 199, 5,
        77, 187, 166, 24, 227, 101, 67, 102, 218, 220, 127, 231, 140, 54, 187, 61, 243, 34, 95, 164,
        173, 102, 90, 111, 252, 132, 243, 136, 68, 26, 183, 37, 161, 121, 48, 248, 234, 34, 253,
        110, 65, 25, 69, 82, 171, 70, 148, 196, 239, 210, 169, 214, 45, 106, 225, 62, 189, 65, 91,
        136, 127, 93, 177, 25, 58, 58, 245, 5, 103, 139, 33, 217, 82, 224, 242, 225, 236, 29, 239,
        217, 113, 113, 197, 108, 109, 188, 55, 129, 226, 83, 62, 248, 111, 4, 198, 159, 36, 31, 101,
        150, 70, 193, 81, 0, 69, 9, 185, 220, 229, 31, 1, 107, 49, 243, 62, 101, 210, 33, 145, 240,
        72, 49, 178, 115, 235, 27, 92, 112, 183, 108, 129, 197, 21, 93, 95, 47, 3, 122, 31, 67, 42,
        227, 31, 107, 126, 154, 44, 149, 120, 250, 4, 123, 120, 94, 200, 149, 61, 194, 180, 223,
        120, 215, 82, 145, 114, 200, 241, 70, 29, 211, 36, 66, 241, 165, 50, 142, 226, 198, 212,
        194, 75, 171, 86, 240, 186, 79, 127, 34, 100, 216, 198, 219, 177, 208, 183, 208, 93, 17,
        192, 141, 184, 177, 191, 35, 7, 16, 40, 9, 189, 208, 99, 235, 71, 201, 131, 54, 91, 209,
        165, 254, 191, 27, 15, 57, 242, 20, 228, 136, 148, 61, 84, 82, 48, 113, 219, 81, 0, 150,
        128, 226, 108, 162, 233, 253, 151, 39, 240, 122, 188, 102, 174, 55, 146, 186, 69, 87, 183,
        236, 65, 1, 38, 32, 246, 77, 141, 14, 163, 168, 30, 230, 63, 210, 137, 39, 126, 139, 152,
        115, 62, 66, 28, 234, 219, 154, 232, 182, 240, 239, 148, 214, 199, 153, 22, 202, 112, 42,
        85, 171, 76, 79, 85, 81, 239, 118, 45, 65, 89, 55, 158, 55, 193, 146, 138, 102, 17, 95, 156,
        169, 196, 19, 137, 30, 119, 45, 77, 44, 29, 127, 146, 110, 88, 14, 75, 99, 4, 118, 153, 157,
        6, 82, 239, 241, 162, 164, 148, 57, 75, 42, 125, 253, 17, 53, 35, 47, 176, 38, 220, 81, 118,
        4, 218, 19, 84, 207, 51, 77, 101, 47, 180, 196, 194, 97, 161, 129, 143, 155, 34, 165, 204,
        53, 8, 32, 110, 13, 8, 179, 125, 176, 40, 204, 168, 122, 224, 61, 200, 103, 52, 51, 255, 14,
        176, 200, 132, 46, 247, 26, 88, 119, 96, 57, 228, 219, 138, 99, 89, 151, 128, 224, 140, 163,
        82, 38, 97, 102, 143, 81, 60, 27, 241, 73, 229, 29, 17, 227, 122, 252, 107, 83, 122, 179,
        12, 55, 132, 251, 80, 209, 231, 203, 69, 19, 10, 34, 254, 203, 180, 51, 89, 28, 51, 146, 90,
        94, 132, 108, 142, 32, 88, 198, 100, 43, 9, 24, 103, 66, 21, 228, 153, 201, 29, 235, 94,
        132, 77, 195, 60, 196, 155, 248, 119, 74, 135, 162, 11, 169, 87, 116, 154, 135, 248, 67, 84,
        252, 143, 66, 132, 226, 110, 66, 2, 203, 174, 23, 193, 129, 202, 54, 63, 244, 171, 6, 36,
        177, 150, 245, 40, 151, 80, 84, 72, 198, 171, 140, 150, 23, 62, 21, 119, 239, 87, 142, 11,
        123, 93, 231, 28, 14, 3, 244, 58, 170, 205, 245, 2, 219, 39, 89, 215, 84, 117, 11, 102, 16,
        146, 208, 178, 214, 244, 89, 1, 251, 6, 128, 195, 163, 21, 67, 27, 157, 189, 52, 189, 72,
        50, 160, 150, 80, 15, 246, 27, 186, 234, 230, 216, 15, 48, 182, 251, 20, 173, 242, 124, 230,
        219, 168, 155, 88, 91, 253, 53, 65, 122, 118, 205, 133, 193, 95, 12, 57, 7, 1, 205, 141,
        155, 145, 47, 60, 215, 47, 77, 46, 94, 88, 23, 212, 75, 228, 114, 240, 61, 171, 163, 131,
        220, 244, 189, 38, 146, 41, 161, 241, 22, 218, 94, 3, 127, 148, 73, 96, 194, 137, 76, 24,
        228, 205, 242, 236, 30, 238, 214, 7, 208, 108, 190, 62, 0, 233, 3, 145, 112, 190, 9, 117,
        39, 11, 77, 210, 206, 149, 110, 113, 249, 78, 246, 53, 157, 19, 152, 75, 94, 231, 230, 53,
        140, 30, 207, 135, 116, 27, 96, 8, 97, 223, 51, 67, 16, 238, 242, 184, 100, 15, 189, 24,
        221, 130, 207, 26, 80, 36, 200, 237, 242, 11, 91, 105, 160, 237, 241, 201, 109, 25, 198,
        146, 43, 20, 104, 51, 190, 243, 32, 204, 204, 199, 116, 127, 67, 50, 241, 212, 66, 23, 243,
        207, 232, 136, 4, 160, 146, 34, 130, 23, 224, 80, 140, 108, 57, 75, 167, 16, 245, 92, 206,
        133, 156, 237, 194, 219, 63, 139, 242, 108, 91, 223, 58, 136, 117, 189, 22, 253, 142, 158,
        24, 105, 19, 251, 107, 127, 171, 190, 153, 84, 164, 72, 98, 208, 55, 228, 127, 248, 22, 194,
        247, 172, 108, 198, 25, 191, 179, 91, 94, 116, 93, 109, 217, 27, 45, 207, 20, 183, 5, 252,
        151, 6, 97, 210, 185, 65, 211, 115, 131, 76, 188, 249, 163, 239, 93, 37, 202, 177, 80, 102,
        150, 237, 198, 11, 137, 198, 226, 26, 134, 104, 137, 68, 105, 28, 11, 255, 233, 56, 250,
        131, 177, 53, 215, 12, 2, 223, 134, 112, 77, 78, 183, 11, 226, 111, 197, 200, 99, 223, 239,
        3, 228, 108, 128, 44, 59, 76, 26, 178, 104, 90, 2, 237, 144, 21, 1, 56, 248, 143, 14, 171,
        199, 194, 12, 185, 60, 13, 80, 221, 237, 138, 104, 118, 101, 153, 57, 110, 221, 172, 184,
        133, 22, 108, 145, 35, 18, 0, 110, 186, 53, 109, 143, 203, 248, 205, 191, 255, 206, 71, 189,
        117, 113, 205, 87, 253, 84, 117, 238, 192, 46, 111, 104, 31, 132, 220, 24, 125, 4, 128, 192,
        26, 19, 15, 99, 147, 200, 75, 56, 123, 231, 50, 51, 50, 252, 41, 119, 186, 236, 9, 165, 119,
        142, 208, 76, 101, 6, 163, 114, 141, 20, 191, 132, 155, 219, 15, 83, 84, 93, 174, 224, 26,
        15, 234, 213, 238, 80, 251, 109, 122, 7, 175, 210, 35, 128, 68, 41, 246, 232, 36, 214, 10,
        57, 125, 158, 187, 15, 215, 209, 150, 193, 147, 85, 151, 113, 139, 147, 128, 13, 76, 101,
        208, 42, 57, 89, 101, 225, 233, 196, 111, 10, 118, 24, 94, 178, 227, 229, 43, 162, 165, 237,
        206, 231, 229, 159, 97, 216, 224, 61, 62, 43, 128, 95, 9, 225, 1, 235, 90, 70, 253, 114, 1,
        135, 124, 190, 77, 14, 236, 69, 217, 101, 117, 115, 20, 29, 17, 208, 177, 158, 191, 226,
        104, 215, 253, 42, 191, 71, 14, 57, 62, 48, 146, 139, 252, 255, 12, 63, 119, 221, 137, 113,
        54, 32, 34, 20, 79, 241, 33, 145, 66, 41, 225, 1, 90, 237, 244, 218, 59, 43, 64, 170, 221,
        136, 9, 220, 146, 148, 146, 198, 14, 187, 173, 201, 121, 96, 74, 173, 81, 137, 102, 4, 31,
        73, 147, 50, 234, 242, 76, 212, 43, 14, 20, 109, 159, 17, 87, 107, 96, 205, 45, 2, 30, 2,
        18, 135, 163, 226, 127, 37, 157, 91, 5, 111, 222, 192, 114, 151, 49, 66, 238, 116, 30, 117,
        230, 116, 197, 252, 224, 224, 209, 9, 189, 194, 157, 153, 185, 122, 86, 164, 71, 129, 56,
        167, 118, 173, 94, 180, 85, 158, 134, 2, 90, 12, 212, 92, 67, 43, 223, 226, 5, 252, 224, 87,
        141, 9, 225, 24, 211, 102, 16, 140, 225, 49, 29, 183, 51, 241, 156, 189, 230, 1, 160, 249,
        122, 31, 7, 216, 246, 207, 229, 23, 82,
    ];
    let mut encrypted_record: BoundedVec<u8, MAX_CONTRIBUTIONS_RECORD_LEN> = BoundedVec::new();
    encrypted_record.extend_from_array(encrypted_record_arr);
    let encrypted_record_signed: [u8; 64] = get_test_encrypted_record_signed();
    let (proxy_pubkey_x, proxy_pubkey_y) = get_proxy_pubkeys();

    // DEV: we pad `json` with empty spaces because any other character will make JSON parsing [l. 84] fail.
    let json: str<MAX_CONTRIBUTIONS_JSON_LEN> = r#"{"repository":{"name":"nphc","owner":{"login":"achab"},"defaultBranchRef":{"target":{"history":{"totalCount":447}}}}}                                                                           "#;
    let start: u32 = 1194; // Start index of the JSON in the decrypted response.
    let end: u32 = 1311; // End index of the JSON in the decrypted response. 126 = 4 + 122 (length of the JSON).
    let json_slice = JsonSlice { json, start, end };

    let signature_payload = SignaturePayload {
        encrypted_record,
        encrypted_record_signed,
        proxy_pubkey_x,
        proxy_pubkey_y,
    };

    let airdrop_payload =
        AirdropPayload { graphql_response: json_slice, repo_name, repo_owner, n_contributions };

    main(key, ctr, nonce, signature_payload, airdrop_payload);
}

/*
    Test helpers.
*/

fn get_test_key_ctr_nonce() -> ([u32; 8], u32, [u32; 3]) {
    let key: [u32; 8] = [
        1772578920, 2538154587, 774728937, 2728829235, 1821042422, 1845607651, 1981527235,
        2348794623,
    ];
    let ctr: u32 = 1;
    let mut nonce: [u32; 3] = [3311912553, 1497415678, 184466957];
    (key, ctr, nonce)
}

fn get_test_repo_name_owner_n_contributions() -> (BoundedVec<u8, MAX_REPO_NAME_LEN>, BoundedVec<u8, MAX_REPO_OWNER_LEN>, u64) {
    let repo_name = "nphc".as_bytes();
    let repo_name_vec: BoundedVec<u8, MAX_REPO_NAME_LEN> = BoundedVec::from_array(repo_name);

    let repo_owner = "achab".as_bytes();
    let repo_owner_vec: BoundedVec<u8, MAX_REPO_OWNER_LEN> = BoundedVec::from_array(repo_owner);

    let n_contributions: u64 = 447;

    (repo_name_vec, repo_owner_vec, n_contributions)
}

fn get_test_encrypted_record_signed() -> [u8; 64] {
    [
        174, 196, 240, 132, 23, 245, 255, 158, 248, 85, 195, 120, 103, 158, 215, 74, 148, 149, 52,
        65, 18, 33, 97, 121, 227, 231, 237, 54, 203, 156, 34, 219, 2, 147, 178, 121, 147, 67, 220,
        102, 131, 79, 130, 57, 29, 119, 98, 12, 98, 47, 145, 73, 167, 14, 9, 137, 8, 246, 34, 79,
        162, 253, 74, 149,
    ] // Removed the last byte which is the recovery id.
}
