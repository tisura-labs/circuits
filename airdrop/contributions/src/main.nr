use airdrop::constants::{
    MAX_CONTRIBUTIONS_JSON_LENGTH, MAX_CONTRIBUTIONS_RECORD_LEN, MAX_REPO_NAME_LEN,
    MAX_REPO_OWNER_LEN,
};
use airdrop::utils::{decrypt_record, get_proxy_pubkeys, JsonSlice, search_json, verify_proxy_sig};
use json_parser::{JSON, JSON512b};

fn main(
    mut key: [u32; 8],
    ctr: u32,
    mut nonce: [u32; 3],
    encrypted_record: pub BoundedVec<u8, MAX_CONTRIBUTIONS_RECORD_LEN>,
    repo_name: pub BoundedVec<u8, MAX_REPO_NAME_LEN>,
    repo_owner: pub BoundedVec<u8, MAX_REPO_OWNER_LEN>,
    n_contributions: pub u64,
    graphql_response: pub JsonSlice<MAX_CONTRIBUTIONS_JSON_LENGTH>,
    encrypted_record_signed: pub [u8; 64],
    proxy_pubkey_x: pub [u8; 32],
    proxy_pubkey_y: pub [u8; 32],
) {
    // 1. Verify encrypted_record comes from the trusted proxy.
    verify_proxy_sig(
        encrypted_record,
        proxy_pubkey_x,
        proxy_pubkey_y,
        encrypted_record_signed,
    );

    // 2. Decrypt the encrypted_record.
    let decrypted_record: BoundedVec<u8, MAX_CONTRIBUTIONS_RECORD_LEN> =
        decrypt_record(key, ctr, nonce, encrypted_record);

    // 3. Search for the expected GraphQL response in the decrypted record, the response is in JSON format.
    search_json(decrypted_record, graphql_response);

    // 4. Check for the number of contributions in the GraphQL response.
    check_contributions(
        graphql_response.json,
        repo_name,
        repo_owner,
        n_contributions,
    );
}

fn check_contributions(
    json_str: str<MAX_CONTRIBUTIONS_JSON_LENGTH>,
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
    let (repo_name, repo_owner, n_contributions) = get_test_repo_name_owner_n_contributions();
    let encrypted_record = get_test_encrypted_record();
    let ciphertext_hash_signed: [u8; 64] = get_test_encrypted_record_signed();
    let (proxy_pubkey_x, proxy_pubkey_y) = get_proxy_pubkeys();

    // Example JSON in string format padded with empty spaces.
    let json: str<MAX_CONTRIBUTIONS_JSON_LENGTH> = r#"{"repository":{"name":"mono","owner":{"login":"tisura-labs"},"defaultBranchRef":{"target":{"history":{"totalCount":50}}}}}                                      "#;
    let start: u32 = 16; // Start index of the JSON in the decrypted response.
    let end: u32 = 135; // End index of the JSON in the decrypted response.
    let json_slice = JsonSlice { json, start, end };

    main(
        key,
        ctr,
        nonce,
        encrypted_record,
        repo_name,
        repo_owner,
        n_contributions,
        json_slice,
        ciphertext_hash_signed,
        proxy_pubkey_x,
        proxy_pubkey_y,
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

fn get_test_repo_name_owner_n_contributions() -> (BoundedVec<u8, MAX_REPO_NAME_LEN>, BoundedVec<u8, MAX_REPO_OWNER_LEN>, u64) {
    let repo_name = "mono".as_bytes();
    let repo_name_vec: BoundedVec<u8, MAX_REPO_NAME_LEN> = BoundedVec::from_array(repo_name);

    let repo_owner = "tisura-labs".as_bytes();
    let repo_owner_vec: BoundedVec<u8, MAX_REPO_OWNER_LEN> = BoundedVec::from_array(repo_owner);

    let n_contributions: u64 = 50;

    (repo_name_vec, repo_owner_vec, n_contributions)
}

fn get_test_encrypted_record() -> BoundedVec<u8, MAX_CONTRIBUTIONS_RECORD_LEN> {
    let encrypted_record = BoundedVec::from_array([
        191, 88, 129, 116, 180, 222, 80, 8, 201, 208, 37, 123, 184, 139, 4, 178, 121, 218, 69, 155,
        114, 124, 147, 50, 74, 214, 13, 160, 63, 59, 97, 232, 168, 209, 166, 94, 25, 64, 62, 82,
        193, 212, 67, 133, 225, 236, 196, 218, 42, 188, 42, 229, 85, 216, 55, 152, 57, 7, 149, 56,
        202, 193, 215, 53, 237, 66, 172, 176, 100, 225, 51, 213, 115, 202, 145, 10, 76, 193, 18, 36,
        160, 1, 174, 70, 165, 33, 28, 111, 129, 86, 111, 211, 147, 148, 75, 124, 66, 110, 32, 131,
        179, 51, 19, 20, 47, 16, 16, 153, 2, 118, 202, 242, 35, 197, 214, 213, 240, 120, 30, 12,
        138, 222, 56, 158, 215, 177, 53, 66, 173, 13, 40, 146, 56, 31, 140, 143, 28, 107, 185, 172,
        221, 188, 50, 3, 232, 39, 205, 115, 139, 249, 111, 54, 88, 168, 180, 84, 56, 42, 153, 246,
        241, 52, 85, 72, 235, 167, 23, 179, 231, 178, 37, 111, 204, 216, 124, 20, 239, 155, 206, 11,
        72, 40, 30, 190, 150, 246, 100, 7, 117, 28, 13, 42, 34, 219, 154, 184, 213, 38, 214, 55,
    ]);
    encrypted_record
}

fn get_test_encrypted_record_signed() -> [u8; 64] {
    [
        72, 86, 251, 87, 170, 161, 81, 33, 0, 187, 90, 156, 131, 12, 221, 5, 136, 54, 126, 52, 193,
        107, 11, 77, 25, 96, 1, 35, 25, 177, 255, 196, 82, 117, 11, 222, 32, 145, 36, 179, 10, 176,
        37, 47, 195, 216, 4, 35, 130, 113, 51, 249, 42, 8, 18, 188, 174, 36, 167, 136, 136, 251,
        251, 89,
    ] // Removed the last byte which is the recovery id.
}
