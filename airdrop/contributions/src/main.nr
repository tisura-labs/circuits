use airdrop::constants::{
    MAX_CONTRIBUTIONS_JSON_LEN, MAX_CONTRIBUTIONS_RECORD_LEN, MAX_REPO_NAME_LEN, MAX_REPO_OWNER_LEN,
};
use airdrop::utils::{
    check_encrypted_json_contributions, decrypt_record, encrypt_substring, get_proxy_pubkeys,
    JsonSlice, verify_proxy_sig,
};
use json_parser::{JSON, JSON512b};

fn main(
    mut key: [u32; 8],
    ctr: u32,
    mut nonce: [u32; 3],
    encrypted_record: pub BoundedVec<u8, MAX_CONTRIBUTIONS_RECORD_LEN>,
    repo_name: pub BoundedVec<u8, MAX_REPO_NAME_LEN>,
    repo_owner: pub BoundedVec<u8, MAX_REPO_OWNER_LEN>,
    n_contributions: pub u64,
    graphql_response: pub JsonSlice<MAX_CONTRIBUTIONS_JSON_LEN>,
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

    // 2. Encrypt the substring of the GraphQL response on the specific keystream offset (start of the JSON in the full encrypted record).
    let encrypted_subtring: BoundedVec<u8, MAX_CONTRIBUTIONS_JSON_LEN> = encrypt_substring(
        key,
        ctr,
        nonce,
        graphql_response.json,
        graphql_response.start,
    );

    // 3. Check whether the encrypted substring (JSON) is present in the full encrypted record.
    check_encrypted_json_contributions(
        encrypted_record,
        encrypted_subtring,
        graphql_response.start,
        graphql_response.end,
    );

    // 4. Check for the number of contributions in the GraphQL response.
    check_contributions(
        graphql_response.json,
        repo_name,
        repo_owner,
        n_contributions,
    );
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
    let mut plaintext_vec: BoundedVec<u8, MAX_CONTRIBUTIONS_RECORD_LEN> = BoundedVec::new();
    plaintext_vec.extend_from_array(plaintext.as_bytes());
    let encrypted_record = decrypt_record(key, ctr, nonce, plaintext_vec); // decrypt_record encrypts plaintext.

    let ciphertext_hash_signed: [u8; 64] = get_test_encrypted_record_signed();
    let (proxy_pubkey_x, proxy_pubkey_y) = get_proxy_pubkeys();

    // DEV: we pad `json` with empty spaces because any other character will make JSON parsing [l. 84] fail.
    let json: str<MAX_CONTRIBUTIONS_JSON_LEN> = r#"{"repository":{"name":"mono","owner":{"login":"tisura-labs"},"defaultBranchRef":{"target":{"history":{"totalCount":50}}}}}                                                                      "#;
    let start: u32 = 4; // Start index of the JSON in the decrypted response.
    let end: u32 = 126; // End index of the JSON in the decrypted response. 126 = 4 + 122 (length of the JSON).
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

fn get_test_encrypted_record_signed() -> [u8; 64] {
    [
        97, 76, 162, 31, 207, 253, 154, 0, 249, 96, 15, 82, 126, 243, 107, 189, 249, 58, 154, 185,
        198, 9, 158, 0, 141, 76, 223, 192, 248, 170, 246, 75, 23, 202, 245, 196, 175, 112, 15, 48,
        130, 221, 98, 182, 40, 221, 135, 120, 234, 230, 50, 183, 84, 82, 126, 76, 169, 230, 111,
        106, 206, 137, 46, 236,
    ] // Removed the last byte which is the recovery id.
}
