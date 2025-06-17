use airdrop::{constants::{PROXY_PUBKEY_X, PROXY_PUBKEY_Y}, utils::{check_json, JsonSlice}};
use chacha20::ChaCha20;
use json_parser::{JSON, JSON512b};
use keccak256::keccak256;

global MAX_CONTRIBUTIONS_CIPHERTEXT_LEN: u32 = 200;
global MAX_JSON_LENGTH: u32 = 160; // In Contributions, Max length of JSON is up to 255, but we use 160 as a beginning.
global MAX_REPO_NAME_LEN: u32 = 20;
global MAX_REPO_OWNER_LEN: u32 = 20;

fn main(
    mut key: [u32; 8],
    ctr: u32,
    mut nonce: [u32; 3],
    ciphertext: pub BoundedVec<u8, MAX_CONTRIBUTIONS_CIPHERTEXT_LEN>,
    expected_repository_name: pub BoundedVec<u8, MAX_REPO_NAME_LEN>,
    expected_repository_owner: pub BoundedVec<u8, MAX_REPO_OWNER_LEN>,
    count: pub u64,
    json_slice: pub JsonSlice<MAX_JSON_LENGTH>,
    ciphertext_hash_signed: pub [u8; 64],
) {
    // Check for trusted proxy signature to be sure the response comes from a gh graphql endpoint.
    // DEV: Is using ciphertext.storage() safe?
    let record_hash = keccak256(ciphertext.storage(), ciphertext.len());
    let valid_signature = std::ecdsa_secp256k1::verify_signature(
        PROXY_PUBKEY_X,
        PROXY_PUBKEY_Y,
        ciphertext_hash_signed,
        record_hash,
    );
    assert(valid_signature);

    let chacha20 = ChaCha20::new(&mut key, ctr, &mut nonce);
    // `ciphertext` is the encrypted response of the gh graphql endpoint.
    let decrypted: BoundedVec<u8, MAX_CONTRIBUTIONS_CIPHERTEXT_LEN> = chacha20.decrypt(ciphertext);

    // Check if the decrypted response contains the expected JSON.
    check_json(decrypted, json_slice);

    // Check the contributions in the decrypted JSON.
    check_contributions(
        json_slice.json,
        expected_repository_name,
        expected_repository_owner,
        count,
    );
}

fn check_contributions(
    json_str: str<MAX_JSON_LENGTH>,
    expected_repository_name: BoundedVec<u8, MAX_REPO_NAME_LEN>,
    expected_repository_owner: BoundedVec<u8, MAX_REPO_OWNER_LEN>,
    expected_count: u64,
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
    let repository: JSON512b = json.get_object_unchecked("repository".as_bytes());

    // Parse decrypted API response to get `repository_name` and `repository_owner`.
    let repository_name: BoundedVec<u8, MAX_REPO_NAME_LEN> =
        repository.get_string_unchecked("name".as_bytes());
    let owner: JSON512b = repository.get_object_unchecked("owner".as_bytes());
    let repository_owner: BoundedVec<u8, MAX_REPO_OWNER_LEN> =
        owner.get_string_unchecked("login".as_bytes());

    // Assert we're on the correct repo, identified by the name and owner.
    assert(repository_name == expected_repository_name);
    assert(repository_owner == expected_repository_owner);

    // Parse decrypted API response to get `count`.
    let default_branch_ref: JSON512b =
        repository.get_object_unchecked("defaultBranchRef".as_bytes());
    let target: JSON512b = default_branch_ref.get_object_unchecked("target".as_bytes());
    let history: JSON512b = target.get_object_unchecked("history".as_bytes());
    let total_count: u64 = history.get_number_unchecked("totalCount".as_bytes());

    // Assert `totalCount` is the expected value.
    assert(total_count == expected_count);
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
    let ciphertext: BoundedVec<u8, MAX_CONTRIBUTIONS_CIPHERTEXT_LEN> = BoundedVec::from_array([
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

    // mono
    let repository_name: BoundedVec<u8, MAX_REPO_NAME_LEN> =
        BoundedVec::from_array([109, 111, 110, 111]);
    // tisura-labs
    let repository_owner: BoundedVec<u8, MAX_REPO_OWNER_LEN> =
        BoundedVec::from_array([116, 105, 115, 117, 114, 97, 45, 108, 97, 98, 115]);
    let count: u64 = 50;
    // Example JSON in string format padded with empty spaces.
    let json: str<MAX_JSON_LENGTH> = r#"{"repository":{"name":"mono","owner":{"login":"tisura-labs"},"defaultBranchRef":{"target":{"history":{"totalCount":50}}}}}                                      "#;
    let start: u32 = 16; // Start index of the JSON in the decrypted response.
    let end: u32 = 135; // End index of the JSON in the decrypted response.
    let json_slice = JsonSlice { json, start, end };
    let ciphertext_hash_signed: [u8; 64] = [
        72, 86, 251, 87, 170, 161, 81, 33, 0, 187, 90, 156, 131, 12, 221, 5, 136, 54, 126, 52, 193,
        107, 11, 77, 25, 96, 1, 35, 25, 177, 255, 196, 82, 117, 11, 222, 32, 145, 36, 179, 10, 176,
        37, 47, 195, 216, 4, 35, 130, 113, 51, 249, 42, 8, 18, 188, 174, 36, 167, 136, 136, 251,
        251, 89,
    ]; // Removed the last 0x01 which is the recovery id.

    main(
        key,
        ctr,
        nonce,
        ciphertext,
        repository_name,
        repository_owner,
        count,
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
    let plaintext: str<MAX_CONTRIBUTIONS_CIPHERTEXT_LEN> = r#"\r\n\r\n{"data":{"repository":{"name":"mono","owner":{"login":"tisura-labs"},"defaultBranchRef":{"target":{"history":{"totalCount":50}}}}}}��F�$��5�/>MO��I�b}������T#�"#;

    let mut plaintext_vec: BoundedVec<u8, MAX_CONTRIBUTIONS_CIPHERTEXT_LEN> = BoundedVec::new();
    plaintext_vec.extend_from_array(plaintext.as_bytes());
    let chacha = ChaCha20::new(&mut key, ctr, &mut nonce);
    let ciphertext = chacha.encrypt(plaintext_vec);

    println(ciphertext);
}
