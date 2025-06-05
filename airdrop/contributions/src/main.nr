use airdrop::{check_json, JsonSlice};
use chacha20::ChaCha20;
use json_parser::{JSON, JSON512b};

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
) {
    // TODO: Check for trusted proxy signature to be sure the response comes from a gh graphql endpoint.
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
       "data":{
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
    }

    Where <n> is the number commits in the repo's default branch.
    */

    let json: JSON512b = JSON::parse_json_from_string(json_str);
    let data: JSON512b = json.get_object_unchecked("data".as_bytes());
    let repository: JSON512b = data.get_object_unchecked("repository".as_bytes());

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

#[test]
fn test_main() {
    let mut key: [u32; 8] = [
        0x00000001, 0x00000002, 0x00000003, 0x00000004, 0x00000005, 0x00000006, 0x00000007,
        0x00000008,
    ];
    let ctr: u32 = 0x00000001;
    let mut nonce: [u32; 3] = [0x00000001, 0x00000002, 0x00000003];
    // Ciphertext decrypts to:
    // ...{"data":{"repository":{"name":"mono","owner":{"login":"tisura-labs"},"defaultBranchRef":{"target":{"history":{"totalCount":50}}}}}...
    let ciphertext: BoundedVec<u8, MAX_CONTRIBUTIONS_CIPHERTEXT_LEN> = BoundedVec::from_array([
        238, 32, 208, 16, 147, 142, 104, 7, 198, 147, 99, 32, 183, 200, 84, 237, 114, 151, 68, 151,
        118, 124, 146, 34, 28, 131, 4, 251, 115, 96, 119, 175, 228, 138, 233, 86, 84, 20, 115, 29,
        130, 152, 67, 208, 163, 171, 217, 143, 126, 162, 122, 171, 0, 196, 124, 154, 116, 90, 222,
        34, 129, 136, 128, 51, 229, 28, 181, 163, 103, 191, 125, 201, 61, 155, 215, 18, 6, 130, 3,
        45, 178, 34, 169, 75, 191, 0, 6, 92, 138, 83, 37, 187, 141, 208, 29, 39, 75, 43, 49, 150,
        227, 110, 13, 66, 101, 67, 24, 207, 5, 109, 192, 164, 118, 204, 141, 131, 165, 119, 93, 20,
        166, 197, 44, 156, 224, 252, 122, 25, 233, 82, 111, 218, 117, 31, 140, 229, 142, 169, 121,
        84, 141, 190, 201, 3, 232, 39, 175, 115, 139, 249, 164, 102, 90, 32, 180, 84, 56, 48, 72, 4,
        3, 244, 212, 184, 75, 247, 21, 71, 231, 178, 37, 68, 94, 136, 126, 203, 125, 203, 204, 89,
        24, 42, 76, 238, 148, 164, 52, 5, 39, 76, 15, 120, 114, 217, 115, 213, 213, 38, 214, 55,
    ]);

    // mono
    let repository_name: BoundedVec<u8, MAX_REPO_NAME_LEN> =
        BoundedVec::from_array([109, 111, 110, 111]);
    // tisura-labs
    let repository_owner: BoundedVec<u8, MAX_REPO_OWNER_LEN> =
        BoundedVec::from_array([116, 105, 115, 117, 114, 97, 45, 108, 97, 98, 115]);

    let count: u64 = 50;

    // Example JSON in string format padded with empty spaces.
    let json: str<MAX_JSON_LENGTH> = r#"{"data":{"repository":{"name":"mono","owner":{"login":"tisura-labs"},"defaultBranchRef":{"target":{"history":{"totalCount":50}}}}}}                             "#;
    let start: u32 = 4; // Start index of the JSON in the decrypted response.
    let end: u32 = 135; // End index of the JSON in the decrypted response.
    let jsonSlice = JsonSlice { json, start, end };

    main(
        key,
        ctr,
        nonce,
        ciphertext,
        repository_name,
        repository_owner,
        count,
        jsonSlice,
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

    // Example ciphertext from a close to reality GitHub GraphQL API response.
    let plaintext: str<MAX_CONTRIBUTIONS_CIPHERTEXT_LEN> = r#"\r\n\r\n{"data":{"repository":{"name":"mono","owner":{"login":"tisura-labs"},"defaultBranchRef":{"target":{"history":{"totalCount":50}}}}}}��F�$��5�/>MO��I�b}������T#�"#;
    let mut plaintext_vec: BoundedVec<u8, MAX_CONTRIBUTIONS_CIPHERTEXT_LEN> = BoundedVec::new();
    plaintext_vec.extend_from_array(plaintext.as_bytes());
    let chacha = ChaCha20::new(&mut key, ctr, &mut nonce);
    let ciphertext = chacha.encrypt(plaintext_vec);

    println(ciphertext);
}
