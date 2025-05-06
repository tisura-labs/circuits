use chacha20::ChaCha20;
use json_parser::{JSON, JSON512b};

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

global MAX: u32 = 160;

fn main(
    mut key: [u32; 8],
    ctr: u32,
    mut nonce: [u32; 3],
    ciphertext: pub BoundedVec<u8, MAX>,
    expected_repository_name: pub BoundedVec<u8, MAX>,
    expected_repository_owner: pub BoundedVec<u8, MAX>,
    count: pub u64,
) {
    // TODO: Check for trusted proxy signature to be sure the response comes from a gh graphql endpoint.
    // DEV: Should we validate repo ? What if it's a gh graphql endpoint but a diff repo that has > n contributions ?
    let chacha20 = ChaCha20::new(&mut key, ctr, &mut nonce);

    // `ciphertext` is the encrypted response of the gh graphql endpoint.
    let decrypted: BoundedVec<u8, MAX> = chacha20.decrypt(ciphertext);

    // Convert decrypted from `BoundedVec<u8, MAX>` to `[u8; MAX]`, then to a `str<MAX>` to be parsed.
    let decrypted_str: str<MAX> = decrypted.storage().as_str_unchecked(); // DEV: Converting to a `BoundedVec` may introduce zeroed out elements on the right if decrypted.len() < MAX. It might be better to reimplement lib to use [u8, MAX] directly.

    check_contributions(
        decrypted_str,
        expected_repository_name,
        expected_repository_owner,
        count,
    );
}

fn check_contributions(
    decrypted_str: str<MAX>,
    expected_repository_name: pub BoundedVec<u8, MAX>,
    expected_repository_owner: pub BoundedVec<u8, MAX>,
    expected_count: u64,
) {
    let json: JSON512b = JSON::parse_json_from_string(decrypted_str);
    let data: JSON512b = json.get_object_unchecked("data".as_bytes());
    let repository: JSON512b = data.get_object_unchecked("repository".as_bytes());

    // Parse decrypted API response to get `repository_name` and `repository_owner`.
    let repository_name: BoundedVec<u8, MAX> = repository.get_string_unchecked("name".as_bytes());

    let owner: JSON512b = repository.get_object_unchecked("owner".as_bytes());
    let repository_owner: BoundedVec<u8, MAX> = owner.get_string_unchecked("login".as_bytes());

    // Assert we're on the correct repo, identified by its name and owner.
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
        0x605fec2f, 0x30ffd5df, 0xf722ed31, 0xed119037, 0xa02cf2f2, 0x12d1e65a, 0xb1fb9cf4,
        0xf8425b7b,
    ];
    let ctr: u32 = 1;
    let mut nonce: [u32; 3] = [0x5ef1f372, 0x244dd026, 0x795c577c];
    // Ciphertext decrypts to:
    // {\"data\": {\"repository\": {\"name\": \"nhpc\", \"owner\": {\"login\": \"achab\"}, \"defaultBranchRef\": {\"target\": {\"history\": {\"totalCount\": 10}}}}}, \"padding\": \"000000000\"}
    let ciphertext: BoundedVec<u8, MAX> = BoundedVec::from_array([
        118, 121, 112, 128, 246, 233, 221, 145, 65, 235, 18, 221, 111, 247, 255, 108, 168, 130, 137,
        75, 16, 179, 79, 130, 80, 107, 173, 215, 164, 189, 85, 231, 175, 129, 139, 154, 228, 209, 5,
        82, 34, 173, 77, 76, 168, 111, 161, 138, 125, 31, 19, 224, 23, 148, 164, 90, 16, 1, 122, 84,
        161, 40, 175, 0, 66, 43, 153, 2, 35, 65, 138, 55, 121, 22, 29, 24, 93, 7, 16, 164, 35, 30,
        88, 24, 181, 33, 36, 145, 231, 71, 19, 12, 125, 55, 99, 164, 181, 213, 119, 125, 240, 158,
        225, 33, 24, 204, 44, 151, 198, 73, 159, 107, 29, 210, 121, 76, 163, 54, 195, 219, 95, 135,
        49, 248, 210, 187, 152, 176, 23, 80, 131, 60, 87, 172, 158, 227, 57, 195, 250, 224, 90, 33,
        150, 227, 51, 240, 252, 55, 221, 66, 102, 172, 137, 221, 82, 170, 230, 155, 83, 82,
    ]);

    // nphc
    let repository_name: BoundedVec<u8, MAX> = BoundedVec::from_array([110, 112, 104, 99]);
    // achab
    let repository_owner: BoundedVec<u8, MAX> = BoundedVec::from_array([97, 99, 104, 97, 98]);

    let count: u64 = 10;

    main(
        key,
        ctr,
        nonce,
        ciphertext,
        repository_name,
        repository_owner,
        count,
    );
}

#[test]
fn test_check_contributions() {
    let mut key: [u32; 8] = [
        0x605fec2f, 0x30ffd5df, 0xf722ed31, 0xed119037, 0xa02cf2f2, 0x12d1e65a, 0xb1fb9cf4,
        0xf8425b7b,
    ];
    let ctr: u32 = 1;
    let mut nonce: [u32; 3] = [0x5ef1f372, 0x244dd026, 0x795c577c];

    let json: str<MAX> = "{\"data\": {\"repository\": {\"name\": \"nphc\", \"owner\": {\"login\": \"achab\"}, \"defaultBranchRef\": {\"target\": {\"history\": {\"totalCount\": 0}}}}}, \"padding\": 000000000000}";

    // nphc
    let repository_name: BoundedVec<u8, MAX> = BoundedVec::from_array([110, 112, 104, 99]);
    // achab
    let repository_owner: BoundedVec<u8, MAX> = BoundedVec::from_array([97, 99, 104, 97, 98]);
    let expected_count: u64 = 0;

    check_contributions(json, repository_name, repository_owner, expected_count);
}
