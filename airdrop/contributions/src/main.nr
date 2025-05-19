use chacha20::ChaCha20;
use json_parser::{JSON, JSON512b};

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
    expected_repository_name: BoundedVec<u8, MAX>,
    expected_repository_owner: BoundedVec<u8, MAX>,
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

    let json: JSON512b = JSON::parse_json_from_string(decrypted_str);
    let data: JSON512b = json.get_object_unchecked("data".as_bytes());
    let repository: JSON512b = data.get_object_unchecked("repository".as_bytes());

    // Parse decrypted API response to get `repository_name` and `repository_owner`.
    let repository_name: BoundedVec<u8, MAX> = repository.get_string_unchecked("name".as_bytes());

    let owner: JSON512b = repository.get_object_unchecked("owner".as_bytes());
    let repository_owner: BoundedVec<u8, MAX> = owner.get_string_unchecked("login".as_bytes());

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
    // {\"data\": {\"repository\": {\"name\": \"nhpc\", \"owner\": {\"login\": \"achab\"}, \"defaultBranchRef\": {\"target\": {\"history\": {\"totalCount\": 10}}}}}, \"padding\": \"000000000\"}
    let ciphertext: BoundedVec<u8, MAX> = BoundedVec::from_array([
        152, 8, 185, 123, 156, 205, 46, 92, 146, 137, 99, 104, 169, 154, 73, 251, 107, 140, 88, 140,
        123, 49, 218, 123, 69, 155, 17, 184, 112, 100, 56, 240, 230, 146, 165, 75, 83, 25, 62, 19,
        142, 152, 67, 208, 163, 171, 217, 143, 126, 249, 35, 229, 3, 204, 114, 157, 56, 66, 198,
        118, 202, 154, 150, 41, 229, 83, 251, 191, 41, 236, 125, 208, 116, 223, 210, 2, 12, 151, 52,
        51, 167, 14, 184, 66, 131, 6, 8, 44, 213, 21, 124, 163, 130, 147, 27, 33, 92, 56, 118, 216,
        225, 47, 84, 8, 100, 89, 31, 212, 24, 102, 155, 188, 108, 204, 141, 131, 165, 119, 93, 20,
        166, 197, 44, 156, 224, 252, 122, 12, 232, 31, 111, 218, 117, 31, 140, 222, 65, 52, 180,
        218, 86, 103, 230, 130, 48, 184, 177, 188, 22, 116, 123, 233, 215, 37, 107, 219, 181, 47,
        84, 52,
    ]);
    let repository_name: BoundedVec<u8, MAX> = BoundedVec::from_array([110, 112, 104, 99]); // nphc
    let repository_owner: BoundedVec<u8, MAX> = BoundedVec::from_array([97, 99, 104, 97, 98]); // achab
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

    let plaintext: str<MAX> = "{\"data\": {\"repository\": {\"name\": \"nphc\", \"owner\": {\"login\": \"achab\"}, \"defaultBranchRef\": {\"target\": {\"history\": {\"totalCount\": 10}}}}}, \"padding\": \"000000000\"}";
    let mut plaintext_vec: BoundedVec<u8, MAX> = BoundedVec::new();
    plaintext_vec.extend_from_array(plaintext.as_bytes());
    let chacha = ChaCha20::new(&mut key, ctr, &mut nonce);
    let ciphertext = chacha.encrypt(plaintext_vec);

    println(ciphertext);
}
