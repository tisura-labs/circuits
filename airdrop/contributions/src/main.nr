use chacha20::ChaCha20;
use json_parser::{JSON, JSON512b};

/*
    Expected JSON schema:
    {
    "data": {
        "repository": {
            "defaultBranchRef": {
                "target": {
                    "history": {
                        "totalCount": <n>
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
    count: u64,
) {
    // TODO: Check for trusted proxy signature to be sure the response comes from a gh graphql endpoint.
    // DEV: Should we validate repo ? What if it's a gh graphql endpoint but a diff repo that has > n contributions ?
    let chacha20 = ChaCha20::new(&mut key, ctr, &mut nonce);

    // `ciphertext` is the encrypted response of the gh graphql endpoint.
    let decrypted: BoundedVec<u8, MAX> = chacha20.decrypt(ciphertext);

    // Convert decrypted from `BoundedVec<u8, MAX>` to `[u8; MAX]`, then to a `str<MAX>` to be parsed.
    let decrypted_str: str<MAX> = decrypted.storage().as_str_unchecked(); // DEV: Converting to a `BoundedVec` may introduce zeroed out elements on the right if decrypted.len() < MAX. It might be better to reimplement lib to use [u8, MAX] directly.

    check_contributions(decrypted_str, count);
}

fn check_contributions(decrypted_str: str<MAX>, expected_count: u64) {
    // Parse decrypted API response.
    let json: JSON512b = JSON::parse_json_from_string(decrypted_str);
    let data: JSON512b = json.get_object_unchecked("data".as_bytes());
    let repository: JSON512b = data.get_object_unchecked("repository".as_bytes());
    let default_branch_ref: JSON512b =
        repository.get_object_unchecked("defaultBranchRef".as_bytes());
    let target: JSON512b = default_branch_ref.get_object_unchecked("target".as_bytes());
    let history: JSON512b = target.get_object_unchecked("history".as_bytes());
    let totalCount: u64 = history.get_number_unchecked("totalCount".as_bytes());

    // Assert `totalCount` is the expected value.
    assert(totalCount == expected_count);
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
    // {\"data\": {\"repository\": {\"defaultBranchRef\": {\"target\": {\"history\": {\"totalCount\": 0}}}}}, \"padding\": 000000000000000000000000000000000000000000000000000000000}
    let ciphertext: BoundedVec<u8, 160> = BoundedVec::from_array([
        118, 121, 112, 128, 246, 233, 221, 145, 65, 235, 18, 221, 111, 247, 255, 108, 168, 130, 137,
        75, 16, 179, 79, 130, 80, 107, 167, 211, 175, 185, 2, 177, 251, 225, 151, 139, 226, 209, 79,
        44, 103, 233, 0, 1, 230, 113, 241, 220, 38, 77, 15, 167, 15, 217, 249, 19, 5, 1, 40, 29,
        240, 61, 163, 26, 90, 107, 129, 95, 116, 67, 220, 60, 104, 17, 16, 46, 94, 6, 60, 162, 96,
        74, 27, 64, 154, 57, 63, 206, 160, 75, 72, 12, 121, 55, 117, 167, 185, 207, 50, 101, 234,
        197, 243, 121, 65, 143, 104, 200, 132, 0, 141, 97, 13, 153, 107, 8, 252, 114, 146, 135, 44,
        216, 116, 166, 150, 169, 146, 160, 22, 80, 206, 113, 26, 225, 211, 255, 41, 209, 186, 177,
        14, 117, 207, 189, 100, 226, 246, 39, 207, 66, 102, 172, 137, 221, 82, 170, 230, 155, 65,
        82,
    ]);
    let count: u64 = 0;

    main(key, ctr, nonce, ciphertext, count);
}

#[test]
fn test_check_contributions() {
    let mut key: [u32; 8] = [
        0x605fec2f, 0x30ffd5df, 0xf722ed31, 0xed119037, 0xa02cf2f2, 0x12d1e65a, 0xb1fb9cf4,
        0xf8425b7b,
    ];
    let ctr: u32 = 1;
    let mut nonce: [u32; 3] = [0x5ef1f372, 0x244dd026, 0x795c577c];

    // DEV: We should address padding, most likely at ts level.
    let json: str<160> = "{\"data\": {\"repository\": {\"defaultBranchRef\": {\"target\": {\"history\": {\"totalCount\": 0}}}}}, \"padding\": 000000000000000000000000000000000000000000000000000000000}";
    let expected_count: u64 = 0;

    check_contributions(json, expected_count);
}
