use chacha20::ChaCha20;
use json_parser::{JSON, JSON512b};

/*
    Expected JSON schema:
    {
        "data": {
            "viewer": {
                "id": "<node_id>",
                "login": "<login>"
            }
        }
    }

    Where <node_id> is a 12 character string.
*/

global MAX: u32 = 160;
global NODE_ID_LEN: u32 = 12;

// TODO: Refactor to implement a struct.

fn main(
    mut key: [u32; 8],
    ctr: u32,
    mut nonce: [u32; 3],
    ciphertext: pub BoundedVec<u8, MAX>,
    node_id: pub str<NODE_ID_LEN>,
) {
    // TODO: Check for trusted proxy signature.
    let chacha20 = ChaCha20::new(&mut key, ctr, &mut nonce);

    // `ciphertext` is the encrypted response of the gh graphql endpoint.
    let decrypted: BoundedVec<u8, MAX> = chacha20.decrypt(ciphertext);
    // Convert decrypted and plaintext from `BoundedVec<u8, MAX>` to `[u8; MAX]`, then to a `str<MAX>` to be parsed.
    let decrypted_str: str<MAX> = decrypted.storage().as_str_unchecked(); // DEV: Converting to a `BoundedVec` may introduce zeroed out elements on the right if decrypted.len() < MAX. It might be better to reimplement lib to use [u8, MAX] directly.

    check_ownership(decrypted_str, node_id);
}

fn check_ownership<let N: u32>(decrypted_str: str<MAX>, expected_node_id: str<N>) {
    // Parse decrypted API response.
    let json: JSON512b = JSON::parse_json_from_string(decrypted_str);
    let data: JSON512b = json.get_object_unchecked("data".as_bytes());
    let viewer: JSON512b = data.get_object_unchecked("viewer".as_bytes());
    let id: BoundedVec<u8, MAX> = viewer.get_string_unchecked("id".as_bytes());

    // Assert `id` is the expected value.
    assert(id == BoundedVec::from_array(expected_node_id.as_bytes()));
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
    // {\"data\": {\"viewer\": {\"id\": \"U_kgDOCPtlRA\", \"login\": \"0x18a6\"}}, \"padding\": 000000000000000000000000000000000000000000000000000000000000000000000000000000000000}
    let ciphertext: BoundedVec<u8, MAX> = BoundedVec::from_array([
        118, 121, 112, 128, 246, 233, 221, 145, 65, 235, 18, 217, 99, 226, 231, 122, 179, 212, 220,
        25, 18, 179, 28, 198, 9, 115, 227, 148, 156, 135, 28, 186, 203, 236, 166, 186, 248, 222,
        117, 63, 32, 163, 2, 25, 170, 101, 180, 193, 41, 29, 82, 226, 89, 203, 187, 2, 70, 66, 118,
        86, 254, 52, 224, 72, 1, 57, 218, 27, 107, 8, 198, 52, 62, 74, 92, 93, 1, 67, 98, 230, 114,
        64, 11, 64, 215, 116, 114, 131, 237, 87, 88, 30, 57, 102, 33, 243, 224, 145, 101, 119, 224,
        213, 243, 121, 65, 143, 104, 200, 132, 0, 141, 97, 13, 153, 107, 8, 252, 114, 146, 135, 44,
        216, 116, 166, 150, 169, 146, 160, 22, 80, 206, 113, 26, 225, 211, 255, 41, 209, 186, 177,
        14, 117, 207, 189, 100, 226, 246, 39, 207, 66, 102, 172, 137, 221, 82, 170, 230, 155, 65,
        82,
    ]);

    let id: str<NODE_ID_LEN> = "U_kgDOCPtlRA";
    main(key, ctr, nonce, ciphertext, id);
}

#[test]
fn test_check_ownership() {
    let mut key: [u32; 8] = [
        0x605fec2f, 0x30ffd5df, 0xf722ed31, 0xed119037, 0xa02cf2f2, 0x12d1e65a, 0xb1fb9cf4,
        0xf8425b7b,
    ];
    let ctr: u32 = 1;
    let mut nonce: [u32; 3] = [0x5ef1f372, 0x244dd026, 0x795c577c];

    let json: str<MAX> = "{\"data\": {\"viewer\": {\"id\": \"U_kgDOCPtlRA\", \"login\": \"0x18a6\"}}, \"padding\": 000000000000000000000000000000000000000000000000000000000000000000000000000000000000}";
    let expected_value: str<NODE_ID_LEN> = "U_kgDOCPtlRA";

    check_ownership(json, expected_value);
}
