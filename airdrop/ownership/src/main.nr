use chacha20::ChaCha20;
use json_parser::{JSON, JSON512b};

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

fn check_ownership(decrypted_str: str<MAX>, expected_node_id: str<NODE_ID_LEN>) {
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
        0x00000001, 0x00000002, 0x00000003, 0x00000004, 0x00000005, 0x00000006, 0x00000007,
        0x00000008,
    ];
    let ctr: u32 = 0x00000001;
    let mut nonce: [u32; 3] = [0x00000001, 0x00000002, 0x00000003];

    let plaintext: str<MAX> = "{\"data\": {\"viewer\": {\"id\": \"U_kgDOCPtlRA\", \"login\": \"0x18a6\"}}, \"padding\": \"0000000000000000000000000000000000000000000000000000000000000000000000000000000000\"}";
    let node_id: str<NODE_ID_LEN> = "U_kgDOCPtlRA";

    // Calculate ciphertext.
    let mut plaintext_vec: BoundedVec<u8, MAX> = BoundedVec::new();
    plaintext_vec.extend_from_array(plaintext.as_bytes());
    let chacha = ChaCha20::new(&mut key, ctr, &mut nonce);
    let ciphertext = chacha.encrypt(plaintext_vec);
    println(ciphertext);

    main(key, ctr, nonce, ciphertext, node_id);
}
