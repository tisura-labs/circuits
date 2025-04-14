// DEV: Should this be refactored to a seperate folder at the same level with "substring" and "airdrop" called "chacha20" ?

mod utils;
mod test_vectors;

global BLOCK_SIZE: u32 = 64; // In bytes.
global STATE_SIZE: u8 = 16; // Each word is 4 bytes long.
global DOUBLE_ROUNDS: u8 = 10;

global MAX: u32 = 160;

// Constants for "expand 32-byte k".
global SIGMA_0: u32 = 0x61707865;
global SIGMA_1: u32 = 0x3320646e;
global SIGMA_2: u32 = 0x79622d32;
global SIGMA_3: u32 = 0x6b206574;

pub struct ChaCha20 {
    state: [u32; 16],
    key: &mut [u32; 8],
    ctr: u32,
    nonce: &mut [u32; 3],
}

impl ChaCha20 {
    pub fn new(key: &mut [u32; 8], ctr: u32, nonce: &mut [u32; 3]) -> Self {
        let state = [
            SIGMA_0, SIGMA_1, SIGMA_2, SIGMA_3, key[0], key[1], key[2], key[3], key[4], key[5],
            key[6], key[7], ctr, nonce[0], nonce[1], nonce[2],
        ];

        ChaCha20 { state, key, ctr, nonce }
    }

    pub fn encrypt(self, plaintext: BoundedVec<u8, MAX>) -> BoundedVec<u8, MAX> {
        // plaintext should not be padded because the code below
        // assumes that plaintext.len() != plaintext.max_len()

        let mut out: BoundedVec<u8, MAX> = BoundedVec::new();

        let plaintext_length = plaintext.len();
        let full_blocks_max = 1 + MAX / BLOCK_SIZE;

        for i in 0..full_blocks_max {
            let key_stream = self.block(self.ctr + i);
            let block_start = i * BLOCK_SIZE;

            for j in 0..BLOCK_SIZE {
                let indice_plain = block_start + j;
                if indice_plain < plaintext_length {
                    out.push(plaintext.get(indice_plain) ^ key_stream[j]);
                }
            }
        }

        out
    }

    pub fn decrypt(self, ciphertext: BoundedVec<u8, MAX>) -> BoundedVec<u8, MAX> {
        self.encrypt(ciphertext)
    }

    fn block(self, ctr: u32) -> [u8; 64] {
        let mut state = self.state;
        state[12] = ctr;
        let mut working_state = state;

        for _ in 0..DOUBLE_ROUNDS {
            inner_block(&mut working_state);
        }
        for i in 0..STATE_SIZE {
            state[i] = utils::wrapping_add_32(state[i], working_state[i]);
        }

        serialize_state(&mut state)
    }
}

fn inner_block(state: &mut [u32; 16]) {
    // Column round.
    quarter_round(state, 0, 4, 8, 12);
    quarter_round(state, 1, 5, 9, 13);
    quarter_round(state, 2, 6, 10, 14);
    quarter_round(state, 3, 7, 11, 15);

    // Diagonal round.
    quarter_round(state, 0, 5, 10, 15);
    quarter_round(state, 1, 6, 11, 12);
    quarter_round(state, 2, 7, 8, 13);
    quarter_round(state, 3, 4, 9, 14);
}

fn quarter_round(state: &mut [u32; 16], a: u8, b: u8, c: u8, d: u8) {
    state[a] = utils::wrapping_add_32(state[a], state[b]);
    state[d] ^= state[a];
    state[d] = utils::rotl32(state[d], 16);

    state[c] = utils::wrapping_add_32(state[c], state[d]);
    state[b] ^= state[c];
    state[b] = utils::rotl32(state[b], 12);

    state[a] = utils::wrapping_add_32(state[a], state[b]);
    state[d] ^= state[a];
    state[d] = utils::rotl32(state[d], 8);

    state[c] = utils::wrapping_add_32(state[c], state[d]);
    state[b] ^= state[c];
    state[b] = utils::rotl32(state[b], 7);
}

fn serialize_state(state: &mut [u32; 16]) -> [u8; 64] {
    let mut serialized_state: [u8; 64] = [0; 64];

    for i in 0..16 {
        let bytes: [u8; 4] = (state[i] as Field).to_le_bytes();
        serialized_state[i * 4] = bytes[0];
        serialized_state[i * 4 + 1] = bytes[1];
        serialized_state[i * 4 + 2] = bytes[2];
        serialized_state[i * 4 + 3] = bytes[3];
    }

    serialized_state
}

/*
    Tests.
*/

#[test]
fn test_quarter_round() {
    let test_cases = get_quarter_round_test_cases();

    for case in test_cases {
        let mut state = case.initial_state;
        quarter_round(&mut state, case.a, case.b, case.c, case.d);
        assert_arrays_eq(state, case.expected_state);
    }
}

#[test]
fn test_block() {
    let test_cases = get_block_test_cases();

    for case in test_cases {
        run_block_test(case.key, case.counter, case.nonce, case.expected);
    }
}

/*
Commenting out this test since MAX has been
decreased from 512 to 160
#[test]
fn test_encrypt() {
    let (case1, case2, case3, case4) = get_encrypt_test_cases();

    run_encrypt_test(
        case1.key,
        case1.counter,
        case1.nonce,
        case1.plaintext,
        case1.expected_ciphertext,
    );

    run_encrypt_test(
        case2.key,
        case2.counter,
        case2.nonce,
        case2.plaintext,
        case2.expected_ciphertext,
    );

    run_encrypt_test(
        case3.key,
        case3.counter,
        case3.nonce,
        case3.plaintext,
        case3.expected_ciphertext,
    );

    run_encrypt_test(
        case4.key,
        case4.counter,
        case4.nonce,
        case4.plaintext,
        case4.expected_ciphertext,
    );
}
*/

/*
    Test helpers.
*/

fn assert_vectors_eq(actual: BoundedVec<u8, MAX>, expected: BoundedVec<u8, MAX>) {
    assert_eq(actual.len(), expected.len());

    for i in 0..actual.len() {
        assert_eq(actual.get(i), expected.get(i));
    }
}

fn assert_arrays_eq<T, let N: u32>(actual: [T; N], expected: [T; N])
where
    T: Eq,
{
    assert_eq(actual.len(), expected.len());

    for i in 0..actual.len() {
        assert_eq(actual[i], expected[i]);
    }
}

fn run_block_test(key: [u32; 8], counter: u32, nonce: [u32; 3], expected: [u8; 64]) {
    let mut key = key;
    let mut nonce = nonce;
    let chacha = ChaCha20::new(&mut key, counter, &mut nonce);

    let actual = chacha.block(counter);
    assert_arrays_eq(actual, expected);
}

fn run_encrypt_test(
    key: [u32; 8],
    counter: u32,
    nonce: [u32; 3],
    plaintext: BoundedVec<u8, MAX>,
    expected: BoundedVec<u8, MAX>,
) {
    let mut key = key;
    let mut nonce = nonce;
    let chacha = ChaCha20::new(&mut key, counter, &mut nonce);

    let encrypted = chacha.encrypt(plaintext);
    assert_vectors_eq(encrypted, expected);
    let decrypted = chacha.decrypt(encrypted);
    assert_vectors_eq(decrypted, plaintext);
}

pub struct QuarterRoundTest {
    pub initial_state: [u32; 16],
    pub a: u8,
    pub b: u8,
    pub c: u8,
    pub d: u8,
    pub expected_state: [u32; 16],
}

pub struct BlockTest {
    pub key: [u32; 8],
    pub counter: u32,
    pub nonce: [u32; 3],
    pub expected: [u8; 64],
}

pub struct EncryptTest {
    pub key: [u32; 8],
    pub counter: u32,
    pub nonce: [u32; 3],
    pub plaintext: BoundedVec<u8, MAX>,
    pub expected_ciphertext: BoundedVec<u8, MAX>,
}

pub fn get_quarter_round_test_cases() -> [QuarterRoundTest; 2] {
    [
        // Test Vector 2.1.1
        QuarterRoundTest {
            initial_state: test_vectors::get_quarter_round_test_state_0(),
            a: 0,
            b: 1,
            c: 2,
            d: 3,
            expected_state: test_vectors::get_quarter_round_test_expected_0(),
        },
        // Test Vector 2.2.1
        QuarterRoundTest {
            initial_state: test_vectors::get_quarter_round_test_state_1(),
            a: 2,
            b: 7,
            c: 8,
            d: 13,
            expected_state: test_vectors::get_quarter_round_test_expected_1(),
        },
    ]
}

pub fn get_block_test_cases() -> [BlockTest; 6] {
    [
        // 2.3.2 Test Vector
        BlockTest {
            key: test_vectors::get_block_test_key_0(),
            counter: 1,
            nonce: test_vectors::get_block_test_nonce_0(),
            expected: test_vectors::get_block_test_expected_state_0(),
        },
        // A.1 Test Vectors
        BlockTest {
            key: test_vectors::get_block_test_key_1(),
            counter: 0,
            nonce: test_vectors::get_block_test_nonce_1(),
            expected: test_vectors::get_block_test_expected_state_1(),
        },
        BlockTest {
            key: test_vectors::get_block_test_key_2(),
            counter: 1,
            nonce: test_vectors::get_block_test_nonce_2(),
            expected: test_vectors::get_block_test_expected_state_2(),
        },
        BlockTest {
            key: test_vectors::get_block_test_key_3(),
            counter: 1,
            nonce: test_vectors::get_block_test_nonce_3(),
            expected: test_vectors::get_block_test_expected_state_3(),
        },
        BlockTest {
            key: test_vectors::get_block_test_key_4(),
            counter: 2,
            nonce: test_vectors::get_block_test_nonce_4(),
            expected: test_vectors::get_block_test_expected_state_4(),
        },
        BlockTest {
            key: test_vectors::get_block_test_key_5(),
            counter: 0,
            nonce: test_vectors::get_block_test_nonce_5(),
            expected: test_vectors::get_block_test_expected_state_5(),
        },
    ]
}

pub fn get_encrypt_test_cases() -> (EncryptTest, EncryptTest, EncryptTest, EncryptTest) {
    (
        // Test Vector from Section 2.4.2 (114 bytes)
        EncryptTest {
            key: test_vectors::get_encrypt_test_key_0(),
            counter: 1,
            nonce: test_vectors::get_encrypt_test_nonce_0(),
            plaintext: test_vectors::get_encrypt_test_plaintext_0(),
            expected_ciphertext: test_vectors::get_encrypt_test_expected_ciphertext_0(),
        },
        // Test Vector #1 from A.2 (64 bytes)
        EncryptTest {
            key: test_vectors::get_encrypt_test_key_1(),
            counter: 0,
            nonce: test_vectors::get_block_test_nonce_1(),
            plaintext: test_vectors::get_encrypt_test_plaintext_1(),
            expected_ciphertext: test_vectors::get_encrypt_test_expected_ciphertext_1(),
        },
        // Test Vector #2 from A.2 (375 bytes)
        EncryptTest {
            key: test_vectors::get_encrypt_test_key_2(),
            counter: 1,
            nonce: test_vectors::get_encrypt_test_nonce_2(),
            plaintext: test_vectors::get_encrypt_test_plaintext_2(),
            expected_ciphertext: test_vectors::get_encrypt_test_expected_ciphertext_2(),
        },
        // Test Vector #3 from A.2 (127 bytes)
        EncryptTest {
            key: test_vectors::get_encrypt_test_key_3(),
            counter: 42,
            nonce: test_vectors::get_encrypt_test_nonce_3(),
            plaintext: test_vectors::get_encrypt_test_plaintext_3(),
            expected_ciphertext: test_vectors::get_encrypt_test_expected_ciphertext_3(),
        },
    )
}

fn generate_ciphertext(
    mut key: [u32; 8],
    ctr: u32,
    mut nonce: [u32; 3],
    plaintext: BoundedVec<u8, MAX>,
) -> BoundedVec<u8, MAX> {
    let chacha = ChaCha20::new(&mut key, ctr, &mut nonce);
    let plaintext = chacha.encrypt(plaintext);
    plaintext
}

#[test]
fn test_generate_input() {
    let mut key: [u32; 8] = [
        0x605fec2f, 0x30ffd5df, 0xf722ed31, 0xed119037, 0xa02cf2f2, 0x12d1e65a, 0xb1fb9cf4,
        0xf8425b7b,
    ];
    let ctr: u32 = 1;
    let mut nonce: [u32; 3] = [0x5ef1f372, 0x244dd026, 0x795c577c];

    let plaintext_contributions: str<160> = "{\"data\": {\"repository\": {\"defaultBranchRef\": {\"target\": {\"history\": {\"totalCount\": 0}}}}}, \"padding\": 000000000000000000000000000000000000000000000000000000000}";

    let plaintext_ownership: str<160> = "{\"data\": {\"viewer\": {\"id\": \"U_kgDOCPtlRA\", \"login\": \"0x18a6\"}}, \"padding\": 000000000000000000000000000000000000000000000000000000000000000000000000000000000000}";

    let id: str<12> = "U_kgDOCPtlRA";

    let mut plaintext_contributions_vec: BoundedVec<u8, MAX> = BoundedVec::new();
    let mut plaintext_ownership_vec: BoundedVec<u8, MAX> = BoundedVec::new();
    let mut id_vec: BoundedVec<u8, MAX> = BoundedVec::new();

    plaintext_contributions_vec.extend_from_array(plaintext_contributions.as_bytes());
    plaintext_ownership_vec.extend_from_array(plaintext_ownership.as_bytes());
    id_vec.extend_from_array(id.as_bytes());

    let ciphertext_contributions =
        generate_ciphertext(key, ctr, nonce, plaintext_contributions_vec);
    let ciphertext_ownership = generate_ciphertext(key, ctr, nonce, plaintext_ownership_vec);

    println(ciphertext_contributions);
    println("________");
    println(ciphertext_ownership);
}
