global MAX_U32: u32 = 0xFFFFFFFF;
global WORD_SIZE: u8 = 32;

pub fn wrapping_add_32(x: u32, y: u32) -> u32 {
    std::wrapping_add(x, y)
}

pub fn rotl32(x: u32, n_bits: u8) -> u32 {
    // In Noir, the bit count in a bit-shift operation must fit in a `u8`, hence `n_bits: u8`.
    let l = x << n_bits & MAX_U32;
    let r = x >> (WORD_SIZE - n_bits);
    l | r
}

#[test(should_fail_with = "Failed constraint")]
fn test_add() {
    assert_eq(0xFFFFFFFF + 1, 0);
}

#[test]
fn test_add_modulo_2_32() {
    assert_eq(wrapping_add_32(0xFFFFFFFF, 1), 0);
}

#[test]
fn test_rotl32_lt_32() {
    assert_eq(rotl32(0x1000, 4), 0x10000);
    /*
        The test was initially asserting: assert_eq(rotl32(0x1000, 4), 0x0001); and was expected to fail.
        However:
            - 0x1000 is treated as a 32-bit value: 0x00001000.
            - Rotating left by 4 bits gives: 0x00010000 (0x10000).
            This is the correct behavior for 32-bit rotation, unlike the previous incorrect expectation of 0x0001.
    */
}

#[test]
fn test_rotl32() {
    assert_eq(rotl32(0x00000001, 0), 0x00000001);

    assert_eq(rotl32(0x00000000, 4), 0x00000000);
    assert_eq(rotl32(0xFFFFFFFF, 4), 0xFFFFFFFF);

    assert_eq(rotl32(0x10000000, 4), 0x00000001);
    assert_eq(rotl32(0x00000001, 4), 0x00000010);
}
