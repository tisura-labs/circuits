pub struct JsonSlice<let MAX_JSON_LENGTH: u32> {
    json: str<MAX_JSON_LENGTH>,
    start: u32,
    end: u32,
}

pub fn check_json<let MAX_LEN: u32, let MAX_JSON_LENGTH: u32>(
    decrypted: BoundedVec<u8, MAX_LEN>,
    json_slice: pub JsonSlice<MAX_JSON_LENGTH>,
) {
    for i in 0..MAX_JSON_LENGTH {
        if i + json_slice.start < json_slice.end {
            assert(
                decrypted.get(i + json_slice.start) == json_slice.json.as_bytes()[i],
                "JSON does not match expected value.",
            );
        }
    }
}

#[test]
fn test_check_json() {
    let decrypted: BoundedVec<u8, 200> = BoundedVec::from_array([
        13, 10, 13, 10, 123, 34, 100, 97, 116, 97, 34, 58, 123, 34, 114, 101, 112, 111, 115, 105,
        116, 111, 114, 121, 34, 58, 123, 34, 110, 97, 109, 101, 34, 58, 34, 109, 111, 110, 111, 34,
        44, 34, 111, 119, 110, 101, 114, 34, 58, 123, 34, 108, 111, 103, 105, 110, 34, 58, 34, 116,
        105, 115, 117, 114, 97, 45, 108, 97, 98, 115, 34, 125, 44, 34, 100, 101, 102, 97, 117, 108,
        116, 66, 114, 97, 110, 99, 104, 82, 101, 102, 34, 58, 123, 34, 116, 97, 114, 103, 101, 116,
        34, 58, 123, 34, 104, 105, 115, 116, 111, 114, 121, 34, 58, 123, 34, 116, 111, 116, 97, 108,
        67, 111, 117, 110, 116, 34, 58, 53, 48, 125, 125, 125, 125, 125, 125, 23, 239, 191, 189,
        239, 191, 189, 70, 239, 191, 189, 36, 239, 191, 189, 239, 191, 189, 53, 239, 191, 189, 47,
        62, 77, 79, 239, 191, 189, 239, 191, 189, 73, 239, 191, 189, 98, 125, 239, 191, 189, 239,
        191, 189, 239, 191, 189, 239, 191, 189, 239, 191, 189, 239, 191, 189, 239, 191, 189, 84, 57,
        35, 239, 191, 189,
    ]);

    // Example JSON in string format padded with empty spaces.
    let json: str<160> = "{\"data\":{\"repository\":{\"name\":\"mono\",\"owner\":{\"login\":\"tisura-labs\"},\"defaultBranchRef\":{\"target\":{\"history\":{\"totalCount\":50}}}}}}                             ";
    let start: u32 = 4; // Start index of the JSON in the decrypted response.
    let end: u32 = 135; // End index of the JSON in the decrypted response.
    let jsonSlice = JsonSlice { json, start, end };

    check_json(decrypted, jsonSlice);
}
