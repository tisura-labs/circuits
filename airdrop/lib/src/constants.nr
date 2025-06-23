global PROXY_PUBKEY_X: [u8; 32] = [
    221, 175, 66, 128, 34, 42, 173, 14, 103, 4, 220, 33, 90, 25, 201, 149, 17, 118, 33, 83, 28, 44,
    238, 247, 236, 72, 13, 255, 174, 240, 48, 198,
];
global PROXY_PUBKEY_Y: [u8; 32] = [
    212, 190, 236, 143, 82, 193, 27, 121, 215, 27, 140, 12, 209, 94, 229, 239, 135, 18, 195, 202,
    153, 109, 29, 237, 168, 183, 33, 143, 251, 136, 82, 213,
];

// Ownership.
global MAX_OWNERSHIP_RECORD_LEN: u32 = 160;
global MAX_OWNERSHIP_JSON_LENGTH: u32 = 32; // In Ownership, len of JSON is always 32.
global NODE_ID_LEN: u32 = 12;

// Contributions.
global MAX_CONTRIBUTIONS_RECORD_LEN: u32 = 200;
global MAX_CONTRIBUTIONS_JSON_LENGTH: u32 = 160; // In Contributions, Max length of JSON is up to 255, but we use 160 as a beginning.
global MAX_REPO_NAME_LEN: u32 = 20;
global MAX_REPO_OWNER_LEN: u32 = 20;
