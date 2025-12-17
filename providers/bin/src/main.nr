use providers::pappers;

// todo: Refactor inputs to be generic for any provider
fn main(city: u64, cities: pub [u64; 2]) {
    pappers::prove(city, cities);
}

#[test]
fn test_main() {
    let cities = [1, 3];
    main(1, cities);
}
