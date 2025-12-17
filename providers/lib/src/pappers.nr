fn prove(city: u64, cities: [u64; 2]) {
    let mut found = false;
    for i in 0..cities.len() {
        if cities[i] == city {
            found = true;
        }
    }
    assert(found);
}

#[test]
fn test_prove() {
    let cities = [1, 3];
    prove(1, cities);
}
