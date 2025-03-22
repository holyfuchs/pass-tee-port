mod sign;

fn main() {
    let passport = sign::PassportData::new(
        "A-1239587-124".to_string(), 
        "Gertrude".to_string(), 
        "Granate".to_string(),
        "0xa0c28cF11F536B8bE2224Db0a26F97952D1e6cc3".to_string()
    );
    passport.sign();
}
