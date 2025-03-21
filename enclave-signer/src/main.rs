mod sign;

fn main() {
    let passport = sign::PassportData::new(
        "A-1239587-124".to_string(), 
        "Gertrude".to_string(), 
        "Granate".to_string()
    );
    passport.sign();
}
