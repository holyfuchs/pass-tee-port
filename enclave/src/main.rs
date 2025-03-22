use actix_web::{post, web, App, HttpResponse, HttpServer, Responder};
use serde::Deserialize;
use std::error::Error;
use ethers::signers::LocalWallet;
use ethers::signers::Signer;
use ethers::core::k256::SecretKey;
use ethers::core::k256::ecdsa::SigningKey;
use std::fs;

mod passport;
mod sign;

#[derive(Deserialize)]
pub struct PassportInput {
    pub sod: Vec<u8>,
    pub ed1: Vec<u8>,
    pub address: String,
}

#[post("/passport_sign")]
async fn passport_sign(
    encrypted_data: web::Json<PassportInput>,
    wallet: web::Data<LocalWallet>,
) -> impl Responder {
    // TODO: data should be encrypted with the public key of this enclave
    let data = encrypted_data;

    match passport::verify_sod(&data.sod) {
        Ok(_) => (),
        Err(e) => return HttpResponse::BadRequest().body(e.to_string()),
    }

    let passport = passport::decode_dg1(data.ed1.clone());

    let passport = sign::PassportData::new(passport.id, passport.given_name, passport.family_name, data.address.clone());

    match passport.sign(&wallet.clone()) {
        Ok(output) => {
            HttpResponse::Ok().json(output)
        }
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

fn load_wallet_from_file(path: &str) -> Result<LocalWallet, Box<dyn Error>> {
    // Read the file as raw bytes.
    let key_bytes = fs::read(path)?;
    
    // Ensure the key length is 32 bytes.
    if key_bytes.len() != 32 {
        return Err("Invalid private key length, expected 32 bytes".into());
    }
    
    // Create a SecretKey using ethers' re-export of k256.
    let secret_key = SecretKey::from_slice(&key_bytes)?;
    
    // Create a SigningKey from the SecretKey.
    let signing_key = SigningKey::from(secret_key);
    
    // Convert the signing key into a LocalWallet.
    let wallet: LocalWallet = signing_key.into();
    
    Ok(wallet)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let wallet = load_wallet_from_file("./ecdsa.sec").expect("Failed to load wallet");
    // Clone the wallet so that wallet can be used later.
    let wallet_data = web::Data::new(wallet.clone());
    println!("Loaded wallet with address: {:?}", wallet.address());

    HttpServer::new(move || {
        App::new()
            .app_data(wallet_data.clone())
            .service(passport_sign)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
