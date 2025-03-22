use actix_web::{post, web, App, HttpResponse, HttpServer, Responder};
use openssl::x509::X509;
use serde::{Deserialize, Serialize};
use std::error::Error;
use ethers::signers::LocalWallet;
use ethers::signers::Signer;
use ethers::core::k256::SecretKey;
use ethers::core::k256::ecdsa::SigningKey;
use std::fs;

mod passport;
mod sign;

#[derive(Deserialize, Debug)]
pub struct PassportInput {
    pub sod: Vec<u8>,
    pub ed1: Vec<u8>,
    pub address: String,
}

#[derive(Serialize, Debug)]
pub struct SignResponse {
    pub encoded_data: String,
    pub data_id: String,
    pub wallet_address: String,
    pub signature: String,
    pub hash: String,
}

#[post("/passport_sign")]
async fn passport_sign(
    encrypted_data: web::Json<PassportInput>,
    wallet: web::Data<LocalWallet>,
) -> impl Responder {
    println!("Received request: {:?}", encrypted_data);

    let ds_cert = match X509::from_pem(&encrypted_data.sod) {
        Ok(cert) => cert,
        Err(e) => {
            println!("Error parsing SOD certificate: {}", e);
            return HttpResponse::BadRequest().body(e.to_string());
        }
    };

    let issuer = match passport::verify_ds_and_get_issuer(&ds_cert, "masterList.pem") {
        Ok(issuer) => issuer,
        Err(e) => {
            println!("Error verifying issuer: {}", e);
            return HttpResponse::BadRequest().body(format!("invalid issuer: {}", e.to_string()));
        }
    };
    println!("Issuer verified: {:?}", issuer);

    let dg1_data = passport::decode_dg1(encrypted_data.ed1.clone());
    println!("Decoded DG1 passport data: {:?}", dg1_data);

    let passport = sign::PassportData::new(
        dg1_data.id,
        dg1_data.given_name,
        dg1_data.family_name,
        encrypted_data.address.clone(),
    );

    match passport.sign(&wallet.clone()) {
        Ok(output) => {
            println!("Sending response: {:?}", output);
            HttpResponse::Ok().json(output)
        }
        Err(e) => {
            println!("Error signing passport data: {}", e);
            HttpResponse::InternalServerError().body(e.to_string())
        }
    }
}

fn load_wallet_from_file(path: &str) -> Result<LocalWallet, Box<dyn Error>> {
    let key_bytes = fs::read(path)?;
    
    if key_bytes.len() != 32 {
        return Err("Invalid private key length, expected 32 bytes".into());
    }
    
    let secret_key = SecretKey::from_slice(&key_bytes)?;
    
    let signing_key = SigningKey::from(secret_key);
    
    let wallet: LocalWallet = signing_key.into();
    
    Ok(wallet)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let wallet = load_wallet_from_file("./ecdsa.sec").expect("Failed to load wallet");
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
