use actix_web::{post, web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};
use std::error::Error;
use ethers::signers::LocalWallet;
use ethers::signers::Signer;
use ethers::core::k256::SecretKey;
use ethers::core::k256::ecdsa::SigningKey;
use std::fs;

#[derive(Debug, Clone)]
pub struct PassportDataID {
    pub id: String,
    pub data: Vec<u8>,
}

impl PassportDataID {
    pub fn abi_encode_packed(&self) -> Vec<u8> {
        let mut v = self.id.as_bytes().to_vec();
        v.extend_from_slice(&self.data);
        v
    }
}

#[derive(Debug, Clone)]
pub struct SignOutput {
    pub encoded_data: String,
    pub data_id: String,
    pub wallet_address: String,
    pub signature: String,
    pub hash: String,
}

pub struct PassportData {
    pub passport_data_id: PassportDataID,
}

impl PassportData {
    pub fn new(passport_number: String, given_name: String, family_name: String) -> Self {
        let passport_data_id = PassportDataID {
            id: passport_number,
            data: format!("{} {}", given_name, family_name).into_bytes(),
        };
        Self { passport_data_id }
    }

    // Modified sign function accepts a wallet reference.
    pub fn sign(&self, wallet: &LocalWallet) -> Result<SignOutput, Box<dyn Error>> {
        use ethers::core::types::H256;
        use ethers::utils::keccak256;
        use alloy::hex;

        // 1. Encode the data
        let encoded_data = self.passport_data_id.abi_encode_packed();

        // 2. Hash it (keccak256)
        let hash = keccak256(&encoded_data);
        let message_hash = H256::from_slice(&hash);

        // 3. Use the provided wallet to sign the hash
        let signature = wallet.sign_hash(message_hash)?;

        // 4. Convert to a 65-byte signature
        let mut sig_bytes = [0u8; 65];
        signature.r.to_big_endian(&mut sig_bytes[0..32]);
        signature.s.to_big_endian(&mut sig_bytes[32..64]);
        sig_bytes[64] = signature.v as u8;

        // 5. Prepare output struct with hex-formatted values
        let output = SignOutput {
            encoded_data: format!("0x{}", hex::encode(&encoded_data)),
            data_id: format!("{:?}", self.passport_data_id),
            wallet_address: format!("{:?}", wallet.address()),
            signature: format!("0x{}", hex::encode(&sig_bytes)),
            hash: format!("0x{}", hex::encode(&hash)),
        };

        Ok(output)
    }
}

#[derive(Deserialize)]
pub struct PassportInput {
    pub passport_number: String,
    pub given_name: String,
    pub family_name: String,
}

#[derive(Serialize)]
pub struct SignResponse {
    pub encoded_data: String,
    pub data_id: String,
    pub wallet_address: String,
    pub signature: String,
    pub hash: String,
}

#[post("/passport_sign")]
async fn passport_sign(
    data: web::Json<PassportInput>,
    wallet: web::Data<LocalWallet>,
) -> impl Responder {
    let passport = PassportData::new(
        data.passport_number.clone(),
        data.given_name.clone(),
        data.family_name.clone(),
    );

    match passport.sign(&wallet) {
        Ok(output) => {
            let response = SignResponse {
                encoded_data: output.encoded_data,
                data_id: output.data_id,
                wallet_address: output.wallet_address,
                signature: output.signature,
                hash: output.hash,
            };
            HttpResponse::Ok().json(response)
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
