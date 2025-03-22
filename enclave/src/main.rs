use actix_web::{post, web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};
use std::error::Error;
use ethers::signers::{LocalWallet, Signer};

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
    let key_hex = std::fs::read_to_string(path)?.trim().to_string();

    println!("Contents of {}: {}", path, key_hex);

    let wallet: LocalWallet = key_hex.parse()?;
    Ok(wallet)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let wallet = load_wallet_from_file("/usr/src/app/ecdsa.sec").expect("Failed to load wallet");
    let wallet_data = web::Data::new(wallet);
    println!("created wallet from enclave private key");

    HttpServer::new(move || {
        App::new()
            .app_data(wallet_data.clone())
            .service(passport_sign)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
