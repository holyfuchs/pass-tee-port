use std::error::Error;

use sha3::{Digest, Keccak256};

use alloy::hex;
use alloy::sol;
use alloy::sol_types::SolValue;
use alloy_primitives::Address;
use alloy_primitives::FixedBytes;

use ethers::signers::LocalWallet;
use ethers::core::types::H256;
use ethers::utils::keccak256;

sol! {
    #[derive(Debug, serde::Serialize)]
    struct OnchainInfo {
        bytes32 id;
        address owner;
        bytes data;
    }
}

pub struct PassportData {
    info: OnchainInfo,
}

#[derive(Debug, serde::Serialize)]
pub struct SignedPassportData {
    info: OnchainInfo,
    signature: String,
}

impl PassportData {
    pub fn new(passport_number: String, given_name: String, family_name: String, address: String) -> Self {
        Self {
            info: Self::generate_passport_tee_data(
                passport_number,
                given_name,
                family_name,
                address,
            ),
        }
    }

    fn generate_passport_tee_data(
        passport_number: String,
        given_name: String,
        family_name: String,
        address: String,
    ) -> OnchainInfo {
        let mut hasher: sha3::digest::core_api::CoreWrapper<sha3::Keccak256Core> = Keccak256::new();
        hasher.update(passport_number.as_bytes());
        let id = hasher.finalize();
        let id = FixedBytes::from_slice(&id);

        let hidden_name = format!(
            "{}{} {}{}",
            given_name.chars().next().unwrap_or('*'),
            "*".repeat(given_name.len().saturating_sub(1)),
            family_name.chars().next().unwrap_or('*'),
            "*".repeat(family_name.len().saturating_sub(1))
        );

        let address = Address::parse_checksummed(address, None).expect("valid checksum");

        let name: alloy_primitives::Bytes = hidden_name.as_bytes().to_vec().into();
        let passport_data = OnchainInfo {
            id,
            owner: address,
            data: name,
        };

        passport_data
    }

    pub fn sign(&self, wallet: &LocalWallet) -> Result<SignedPassportData, Box<dyn Error>> {
        let encoded_data = self.info.abi_encode_packed();

        let hash = keccak256(&encoded_data);
        let message_hash = H256::from_slice(&hash);

        let signature = wallet.sign_hash(message_hash)?;

        let mut sig_bytes = [0u8; 65];
        signature.r.to_big_endian(&mut sig_bytes[0..32]);
        signature.s.to_big_endian(&mut sig_bytes[32..64]);
        sig_bytes[64] = signature.v as u8;

        let signed_passport_data = SignedPassportData {
            info: self.info.clone(),
            signature: hex::encode(&sig_bytes),
        };

        // println!("encoded_data: 0x{}", hex::encode(&encoded_data));
        // println!("data: {:?}", self.passport_data);
        // println!("Address: {:?}", wallet.address());
        // println!("Signature: 0x{}", hex::encode(&sig_bytes));
        // println!("Hash: 0x{}", hex::encode(&hash));

        Ok(signed_passport_data)
    }
}
