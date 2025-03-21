use std::error::Error;

use sha3::{Digest, Keccak256};

use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use k256::PublicKey;
use k256::elliptic_curve::rand_core::OsRng;

use alloy::hex;
use alloy::sol;
use alloy::sol_types::eip712_domain;
use alloy::sol_types::SolStruct;
use alloy::sol_types::SolValue;
use alloy_primitives::FixedBytes;

use ethers::signers::{LocalWallet, Signer};
use ethers::core::types::{H256};
use ethers::utils::keccak256;
// use rand_core::{TryRngCore, CryptoRng};

sol! {
    #[derive(Debug)]
    struct PassportDataID {
        bytes32 id;
        bytes data;
    }
}

pub struct PassportData {
    passport_data_id: PassportDataID,
}

impl PassportData {
    pub fn new(passport_number: String, given_name: String, family_name: String) -> Self {
        Self {
            passport_data_id: Self::generate_passport_data_id(
                passport_number,
                given_name,
                family_name,
            ),
        }
    }

    fn generate_passport_data_id(
        passport_number: String,
        given_name: String,
        family_name: String,
    ) -> PassportDataID {
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

        let name: alloy_primitives::Bytes = hidden_name.as_bytes().to_vec().into();
        let passport_data_id = PassportDataID {
            id,
            data: name,
        };

        passport_data_id
    }

    pub fn sign(&self) -> Result<(), Box<dyn Error>> {
        // 1. Encode the data
        let encoded_data = self.passport_data_id.abi_encode_packed();

        // 2. Hash it (keccak256)
        let hash = keccak256(&encoded_data);
        let message_hash = H256::from_slice(&hash);

        // 3. Parse the wallet from the private key
        let wallet: LocalWallet = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".parse()?;

        // 4. Sign the hash (non-async)
        let signature = wallet.sign_hash(message_hash)?;

        // 5. Convert to 65-byte signature
        let mut sig_bytes = [0u8; 65];
        signature.r.to_big_endian(&mut sig_bytes[0..32]);
        signature.s.to_big_endian(&mut sig_bytes[32..64]);
        sig_bytes[64] = signature.v as u8;

        // 6. Print debug info
        println!("encoded_data: 0x{}", hex::encode(&encoded_data));
        println!("data id: {:?}", self.passport_data_id);
        println!("Address: {:?}", wallet.address());
        println!("Signature: 0x{}", hex::encode(&sig_bytes));
        println!("Hash: 0x{}", hex::encode(&hash));

        Ok(())
    }

    // pub fn sign(&self) -> Result<(), Box<dyn Error>> {
    //     let encoded_data = self.passport_data_id.abi_encode_packed();
    //     let mut hasher = Keccak256::new();
    //     hasher.update(&encoded_data);
    //     let hash = hasher.finalize();

    //     let wallet: LocalWallet = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".parse().unwrap();
    //     let message_hash = H256::from(hash);
    //     let signature: Signature = wallet.sign_hash(message_hash).await?;

    //     let mut sig_bytes = [0u8; 65];
    //     signature.r.to_big_endian(&mut sig_bytes[0..32]);
    //     signature.s.to_big_endian(&mut sig_bytes[32..64]);
    //     sig_bytes[64] = signature.v;

    //     println!("encoded_data: {:?}", hex::encode(encoded_data));
    //     println!("data id: {:?}", self.passport_data_id);
    //     println!("Public Key: {:?}", hex::encode(signing_key.to_bytes()));
    //     println!("Signature: 0x{}", hex::encode(&eth_signature));
    //     println!("Hash: 0x{}", hex::encode(&hash));
    //     Ok(())
    //     // Verify attestation
    //     // let attestation_doc = get_attestation_doc(format!("http://{}:1301/attestation/raw", self.ip).parse()?).await?;
    //     // let parsed = decode_attestation(attestation_doc.clone())?;
    //     // let expected_verifying_key = hex::encode(verify_with_timestamp(attestation_doc, parsed.pcrs, parsed.timestamp)?);
    //     // // Create digest
    //     // let digest = self._create_digest();
    //     // // Verify signature
    //     // let signature_with_recovery = hex::decode(&self.response.signature)?;
    //     // let signature = Signature::from_slice(&signature_with_recovery[..64])?;
    //     // let rec_id = RecoveryId::try_from(signature_with_recovery.last().unwrap().clone()-27)?;
    //     // // Verify signature using secp256k1

    //     // let recovered_key = VerifyingKey::recover_from_prehash(
    //     //     digest.as_slice(),
    //     //     &signature,
    //     //     rec_id
    //     // )?;
    //     // let recoverd_key_hex = hex::encode(recovered_key.to_encoded_point(false).as_bytes()).split_off(2);
    //     // assert_eq!(expected_verifying_key, recoverd_key_hex);
    //     // Ok(())
    // }

    // fn _sol_data(&self) -> RequestResponseData {
    //     RequestResponseData {
    //         requestData: RequestData {
    //             url: self.request.url.clone(),
    //             method: self.request.method.clone(),
    //             headerKeys: self.request.headers.keys().map(|k| k.to_owned()).collect(),
    //             headerValues: self.request.headers.values().map(|k| k.to_owned()).collect(),
    //             body: self.request.body.clone(),
    //             responseHeaders: self.request.response_headers.clone(),
    //         },
    //         responseData: ResponseData {
    //             handler: self.response.handler,
    //             status: self.response.status,
    //             headerKeys: self.response.headers.keys().map(|k| k.to_owned()).collect(),
    //             headerValues: self.response.headers.values().map(|k| k.to_owned()).collect(),
    //             body: self.response.body.clone(),
    //             timestamp: self.response.timestamp,
    //         },
    //     }
    // }

    // fn _create_digest(&self) -> Vec<u8> {
    //     let domain = eip712_domain! {
    //         name: "marlin.oyster.Teefetch",
    //         version: "1",
    //     };

    //     let signing_struct = self._sol_data();
    //     let signing_hash = signing_struct.eip712_signing_hash(&domain);

    //     signing_hash.to_vec()
    // }

    // pub fn abi_encode(&self) -> Result<Vec<u8>> {
    //     Ok(self._sol_data().abi_encode())
    // }

    // pub fn get_signature(&self) -> &str {
    //     &self.response.signature
    // }
}
