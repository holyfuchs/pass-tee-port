use der::asn1::{ObjectIdentifier, OctetString, PrintableString, Any};
use cms::content_info::{ContentInfo};
use der::{Decode, Encode, Sequence};
use cms::signed_data::{SignedData};
use std::io::{Error, ErrorKind};
use sha3::Digest;

use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Padding;
use openssl::sign::{RsaPssSaltlen, Verifier};
use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
use openssl::stack::Stack;
use openssl::asn1::Asn1Object;
use std::error::Error as StdError;


/* -------------------------------------------------------------------------- */
/*                                ASN1 Structs                                */
/* -------------------------------------------------------------------------- */
#[derive(Debug, PartialEq, Eq, Sequence)]
pub struct AlgorithmIdentifier {
    pub oid: ObjectIdentifier,
    pub parameters: Option<Any>,
}

#[derive(Debug, PartialEq, Eq, Sequence)]
pub struct DataGroupHash {
    pub data_group_number: u8,
    pub data_group_hash_value: OctetString,
}

#[derive(Debug, PartialEq, Eq, Sequence)]
pub struct LDSVersionInfo {
    pub lds_version: PrintableString,
    pub unicode_version: PrintableString,
}

#[derive(Debug, PartialEq, Eq, Sequence)]
pub struct LDSSecurityObject {
    pub version: u8,
    pub hash_algorithm: AlgorithmIdentifier,
    pub data_group_hash_values: Vec<DataGroupHash>,
    pub lds_version_info: Option<LDSVersionInfo>,
}


/* -------------------------------------------------------------------------- */
/*                                   Structs                                  */
/* -------------------------------------------------------------------------- */
#[derive(Debug)]
struct SOD {
	encapsulated_content: Vec<u8>,
	signed_attribs_hash_oid: String,
	signed_attributes: Vec<u8>,
	message_digest: Option<Vec<u8>>,
	signature: Vec<u8>,
	sig_type: String,
}


/* -------------------------------------------------------------------------- */
/*                                   Helpers                                  */
/* -------------------------------------------------------------------------- */
fn calc_hash(data: &[u8], hash_algorithm_oid: &str) -> Vec<u8> {
	let algorithm = Asn1Object::from_str(hash_algorithm_oid).unwrap();
    let algo_str = algorithm.to_string().to_lowercase();
    
    if algo_str.contains("sha224") {
        let mut hasher = sha2::Sha224::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    } else if algo_str.contains("sha256") {
        let mut hasher = sha2::Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    } else if algo_str.contains("sha384") {
        let mut hasher = sha2::Sha384::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    } else if algo_str.contains("sha512") {
        let mut hasher = sha2::Sha512::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    } else {
        panic!("Unsupported hash algorithm: {}", hash_algorithm_oid)
    }
}

fn get_cert_pubkey_from_sod(sod_data: &[u8]) -> Result<PKey<openssl::pkey::Public>, Box<dyn StdError>> {
    // Remove header safely
    let cert_data = sod_data.get(4..)
        .ok_or("SOD data is too short to remove header")?
        .to_vec();

    // Parse PKCS#7 data
    let pkcs7 = Pkcs7::from_der(&cert_data)
        .map_err(|e| format!("Failed to parse PKCS#7 data: {}", e))?;

    let additional_certs = Stack::new()?;
    let signer_certs = pkcs7.signers(&additional_certs, Pkcs7Flags::empty())
        .map_err(|e| format!("Failed to get signer certificates: {}", e))?;

    let first_cert = signer_certs.iter().next()
        .ok_or("No signer certificates found")?;

    Ok(first_cert.public_key()?)
}

fn verify_signature(data: &[u8], signature: &[u8], pubkey: &PKey<openssl::pkey::Public>, digest_type: &str) -> bool {
    let digest = {
        let dt = digest_type.to_lowercase();
        if dt.contains("sha1") {
            MessageDigest::sha1()
        } else if dt.contains("sha224") {
            MessageDigest::sha224()
        } else if dt.contains("sha256") || dt.contains("rsassapss") {
            MessageDigest::sha256()
        } else if dt.contains("sha384") {
            MessageDigest::sha384()
        } else if dt.contains("sha512") {
            MessageDigest::sha512()
        } else {
            MessageDigest::sha256()
        }
    };

    let mut verifier = match Verifier::new(digest, pubkey) {
        Ok(v) => v,
        Err(_) => return false,
    };

    if digest_type.to_lowercase().contains("rsassapss") {
        if verifier.set_rsa_padding(Padding::PKCS1_PSS).is_err() {
            return false;
        }
        if verifier
            .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
            .is_err()
        {
            return false;
        }
    }

    if verifier.update(data).is_err() {
        return false;
    }

    verifier.verify(signature).unwrap_or(false)
}


/* -------------------------------------------------------------------------- */
/*                                 SOD Parser                                 */
/* -------------------------------------------------------------------------- */
fn parse_sod_data(sod_data: &[u8]) -> Result<SOD, Box<dyn std::error::Error>> {
    // remove header
    let cms_data = sod_data[4..].to_vec();
    
    let content_info = ContentInfo::from_der(&cms_data)
        .map_err(|e| e.to_string())?;
    let signed_data = content_info.content
        .decode_as::<SignedData>()
        .map_err(|e| e.to_string())?;
    
    let encap_content_info_econtent = signed_data.encap_content_info.econtent
        .ok_or_else(|| "Failed to decode encapsulated content".to_string())?;
    let encapsulated_content = encap_content_info_econtent.value().to_vec();
    let signed_attribs_hash_oid = signed_data.digest_algorithms.get(0)
        .unwrap()
        .oid.to_string();
    
    let signer_info = signed_data.signer_infos.0.get(0).unwrap();
    let signed_attributes = signer_info.signed_attrs.as_ref()
        .unwrap()
        .to_der()
        .map_err(|e| e.to_string())?;
    
    let mut message_digest: Option<Vec<u8>> = None;
    if let Some(signed_attrs) = &signer_info.signed_attrs {
        for attr in signed_attrs.iter() {
            if attr.oid.to_string() == "1.2.840.113549.1.9.4" { // message-digest OID
                let attribute_value = attr.values.get(0)
                    .expect("Failed to decode attribute value");
                message_digest = Some(attribute_value.value().to_vec());
            }
        }
    }
    
    let signature = signer_info.signature.as_bytes().to_vec();
    let sig_type = match Asn1Object::from_str(&signer_info.signature_algorithm.oid.to_string()) {
        Ok(obj) => obj.to_string(),
        Err(_) => signer_info.signature_algorithm.oid.to_string(),
    };

    Ok(SOD {
        encapsulated_content,
        signed_attribs_hash_oid,
        signed_attributes,
        message_digest,
        signature,
        sig_type,
    })
}


pub fn check(sod_data: &[u8], dg1: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
	/* ------------------ Verify Integrity Of Hashes/Signatures ----------------- */
    let mut sod_data_header = vec![0x30, 0x09, 0x06, 0x05];
    sod_data_header.extend_from_slice(&sod_data);
    let sod_data = sod_data_header;
	let sod = parse_sod_data(&sod_data).unwrap();
	let sod_hash = calc_hash(&sod.encapsulated_content, &sod.signed_attribs_hash_oid);
	if sod.message_digest.unwrap() != sod_hash {
		println!("SOD hash is invalid");
		Error::new(ErrorKind::InvalidData, "Invalid SOD data");
	} else {
		println!("SOD hash is valid");
	}
	let public_key = get_cert_pubkey_from_sod(&sod_data).unwrap();
	let verified = verify_signature(&sod.signed_attributes, &sod.signature, &public_key, &sod.sig_type);
	if !verified {
		println!("SOD Signature not verified");
	} else {
		println!("SOD Signature verified!");
	}

	let ldssec = LDSSecurityObject::from_der(&sod.encapsulated_content)
		.map_err(|e| e.to_string())?;
	let ldssec_hashes_oid = ldssec.hash_algorithm.oid.to_string();
	let ldssec_hashes: Vec<(u8, Vec<u8>)> = ldssec.data_group_hash_values
		.iter()
		.map(|hash| (hash.data_group_number, hash.data_group_hash_value.as_bytes().to_vec()))
		.collect();

	/* --------------------------- Check Hashes Of DGs -------------------------- */
	let dg1_hash = calc_hash(&dg1, &ldssec_hashes_oid);
	// get the hash for DG1 from the ldssec_hashes vector (key 1 in vector)
	if dg1_hash != *ldssec_hashes.iter().find(|(key, _)| *key == 1).map(|(_, value)| value).unwrap() {
		println!("DG1 hash is invalid");
		Error::new(ErrorKind::InvalidData, "Invalid DG1 hash");
	} else {
		println!("DG1 hash is valid");
	}

	Ok(())
}
