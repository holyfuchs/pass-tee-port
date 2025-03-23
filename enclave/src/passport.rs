use std::borrow::Cow;
use openssl::error::ErrorStack;
use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
use openssl::x509::store::X509Store;
use openssl::x509::X509StoreContext;
use openssl::x509::{X509, store::X509StoreBuilder};
use openssl::stack::Stack;
use std::fs;

#[derive(Debug)]
pub struct PassportData {
    pub id: String,
    pub given_name: String,
    pub family_name: String,
}

pub fn decode_dg1(dg1: Vec<u8>) -> PassportData {
    let s: Cow<str> = String::from_utf8_lossy(&dg1);
    println!("DG1 as string: {}", s);

    let parts: Vec<&str> = s.split("<").collect();
    println!("Split parts: {:?}", parts);

    let passport_number = parts.get(25).unwrap_or(&"").trim().to_string();
    let given_name = parts.get(5).unwrap_or(&"").trim().to_string();
    let family_name = parts.get(3).unwrap_or(&"").trim().to_string();

    PassportData {
        id: passport_number,
        given_name,
        family_name,
    }
}

pub fn verify_sod(sod: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let pkcs7 = Pkcs7::from_der(sod)?;
	let additional_certs = Stack::new()?;
	let signer_certs = pkcs7.signers(&additional_certs, Pkcs7Flags::empty())?;
	let first_cert = signer_certs.iter().next().unwrap();
    let cert_pem = first_cert.to_pem()?;
    let cert = X509::from_pem(&cert_pem)?;

    // let _issuer = verify_ds_and_get_issuer(&cert, "./masterList.pem")?;
    let _issuer = verify_ds_and_get_issuer(&cert, "/masterList.pem")?;
    Ok(())
}

fn verify_ds_and_get_issuer(ds_cert: &X509, ca_file_path: &str) -> Result<X509, Box<dyn std::error::Error>> {
    let pem_data = fs::read_to_string(ca_file_path)?;
    let csca_certs: Vec<X509> = pem_data
        .split("-----BEGIN CERTIFICATE-----")
        .filter(|s| !s.trim().is_empty())
        .map(|s| format!("-----BEGIN CERTIFICATE-----{}", s))
        .filter_map(|s| X509::from_pem(s.as_bytes()).ok())
        .collect();

    if csca_certs.is_empty() {
        return Err("No CSCA certificates found in CA file".into());
    }

    let mut store_builder = X509StoreBuilder::new()?;
    for cert in &csca_certs {
        store_builder.add_cert(cert.clone())?;
    }
    let store: X509Store = store_builder.build();

    let mut store_ctx = X509StoreContext::new()?;
    let chain = Stack::new()?;
    Ok(store_ctx.init(&store, ds_cert, &chain, |ctx| {
        if let Err(e) = ctx.verify_cert() {
            return Err(e);
        }
        let chain = ctx.chain().ok_or(ErrorStack::get())?;
        if chain.len() < 2 {
            return Err(ErrorStack::get()); 
        }

        Ok(chain[chain.len() - 1].to_owned())
    })?)
}