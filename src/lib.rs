//! AWS Nitro Enclave Document material
//!
//! ## Authors
//!
//! @asa93 for Eternis.AI
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the repo for
//! information on licensing and copyright.

//#![no_std]

use base64::{engine::general_purpose::STANDARD, Engine};
use core::convert::TryInto;
use p384::ecdsa::{Signature, VerifyingKey};
use rsa::signature::Verifier;
use rustls::{server::AllowAnyAuthenticatedClient, Certificate, RootCertStore};
use std::collections::BTreeMap;
use thiserror::Error;
use tracing::info;
use wasm_bindgen::prelude::*;
use x509_cert::der::Decode;
use x509_cert::der::Encode;

#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("Invalid nonce")]
    InvalidNonce,
    #[error("Invalid PCR {0}")]
    InvalidPCR(usize),
    #[error("X509 certificate verification failed: {0}")]
    X509CertVerificationFailed(String),
    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(String),
    #[error("Failed to decode trusted root: {0}")]
    FailedToDecodeTrustedRoot(base64::DecodeError),
    #[error("Payload length bytes conversion failed: {0}")]
    PayloadLengthBytesConversionFailed(core::num::TryFromIntError),
    #[error("Decode X509 certificate failed: {0}")]
    DecodeX509CertFailed(String),
    #[error("Public key DER failed: {0}")]
    PublicKeyDerFailed(String),
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),
    #[error("Failed to add trusted root cert: {0}")]
    FailedToAddTrustedRootCert(String),
}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("Parse document failed: {0}")]
    ParseDocumentFailed(String),
    #[error("Parse payload failed: {0}")]
    ParsePayloadFailed(String),
}

#[derive(Debug, Error)]
pub enum ParseVerificationError {
    #[error("Parse error: {0}")]
    ParseError(ParseError),
    #[error("Verification error: {0}")]
    VerificationError(VerificationError),
}

#[derive(Debug)]
pub struct AttestationDocument {
    pub protected: Vec<u8>,
    pub signature: Vec<u8>,
    pub payload: Vec<u8>,
}

const AWS_TRUSTED_ROOT_CERT: &str = "MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTELMAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYDVQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQLDANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEGBSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZEh8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkFR+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYCMQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPWrfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6NIwLz3/Y=";

#[derive(Debug)]
pub struct Payload {
    pub module_id: String,
    pub timestamp: u64,
    pub public_key: Vec<u8>,
    pub certificate: Vec<u8>,
    pub cabundle: Vec<Vec<u8>>,
    pub nonce: Vec<u8>,
    pub user_data: Option<Vec<u8>>,
    pub digest: String,
    pub pcrs: Vec<Vec<u8>>,
}

fn verify_x509_cert(
    trusted_root: Vec<u8>,
    cabundle: Vec<Vec<u8>>,
    certificate: Vec<u8>,
    unix_time: u64,
) -> Result<(), VerificationError> {
    let mut certs: Vec<Certificate> = Vec::new();
    for this_cert in cabundle.clone().iter().rev() {
        let cert = Certificate(this_cert.to_vec());
        certs.push(cert);
    }
    let cert = Certificate(certificate.clone());
    certs.push(cert.clone());

    let mut root_store = RootCertStore::empty();
    root_store
        .add(&Certificate(trusted_root.clone()))
        .map_err(|err| VerificationError::FailedToAddTrustedRootCert(err.to_string()))?;

    let verifier = AllowAnyAuthenticatedClient::new(root_store);

    info!("verifying client cert");

    //time is passed as parameter because now() fn doesn't work in wasm
    let duration = std::time::Duration::from_secs(unix_time);
    let datetime = std::time::UNIX_EPOCH + duration;
    let _verified = verifier
        .verify_client_cert(&cert, &certs, datetime)
        .map_err(|err| VerificationError::X509CertVerificationFailed(err.to_string()))?;
    Ok(())
}

fn verify_remote_attestation_signature(
    protected: Vec<u8>,
    signature: Vec<u8>,
    certificate: Vec<u8>,
    payload: Vec<u8>,
) -> Result<(), VerificationError> {
    let cert = x509_cert::Certificate::from_der(&certificate)
        .map_err(|err| VerificationError::DecodeX509CertFailed(err.to_string()))?;

    let public_key = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|err| VerificationError::PublicKeyDerFailed(err.to_string()))?;

    let public_key = &public_key[public_key.len() - 97..];
    let verifying_key = VerifyingKey::from_sec1_bytes(&public_key)
        .map_err(|err| VerificationError::InvalidPublicKey(err.to_string()))?;

    let signature = Signature::from_slice(&signature).expect("Invalid signature");

    const HEADER: [u8; 13] = [132, 106, 83, 105, 103, 110, 97, 116, 117, 114, 101, 49, 68];

    let payload_length_bytes: u8 = (payload.len() + 94 - 4446)
        .try_into()
        .map_err(|err| VerificationError::PayloadLengthBytesConversionFailed(err))?;

    let filler: [u8; 4] = [64, 89, 17, payload_length_bytes];

    let sign_structure = [
        HEADER.as_ref(),
        protected.as_ref(),
        filler.as_ref(),
        payload.as_ref(),
    ]
    .concat();

    verifying_key
        .verify(&sign_structure, &signature)
        .map_err(|err| VerificationError::SignatureVerificationFailed(err.to_string()))?;
    Ok(())
}

pub fn verify(
    attestation_document: AttestationDocument,
    payload: Payload,
    nonce: Vec<u8>,
    pcrs: Vec<Vec<u8>>,
    trusted_root: Option<Vec<u8>>,
    unix_time: u64,
) -> Result<(), VerificationError> {
    if payload.nonce != nonce {
        return Err(VerificationError::InvalidNonce);
    }

    for (i, pcr) in pcrs.iter().enumerate() {
        if pcr != &vec![0 as u8; 48] && pcr != &payload.pcrs[i] {
            return Err(VerificationError::InvalidPCR(i));
        }
    }

    let trusted_root = match trusted_root {
        Some(root) => root,
        None => STANDARD
            .decode(AWS_TRUSTED_ROOT_CERT)
            .map_err(|err| VerificationError::FailedToDecodeTrustedRoot(err))?,
    };
    verify_x509_cert(
        trusted_root,
        payload.cabundle,
        payload.certificate.clone(),
        unix_time,
    )
    .map_err(|err| VerificationError::X509CertVerificationFailed(err.to_string()))?;

    verify_remote_attestation_signature(
        attestation_document.protected,
        attestation_document.signature,
        payload.certificate,
        attestation_document.payload,
    )
    .map_err(|err| VerificationError::SignatureVerificationFailed(err.to_string()))?;

    Ok(())
}

pub fn parse_document(document_data: &Vec<u8>) -> Result<AttestationDocument, ParseError> {
    let cbor: serde_cbor::Value = serde_cbor::from_slice(document_data)
        .map_err(|err| ParseError::ParseDocumentFailed(err.to_string()))?;
    let elements = match cbor {
        serde_cbor::Value::Array(elements) => elements,
        _ => panic!("AttestationVerifier::parse Unknown field cbor:{:?}", cbor),
    };
    let protected = match &elements[0] {
        serde_cbor::Value::Bytes(prot) => prot,
        _ => panic!(
            "AttestationVerifier::parse Unknown field protected:{:?}",
            elements[0]
        ),
    };
    let _unprotected = match &elements[1] {
        serde_cbor::Value::Map(unprot) => unprot,
        _ => panic!(
            "AttestationVerifier::parse Unknown field unprotected:{:?}",
            elements[1]
        ),
    };
    let payload = match &elements[2] {
        serde_cbor::Value::Bytes(payld) => payld,
        _ => panic!(
            "AttestationVerifier::parse Unknown field payload:{:?}",
            elements[2]
        ),
    };
    let signature = match &elements[3] {
        serde_cbor::Value::Bytes(sig) => sig,
        _ => panic!(
            "AttestationVerifier::parse Unknown field signature:{:?}",
            elements[3]
        ),
    };
    Ok(AttestationDocument {
        protected: protected.to_vec(),
        payload: payload.to_vec(),
        signature: signature.to_vec(),
    })
}

pub fn parse_payload(payload: &Vec<u8>) -> Result<Payload, ParseError> {
    let document_data: serde_cbor::Value = serde_cbor::from_slice(payload.as_slice())
        .map_err(|err| ParseError::ParsePayloadFailed(err.to_string()))?;
    let document_map: BTreeMap<serde_cbor::Value, serde_cbor::Value> = match document_data {
        serde_cbor::Value::Map(map) => map,
        _ => {
            return Err(ParseError::ParsePayloadFailed(format!(
                "AttestationVerifier::parse_payload field ain't what it should be:{:?}",
                document_data
            )))
        }
    };
    let module_id = match document_map.get(&serde_cbor::Value::Text(
        "module_id".try_into().expect("module_id_fail"),
    )) {
        Some(serde_cbor::Value::Text(val)) => val.to_string(),
        _ => {
            return Err(ParseError::ParsePayloadFailed(format!(
                "AttestationVerifier::parse_payload module_id is wrong type or not present"
            )))
        }
    };
    let timestamp: i128 = match document_map.get(&serde_cbor::Value::Text("timestamp".to_string()))
    {
        Some(serde_cbor::Value::Integer(val)) => *val,
        _ => {
            return Err(ParseError::ParsePayloadFailed(format!(
                "AttestationVerifier::parse_payload timestamp is wrong type or not present"
            )))
        }
    };
    let timestamp: u64 = timestamp.try_into().map_err(|err| {
        ParseError::ParsePayloadFailed(format!(
            "AttestationVerifier::parse_payload failed to convert timestamp to u64:{:?}",
            err
        ))
    })?;
    let public_key: Vec<u8> =
        match document_map.get(&serde_cbor::Value::Text("public_key".to_string())) {
            Some(serde_cbor::Value::Bytes(val)) => val.to_vec(),
            Some(_null) => vec![],
            _ => {
                return Err(ParseError::ParsePayloadFailed(format!(
                    "AttestationVerifier::parse_payload public_key is wrong type or not present"
                )))
            }
        };
    let certificate: Vec<u8> =
        match document_map.get(&serde_cbor::Value::Text("certificate".to_string())) {
            Some(serde_cbor::Value::Bytes(val)) => val.to_vec(),
            _ => {
                return Err(ParseError::ParsePayloadFailed(format!(
                    "AttestationVerifier::parse_payload certificate is wrong type or not present"
                )))
            }
        };
    let pcrs: Vec<Vec<u8>> = match document_map.get(&serde_cbor::Value::Text("pcrs".to_string())) {
        Some(serde_cbor::Value::Map(map)) => {
            let mut ret_vec: Vec<Vec<u8>> = Vec::new();
            let num_entries: i128 = map.len().try_into().map_err(|err| {
                ParseError::ParsePayloadFailed(format!(
                    "AttestationVerifier::parse_payload failed to convert pcrs len into i128:{:?}",
                    err
                ))
            })?;
            for x in 0..num_entries {
                match map.get(&serde_cbor::Value::Integer(x)) {
                    Some(serde_cbor::Value::Bytes(inner_vec)) => {
                        ret_vec.push(inner_vec.to_vec());
                    }
                    _ => {
                        //println!("PCR: None value");
                        // return Err(ParseError::ParsePayloadFailed(format!(
                        //     "AttestationVerifier::parse_payload pcrs inner vec is wrong type or not there?"
                        // )));
                    }
                }
            }
            ret_vec
        }
        _ => {
            return Err(ParseError::ParsePayloadFailed(format!(
                "AttestationVerifier::parse_payload pcrs is wrong type or not present"
            )))
        }
    };

    // let nonce = match document_map.get(&serde_cbor::Value::Text("nonce".to_string())) {
    //     Some(serde_cbor::Value::Bytes(val)) => val.to_vec(),
    //     _ => {
    //         return Err(ParseError::ParsePayloadFailed(format!(
    //             "AttestationVerifier::parse_payload nonce is wrong type or not present"
    //         )))
    //     }
    // };
    // skip nonce for now
    let nonce = vec![0; 20];

    let user_data: Option<Vec<u8>> =
        match document_map.get(&serde_cbor::Value::Text("user_data".to_string())) {
            Some(serde_cbor::Value::Bytes(val)) => Some(val.to_vec()),
            None => None,
            Some(_null) => None,
        };
    let digest: String = match document_map.get(&serde_cbor::Value::Text("digest".to_string())) {
        Some(serde_cbor::Value::Text(val)) => val.to_string(),
        _ => {
            return Err(ParseError::ParsePayloadFailed(format!(
                "AttestationVerifier::parse_payload digest is wrong type or not present"
            )))
        }
    };
    let cabundle: Vec<Vec<u8>> =
        match document_map.get(&serde_cbor::Value::Text("cabundle".to_string())) {
            Some(serde_cbor::Value::Array(outer_vec)) => {
                let mut ret_vec: Vec<Vec<u8>> = Vec::new();
                for this_vec in outer_vec.iter() {
                    match this_vec {
                        serde_cbor::Value::Bytes(inner_vec) => {
                            ret_vec.push(inner_vec.to_vec());
                        }
                        _ => {
                            return Err(ParseError::ParsePayloadFailed(format!(
                                "AttestationVerifier::parse_payload inner_vec is wrong type"
                            )))
                        }
                    }
                }
                ret_vec
            }
            _ => {
                return Err(ParseError::ParsePayloadFailed(format!(
                    "AttestationVerifier::parse_payload cabundle is wrong type or not present:{:?}",
                    document_map.get(&serde_cbor::Value::Text("cabundle".to_string()))
                )))
            }
        };
    Ok(Payload {
        module_id,
        timestamp,
        public_key,
        certificate,
        cabundle,
        nonce,
        user_data,
        digest,
        pcrs,
    })
}

pub fn parse_verify_with(
    document_data: Vec<u8>,
    nonce: Vec<u8>,
    pcrs: Vec<Vec<u8>>,
    unix_time: u64,
) -> Result<(), ParseVerificationError> {
    let attestation_document =
        parse_document(&document_data).map_err(ParseVerificationError::ParseError)?;

    let payload =
        parse_payload(&attestation_document.payload).map_err(ParseVerificationError::ParseError)?;

    verify(attestation_document, payload, nonce, pcrs, None, unix_time)
        .map_err(ParseVerificationError::VerificationError)?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn verify_js(attestation_document: Vec<u8>, nonce: Vec<u8>, pcrs: js_sys::Array) -> bool {
    let pcrs: Vec<Vec<u8>> = pcrs
        .iter()
        .map(|item| js_sys::Uint8Array::new(&item).to_vec())
        .collect();
    let unix_time = std::time::UNIX_EPOCH.elapsed().unwrap().as_secs();
    let parsed_document = parse_document(&attestation_document).expect("parse document failed");

    let payload = parse_payload(&parsed_document.payload).expect("parse payload failed");

    let result = parse_verify_with(attestation_document, nonce, pcrs, unix_time)
        .map_err(|err: ParseVerificationError| JsValue::from_str(&err.to_string()));

    return result.is_ok();
}

#[cfg(test)]
mod tests {

    use super::*;
    use hex;
    #[test]
    fn test_verify() {
        let unix_time = std::time::UNIX_EPOCH.elapsed().unwrap().as_secs();
        //let unix_time = 1734662485;
        // use an older unix_time to test a expired cert
        // the cert below is probably expired by the time you run this test

        let document_data  = STANDARD.decode("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")
            .expect("decode cbor document failed");

        let mut pcrs = vec![vec![0; 48]; 16];
        pcrs.insert(
            2,
            vec![
                82, 109, 106, 26, 82, 112, 94, 220, 96, 33, 50, 18, 83, 138, 170, 165, 201, 23,
                162, 43, 73, 60, 232, 132, 234, 119, 172, 24, 1, 253, 90, 10, 150, 45, 136, 78,
                242, 58, 104, 123, 48, 108, 67, 123, 146, 152, 255, 65,
            ]
            .to_vec(),
        );
        let nonce =
            hex::decode("0000000000000000000000000000000000000000").expect("decode nonce failed");

        let document = parse_document(&document_data).expect("parse document failed");

        let payload = parse_payload(&document.payload).expect("parse payload failed");

        println!("pcrs {:?}", payload.pcrs);
        println!("nonce {:?}", nonce);

        match parse_verify_with(document_data, nonce, pcrs, unix_time) {
            Ok(_) => (),
            Err(e) => panic!("parse_verify_with failed: {:?}", e.to_string()),
        }
    }
}
