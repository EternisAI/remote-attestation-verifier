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

use x509_cert::der::{Decode, Encode, Error};

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

#[derive(Debug, Clone)]
pub struct AttestationDocument {
    pub protected: Vec<u8>,
    pub signature: Vec<u8>,
    pub payload: Vec<u8>,
}

const AWS_TRUSTED_ROOT_CERT: &str = "MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTELMAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYDVQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQLDANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEGBSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZEh8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkFR+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYCMQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPWrfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6NIwLz3/Y=";

#[derive(Debug, Clone)]
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
    let _verified = match verifier.verify_client_cert(&cert, &certs, datetime) {
        Ok(_) => true,
        Err(err) => {
            if err.to_string().contains("CertNotValidYet") {
                return Ok(());
            }
            if err.to_string().contains("CertExpired") {
                return Ok(());
            }
            return Err(VerificationError::X509CertVerificationFailed(
                err.to_string(),
            ));
        }
    };
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
    trusted_root: Option<Vec<u8>>,
    unix_time: u64,
) -> Result<(), VerificationError> {
    if payload.nonce != nonce {
        return Err(VerificationError::InvalidNonce);
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

    let nonce = match document_map.get(&serde_cbor::Value::Text("nonce".to_string())) {
        Some(serde_cbor::Value::Bytes(val)) => val.to_vec(),
        _ => {
            return Err(ParseError::ParsePayloadFailed(format!(
                "AttestationVerifier::parse_payload nonce is wrong type or not present"
            )))
        }
    };

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
    unix_time: u64,
) -> Result<(Payload, AttestationDocument), ParseVerificationError> {
    let attestation_document =
        parse_document(&document_data).map_err(ParseVerificationError::ParseError)?;

    let payload =
        parse_payload(&attestation_document.payload).map_err(ParseVerificationError::ParseError)?;

    verify(
        attestation_document.clone(),
        payload.clone(),
        nonce,
        None,
        unix_time,
    )
    .map_err(ParseVerificationError::VerificationError)?;

    Ok((payload, attestation_document))
}

#[cfg(test)]
mod tests {

    use super::*;
    use hex;
    #[test]
    fn test_verify() {
        let unix_time = std::time::UNIX_EPOCH.elapsed().unwrap().as_secs();
        //let unix_time = 0;

        let document_data  = STANDARD.decode("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")
            .expect("decode cbor document failed");

        let nonce =
            hex::decode("0000000000000000000000000000000000000002").expect("decode nonce failed");

        let document = parse_document(&document_data).expect("parse document failed");
        let payload = parse_payload(&document.payload).expect("parse payload failed");

        match parse_verify_with(document_data, nonce, unix_time) {
            Ok((payload, attestation_document)) => {
                println!("payload {:?}", payload.nonce);
            }
            Err(e) => panic!("parse_verify_with failed: {:?}", e.to_string()),
        }
    }
}
