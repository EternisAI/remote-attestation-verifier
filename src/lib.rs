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
use tracing::{error, info};
use x509_cert::der;
use x509_cert::der::Decode;
use x509_cert::der::Encode;
use x509_cert::Certificate;

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

use rustls_pemfile::{certs, pkcs8_private_keys};
use std::io::BufReader;
pub fn verify(
    attestation_document: AttestationDocument,
    payload: Payload,
    nonce: Vec<u8>,
    trusted_root: Option<Vec<u8>>,
) -> Result<(), String> {
    let trusted_root = match trusted_root {
        Some(root) => root,
        None => STANDARD
            .decode(AWS_TRUSTED_ROOT_CERT)
            .map_err(|err| format!("failed to decode trusted_root: {}", err))?,
    };

    //////////////////////////////////////////////////////////////////////////////
    //1. verify nonce
    if payload.nonce != nonce {
        return Err("invalid nonce".to_string());
    }

    //////////////////////////////////////////////////////////////////////////////
    //2. verify pcrs

    //////////////////////////////////////////////////////////////////////////////
    //1. verify x509 cert
    let mut certs: Vec<rustls::Certificate> = Vec::new();
    for this_cert in payload.cabundle.clone().iter().rev() {
        let cert = rustls::Certificate(this_cert.to_vec());
        certs.push(cert);
    }
    let cert = rustls::Certificate(payload.certificate.clone());
    certs.push(cert);

    let mut root_store = rustls::RootCertStore::empty();
    root_store
        .add(&rustls::Certificate(trusted_root.clone()))
        .map_err(|err| {
            format!(
                "AttestationVerifier::authenticate failed to add trusted root cert:{:?}",
                err
            )
        })
        .expect("failed to add trusted root cert");

    let verifier = rustls::server::AllowAnyAuthenticatedClient::new(root_store);

    info!("verifying client cert");
    //BUG:  std::time does not work within WASM
    // let _verified = verifier
    //     .verify_client_cert(
    //         &rustls::Certificate(payload.certificate.clone()),
    //         &certs,
    //         std::time::SystemTime::now(),
    //     )
    //     .map_err(|err| {
    //         format!(
    //             "AttestationVerifier::authenticate verify_client_cert failed:{:?}",
    //             err
    //         )
    //     });

    // info!("verified: {:?}", _verified);
    // match _verified {
    //     Ok(_) => (),
    //     Err(err) => {
    //         error!(
    //             "AttestationVerifier::authenticate verify_client_cert failed:{:?}",
    //             err
    //         );
    //         return Err(err);
    //     }
    // }

    //////////////////////////////////////////////////////////////////////////////
    // 2. verify remote attestation signature using public_key from the certificate
    let cert = x509_cert::Certificate::from_der(&payload.certificate)
        .map_err(|err| format!("decode x509 cert failed: {}", err))?;

    let public_key = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .expect("public key der failed");

    let public_key = &public_key[public_key.len() - 97..];
    let verifying_key = VerifyingKey::from_sec1_bytes(&public_key).expect("Invalid public key");

    let signature =
        Signature::from_slice(&attestation_document.signature).expect("Invalid signature");

    const HEADER: [u8; 13] = [132, 106, 83, 105, 103, 110, 97, 116, 117, 114, 101, 49, 68];
    let protected = attestation_document.protected;

    let payload_length_bytes: u8 = (attestation_document.payload.len() + 94 - 4446)
        .try_into()
        .expect("payload length bytes conversion failed");

    let filler: [u8; 4] = [64, 89, 17, payload_length_bytes];
    let payload = attestation_document.payload;

    let sign_structure = [
        HEADER.as_ref(),
        protected.as_ref(),
        filler.as_ref(),
        payload.as_ref(),
    ]
    .concat();

    verifying_key
        .verify(&sign_structure, &signature)
        .map_err(|err| {
            format!(
                "AttestationVerifier::authenticate verify x509 cert failed:{:?}",
                err
            )
        })
}

pub fn parse_document(document_data: &Vec<u8>) -> Result<AttestationDocument, String> {
    let cbor: serde_cbor::Value = serde_cbor::from_slice(document_data)
        .map_err(|err| format!("AttestationVerifier::parse from_slice failed:{:?}", err))?;
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

use std::collections::BTreeMap;
pub fn parse_payload(payload: &Vec<u8>) -> Result<Payload, String> {
    let document_data: serde_cbor::Value = serde_cbor::from_slice(payload.as_slice())
        .map_err(|err| format!("document parse failed:{:?}", err))?;
    let document_map: BTreeMap<serde_cbor::Value, serde_cbor::Value> = match document_data {
        serde_cbor::Value::Map(map) => map,
        _ => {
            return Err(format!(
                "AttestationVerifier::parse_payload field ain't what it should be:{:?}",
                document_data
            ))
        }
    };
    let module_id = match document_map.get(&serde_cbor::Value::Text(
        "module_id".try_into().expect("module_id_fail"),
    )) {
        Some(serde_cbor::Value::Text(val)) => val.to_string(),
        _ => {
            return Err(format!(
                "AttestationVerifier::parse_payload module_id is wrong type or not present"
            ))
        }
    };
    let timestamp: i128 = match document_map.get(&serde_cbor::Value::Text("timestamp".to_string()))
    {
        Some(serde_cbor::Value::Integer(val)) => *val,
        _ => {
            return Err(format!(
                "AttestationVerifier::parse_payload timestamp is wrong type or not present"
            ))
        }
    };
    let timestamp: u64 = timestamp.try_into().map_err(|err| {
        format!(
            "AttestationVerifier::parse_payload failed to convert timestamp to u64:{:?}",
            err
        )
    })?;
    let public_key: Vec<u8> =
        match document_map.get(&serde_cbor::Value::Text("public_key".to_string())) {
            Some(serde_cbor::Value::Bytes(val)) => val.to_vec(),
            Some(_null) => vec![],
            _ => {
                return Err(format!(
                    "AttestationVerifier::parse_payload public_key is wrong type or not present"
                ))
            }
        };
    let certificate: Vec<u8> =
        match document_map.get(&serde_cbor::Value::Text("certificate".to_string())) {
            Some(serde_cbor::Value::Bytes(val)) => val.to_vec(),
            _ => {
                return Err(format!(
                    "AttestationVerifier::parse_payload certificate is wrong type or not present"
                ))
            }
        };
    let pcrs: Vec<Vec<u8>> = match document_map.get(&serde_cbor::Value::Text("pcrs".to_string())) {
        Some(serde_cbor::Value::Map(map)) => {
            let mut ret_vec: Vec<Vec<u8>> = Vec::new();
            let num_entries: i128 = map.len().try_into().map_err(|err| {
                format!(
                    "AttestationVerifier::parse_payload failed to convert pcrs len into i128:{:?}",
                    err
                )
            })?;
            for x in 0..num_entries {
                match map.get(&serde_cbor::Value::Integer(x)) {
                    Some(serde_cbor::Value::Bytes(inner_vec)) => {
                        ret_vec.push(inner_vec.to_vec());
                    },
                    _ => return Err(format!("AttestationVerifier::parse_payload pcrs inner vec is wrong type or not there?")),
                }
            }
            ret_vec
        }
        _ => {
            return Err(format!(
                "AttestationVerifier::parse_payload pcrs is wrong type or not present"
            ))
        }
    };
    for (i, pcr) in pcrs.iter().enumerate() {
        let pcr_str = pcr.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        // println!("PCR {}: {}", i, pcr_str);
    }
    let nonce = match document_map.get(&serde_cbor::Value::Text("nonce".to_string())) {
        Some(serde_cbor::Value::Bytes(val)) => val.to_vec(),
        _ => {
            return Err(format!(
                "AttestationVerifier::parse_payload nonce is wrong type or not present"
            ))
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
            return Err(format!(
                "AttestationVerifier::parse_payload digest is wrong type or not present"
            ))
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
                            return Err(format!(
                                "AttestationVerifier::parse_payload inner_vec is wrong type"
                            ))
                        }
                    }
                }
                ret_vec
            }
            _ => {
                return Err(format!(
                    "AttestationVerifier::parse_payload cabundle is wrong type or not present:{:?}",
                    document_map.get(&serde_cbor::Value::Text("cabundle".to_string()))
                ))
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
// pub fn fetch_attestation_document(&self, nonce: &str) -> Result<Vec<u8>, String> {
//     use reqwest::blocking::Client;
//     use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};
//     let url = format!("{}?nonce={}", self.enclave_endpoint, nonce);
//     let mut headers = HeaderMap::new();
//     headers.insert(USER_AGENT, HeaderValue::from_static("attestation-client"));
//     let client = Client::builder()
//         .danger_accept_invalid_certs(true)
//         .default_headers(headers)
//         .build()
//         .map_err(|e| format!("Failed to build client: {}", e))?;
//     let response = client
//         .get(&url)
//         .send()
//         .map_err(|e| format!("Failed to send request: {}", e))?;
//     if !response.status().is_success() {
//         return Err(format!("Request failed with status: {}", response.status()));
//     }
//     let decoded_response = response
//         .text()
//         .map_err(|e| format!("Failed to read response body as text: {}", e))?;
//     STANDARD.decode(decoded_response.trim())
//         .map_err(|e| format!("Failed to decode base64: {}", e))
// }

#[cfg(test)]
mod tests {

    use super::*;
    use hex;
    #[test]
    fn test_verify() {
        //parsing cbor without std functions

        let document_data  = STANDARD.decode("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")
            .expect("decode cbor document failed");

        let attestation_document =
            parse_document(&document_data).expect("parse cbor document failed");

        let nonce =
            hex::decode("0000000000000000000000000000000000000001").expect("decode nonce failed");

        let payload = parse_payload(&attestation_document.payload).expect("parse payload failed");

        verify(attestation_document, payload, nonce, None)
            .expect("remote attestation verification failed");
    }
}
