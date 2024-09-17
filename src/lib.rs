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

#[derive(Debug)]
pub struct Payload {
    pub module_id: String,
    pub timestamp: u64,
    pub public_key: Option<Vec<u8>>,
    pub certificate: Vec<u8>,
    pub cabundle: Vec<Vec<u8>>,
}

use rustls_pemfile::{certs, pkcs8_private_keys};
use std::io::BufReader;
pub fn verify(
    attestation_document: AttestationDocument,
    payload: Payload,
) -> Result<(), p384::ecdsa::Error> {
    //OK: parse public key, convert from der to sec1 format

    //////////////////////////////////////////////////////////////////////////////
    //1. verify x509 cert signature using x509_cert crate
    //verify cabundle x509 certificate
    let mut certs: Vec<rustls::Certificate> = Vec::new();
    for this_cert in payload.cabundle.clone().iter().rev() {
        let cert = rustls::Certificate(this_cert.to_vec());
        certs.push(cert);
    }
    let cert = rustls::Certificate(payload.certificate.clone());
    certs.push(cert);

    let mut root_store = rustls::RootCertStore::empty();
    root_store
        .add(&rustls::Certificate(payload.certificate.clone()))
        .map_err(|err| {
            format!(
                "AttestationVerifier::authenticate failed to add trusted root cert:{:?}",
                err
            )
        })
        .expect("failed to add trusted root cert");

    let verifier = rustls::server::AllowAnyAuthenticatedClient::new(root_store);
    let _verified = verifier
        .verify_client_cert(
            &rustls::Certificate(payload.certificate.clone()),
            &certs,
            std::time::SystemTime::now(),
        )
        .map_err(|err| {
            format!(
                "AttestationVerifier::authenticate verify_client_cert failed:{:?}",
                err
            )
        })
        .expect("failed to verify client cert");

    //////////////////////////////////////////////////////////////////////////////
    //TEST:
    let cert =
        x509_cert::Certificate::from_der(&payload.certificate).expect("decode x509 cert failed");

    let issuer_cert =
        x509_cert::Certificate::from_der(&payload.cabundle[3]).expect("decode x509 cert failed");

    println!(
        "issuer subject {:?} \nissuer: {:?} ",
        issuer_cert.tbs_certificate.subject.to_string(),
        issuer_cert.tbs_certificate.issuer.to_string()
    );
    println!(
        "cert subject {:?} \n cert issuer {:?}",
        cert.tbs_certificate.subject.to_string(),
        cert.tbs_certificate.issuer.to_string()
    );

    let issuer_public_key = issuer_cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .expect("issuer public key der failed");

    let issuer_public_key = &issuer_public_key[issuer_public_key.len() - 97..];
    let issuer_public_key =
        VerifyingKey::from_sec1_bytes(&issuer_public_key).expect("Invalid public key");

    //println!("issuer public key sec1 {:?}", issuer_public_key);
    //TODO: should be issuer sig & issuer sig_structure
    let x509_signature = cert.signature.raw_bytes();

    //@ok remove DER header, rest is the same as openssl
    let x509_signature: [u8; 96] = x509_signature[cert.signature.raw_bytes().len() - 96..]
        .try_into()
        .expect("x509 signature doesn't have enough bytes");

    //println!("x509 signature DER {:?}", cert.signature.to_der());

    let x509_signature = Signature::from_slice(&x509_signature).expect("Invalid x509 signature");

    //NOTE: certificate is in DER format
    let mut sig_structure_x509 = vec![];
    cert.tbs_certificate
        .encode_to_vec(&mut sig_structure_x509)
        .expect("cert to der failed");
    //println!("sig_structure_x509: {:?}", sig_structure_x509);

    // let mut sig_structure_x509_with_prefix = vec![48, 130, 2, 123];
    // sig_structure_x509_with_prefix.extend_from_slice(&sig_structure_x509);
    // let sig_structure_x509 = sig_structure_x509_with_prefix;

    //BUG:  verify fails here, one of 3 values must be wrong
    // issuer_public_key
    //     .verify(&sig_structure_x509, &x509_signature)
    //     .expect("verify x509 cert failed");

    //////////////////////////////////////////////////////////////////////////////
    /////TEST: using OPENSSL to see if we get the same parameters

    ///// get signature & sig_structure from cert
    // println!("---------------------------------------\n using openssl");
    // let x509_cert =
    //     openssl::x509::X509::from_der(_certificate).expect("Failed to parse certificate");

    //println!("subject: {:?}", x509_cert.subject_name());
    //println!("issuer: {:?}", x509_cert.issuer_name());

    // let tbs_cert = x509_cert
    //     .to_der()
    //     .expect("Failed to get TBS certificate raw bytes");

    // let pub_key = x509_cert.public_key().expect("Failed to get public key");
    // //println!("subject public key: {:?}", pub_key);
    // println!("x509 signature: {:?}", x509_cert.signature().as_slice());
    // println!("sig_structure_x509: {:?}", tbs_cert);

    // ///// get public key from issuer_cert
    // let issuer_cert =
    //     openssl::x509::X509::from_der(&issuer_der).expect("Failed to parse issuer PEM");

    // use base64::encode;

    //////////////////////////////////////////////////////////////////////////////
    //OK: 2.verify remote attestation document signature
    //this public key is different than the one that signed the x509
    //note:sec1 doesnt comprise der headers
    let public_key = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .expect("public key der failed");

    let public_key = &public_key[public_key.len() - 97..];
    //println!("cert public key {:?}", public_key);

    //OK: public key valid
    let verifying_key = VerifyingKey::from_sec1_bytes(&public_key).expect("Invalid public key");

    // Create a Signature object from the raw signature bytes
    let signature =
        Signature::from_slice(&attestation_document.signature).expect("Invalid signature");

    //OK: construct cosign structure
    const HEADER: [u8; 13] = [132, 106, 83, 105, 103, 110, 97, 116, 117, 114, 101, 49, 68];
    let protected = attestation_document.protected;

    let payload_length_bytes: u8 = (attestation_document.payload.len() - 4446 + 94)
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

    //println!("sign_structure: {:?}", sign_structure);
    //println!("pcrs: {:?}", document.pcrs);
    //OK:
    // Verify the signature
    verifying_key.verify(&sign_structure, &signature)
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
    let public_key: Option<Vec<u8>> =
        match document_map.get(&serde_cbor::Value::Text("public_key".to_string())) {
            Some(serde_cbor::Value::Bytes(val)) => Some(val.to_vec()),
            Some(_null) => None,
            None => None,
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
    let nonce: Option<Vec<u8>> =
        match document_map.get(&serde_cbor::Value::Text("nonce".to_string())) {
            Some(serde_cbor::Value::Bytes(val)) => Some(val.to_vec()),
            None => None,
            _ => {
                return Err(format!(
                    "AttestationVerifier::parse_payload nonce is wrong type or not present"
                ))
            }
        };
    println!("nonce:{:?}", nonce);
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
        module_id: module_id,
        timestamp: timestamp,
        public_key: public_key,
        certificate: certificate,
        cabundle: cabundle,
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

    #[test]
    fn test_verify() {
        //parsing cbor without std functions
        let document_data  = STANDARD.decode("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")
            .expect("decode cbor document failed");

        let attestation_document =
            parse_document(&document_data).expect("parse cbor document failed");

        let payload = parse_payload(&attestation_document.payload).expect("parse payload failed");
        verify(attestation_document, payload).expect("remote attestation verification failed");
    }
}
