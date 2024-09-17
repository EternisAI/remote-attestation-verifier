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

pub fn verify(
    attestation_document: AttestationDocument,
    payload: Payload,
) -> Result<(), p384::ecdsa::Error> {
    //OK: parse public key, convert from der to sec1 format
    let cert =
        x509_cert::Certificate::from_der(&payload.certificate).expect("decode x509 cert failed");

    //////////////////////////////////////////////////////////////////////////////
    //1. verify x509 cert signature using x509_cert crate

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
        let document_data  = STANDARD.decode("hEShATgioFkRX6lpbW9kdWxlX2lkeCdpLTBiYmYxYmZlMjMyYjhjMmNlLWVuYzAxOTFiYTM1YzlkMWI3N2FmZGlnZXN0ZlNIQTM4NGl0aW1lc3RhbXAbAAABkd0e8/pkcGNyc7AAWDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABWDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACWDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADWDBnHKHjKPdQFbKu7mBjnMUlK8g12LtpBETR+OK/QmD3PcG3HgehSncMfQvsrG6ztT8EWDDTUs+jG43F9IVsn6gYGxntEvXaI4g6xOxylTD1DcHTfxrDh2p685vU3noq6tFNFMsFWDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGWDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHWDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIWDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJWDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKWDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALWDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMWDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANWDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOWDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPWDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABrY2VydGlmaWNhdGVZAoAwggJ8MIICAaADAgECAhABkbo1ydG3egAAAABm4Ir+MAoGCCqGSM49BAMDMIGOMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjEQMA4GA1UEBwwHU2VhdHRsZTEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQLDANBV1MxOTA3BgNVBAMMMGktMGJiZjFiZmUyMzJiOGMyY2UudXMtZWFzdC0xLmF3cy5uaXRyby1lbmNsYXZlczAeFw0yNDA5MTAxODA3NTVaFw0yNDA5MTAyMTA3NThaMIGTMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjEQMA4GA1UEBwwHU2VhdHRsZTEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQLDANBV1MxPjA8BgNVBAMMNWktMGJiZjFiZmUyMzJiOGMyY2UtZW5jMDE5MWJhMzVjOWQxYjc3YS51cy1lYXN0LTEuYXdzMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAErm5mYod9az3WK4jtxnd03ik74rLx30Y0TxEkjnJwsNj4U9Eh84lIg6uieQZvH/GRVuqCuN/VHhGcW659t0R4uxt9+RhpfHr6xMg9/wvQKsDKYzYa7Ag3N2gXMR/HX64uox0wGzAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIGwDAKBggqhkjOPQQDAwNpADBmAjEAlvGr/lVjTL81pguhFloO2ngUWPIrIFrk+61+bQVJ2RUWbZVXR29NRGhLZxqSX4e2AjEA+f9AkwwmF3cWGp0t6J9q2tXt8yCyO2SJ58B1OvVI7XvuJT6K/T0q21JzW9EhPAwlaGNhYnVuZGxlhFkCFTCCAhEwggGWoAMCAQICEQD5MXVoG5Cv4R1GzLTk5/hWMAoGCCqGSM49BAMDMEkxCzAJBgNVBAYTAlVTMQ8wDQYDVQQKDAZBbWF6b24xDDAKBgNVBAsMA0FXUzEbMBkGA1UEAwwSYXdzLm5pdHJvLWVuY2xhdmVzMB4XDTE5MTAyODEzMjgwNVoXDTQ5MTAyODE0MjgwNVowSTELMAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYDVQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT8AlTrpgjB82hw4prakL5GODKSc26JS//2ctmJREtQUeU0pLH22+PAvFgaMrexdgcO3hLWmj/qIRtm51LPfdHdCV9vE3D0FwhD2dwQASHkz2MBKAlmRIfJeWKEME3FP/SjQjBAMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFJAltQ3ZBUfnlsOW+nKdz5mp30uWMA4GA1UdDwEB/wQEAwIBhjAKBggqhkjOPQQDAwNpADBmAjEAo38vkaHJvV7nuGJ8FpjSVQOOHwND+VtjqWKMPTmAlUWhHry/LjtV2K7ucbTD1q3zAjEAovObFgWycCil3UugabUBbmW0+96P4AYdalMZf5za9dlDvGH8K+sDy2/ujSMC89/2WQLDMIICvzCCAkWgAwIBAgIRAI7tUjZDlXKmHJ90xf/MdEwwCgYIKoZIzj0EAwMwSTELMAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYDVQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMjQwOTA5MTQwNzQ1WhcNMjQwOTI5MTUwNzQ1WjBkMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQLDANBV1MxNjA0BgNVBAMMLWFjMWNkMTRlNDBkNWNmMTAudXMtZWFzdC0xLmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEGBSuBBAAiA2IABGK11923vnqPvql138TWXc3VAhK7DyPoLiLG6VDEYP/gfFHjjq44rRBwMP9L5n0GLaBvqCIfTE/kHDnDXjhRIvHT2NKrefKk+TAtI3Our1W32R/dvy2kUHFDBR2ptr8vmqOB1TCB0jASBgNVHRMBAf8ECDAGAQH/AgECMB8GA1UdIwQYMBaAFJAltQ3ZBUfnlsOW+nKdz5mp30uWMB0GA1UdDgQWBBS/s3ZJAkfOU7ivmQ/rQgfEFb7HHDAOBgNVHQ8BAf8EBAMCAYYwbAYDVR0fBGUwYzBhoF+gXYZbaHR0cDovL2F3cy1uaXRyby1lbmNsYXZlcy1jcmwuczMuYW1hem9uYXdzLmNvbS9jcmwvYWI0OTYwY2MtN2Q2My00MmJkLTllOWYtNTkzMzhjYjY3Zjg0LmNybDAKBggqhkjOPQQDAwNoADBlAjEArYIRiGqTiZkEwVTu0MR/tWPazowzWD+2PWsiSEgxBJkwjEKYRurUMhO8de6fo5awAjBI4HmpzB2RY21USfuDLfu9rpGiJ1Tn1QqspscK6Tx6pxIi0rH7t+tfMelw8t0gFUVZAxgwggMUMIICmqADAgECAhAtUo6ENzMywFf1+n2yXKtlMAoGCCqGSM49BAMDMGQxCzAJBgNVBAYTAlVTMQ8wDQYDVQQKDAZBbWF6b24xDDAKBgNVBAsMA0FXUzE2MDQGA1UEAwwtYWMxY2QxNGU0MGQ1Y2YxMC51cy1lYXN0LTEuYXdzLm5pdHJvLWVuY2xhdmVzMB4XDTI0MDkxMDEyMzc0NloXDTI0MDkxNjA1Mzc0NVowgYkxPDA6BgNVBAMMM2IyZjg2MGQ4ZTJhMGQ3NjEuem9uYWwudXMtZWFzdC0xLmF3cy5uaXRyby1lbmNsYXZlczEMMAoGA1UECwwDQVdTMQ8wDQYDVQQKDAZBbWF6b24xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJXQTEQMA4GA1UEBwwHU2VhdHRsZTB2MBAGByqGSM49AgEGBSuBBAAiA2IABF4MOi6Jcw4TnMrdhD+fCaIq3WVae9BEDzc2eyUjCaE/wJUR6QaWpVZMf7KyoyRrOo+uaPV81pMYHmrE8MLOeJVlpiay6DsIctsDeYuOaTdnVvhZWqaPH7wtKSImwsL0i6OB6jCB5zASBgNVHRMBAf8ECDAGAQH/AgEBMB8GA1UdIwQYMBaAFL+zdkkCR85TuK+ZD+tCB8QVvsccMB0GA1UdDgQWBBSn5T5LzAyoQxZAjL9jMu5t1WMKQzAOBgNVHQ8BAf8EBAMCAYYwgYAGA1UdHwR5MHcwdaBzoHGGb2h0dHA6Ly9jcmwtdXMtZWFzdC0xLWF3cy1uaXRyby1lbmNsYXZlcy5zMy51cy1lYXN0LTEuYW1hem9uYXdzLmNvbS9jcmwvMDNjN2MxOWYtYTdiNC00MjgxLWI3NDQtZDkwMDk1ODhjMjQyLmNybDAKBggqhkjOPQQDAwNoADBlAjEAt/32FWeX550OwJOYwoZroBalw+KSDszqcqtq1IchMMbyH2zIH0TKlyi9jWOwWLbEAjABagGFFowL0yd1M8Yn8PLN4E68rq/LPJgQrTAl7xRGOI2CTBodCgC9uyxqRm76gjhZAsMwggK/MIICRaADAgECAhUA35riCCRBqe+CqsGESdAvBeLYHukwCgYIKoZIzj0EAwMwgYkxPDA6BgNVBAMMM2IyZjg2MGQ4ZTJhMGQ3NjEuem9uYWwudXMtZWFzdC0xLmF3cy5uaXRyby1lbmNsYXZlczEMMAoGA1UECwwDQVdTMQ8wDQYDVQQKDAZBbWF6b24xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJXQTEQMA4GA1UEBwwHU2VhdHRsZTAeFw0yNDA5MTAxNDIzNDdaFw0yNDA5MTExNDIzNDdaMIGOMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjEQMA4GA1UEBwwHU2VhdHRsZTEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQLDANBV1MxOTA3BgNVBAMMMGktMGJiZjFiZmUyMzJiOGMyY2UudXMtZWFzdC0xLmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEGBSuBBAAiA2IABF7SGcHdkRbzl/tGMXHBgJ88sy+HTekW+lomScVSEXYB1giAC6eQgElex/q78JTxuj/k7BV83GfjKE5BS5Bdlohfb3b/yA52MLQubQGAYLSZhBGZmRBaEleTF6r0381CgqNmMGQwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAgQwHQYDVR0OBBYEFBvZFAgI1uf1KLtxVdsv0Zeh+HFMMB8GA1UdIwQYMBaAFKflPkvMDKhDFkCMv2My7m3VYwpDMAoGCCqGSM49BAMDA2gAMGUCMQCf5mKZqKqPaLaWDe+hDo2emzI30WceoUS14oCOEN8/2jC+SZRBsrtK5k0cImJW/XgCMAPdVK65k6kDVt0UKgKajx1VvAcWXU5D2SGPixIakwq6INs8B2J/6j4T3QKqKSE1PGpwdWJsaWNfa2V5RWR1bW15aXVzZXJfZGF0YVhEEiDGgrxsgUpnSPSQyMjkjlxAxQXlyZsLYXuFzccdI28qOBIgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABlbm9uY2VUAAAAAAAAAAAAAAAAAAAAAAAAAAFYYFAnFgZYOo8zcp/vvncWNgX0YtN4QiLgJWO92mDLVSn2d03NQCzGVttdhZErLlb9tgyneA7757nss6E7d8C5Rvvy5hQ5jefDTH1Czu8LGLnNzYXkzS152/28nNyW3cd3/g==")
            .expect("decode cbor document failed");

        let attestation_document =
            parse_document(&document_data).expect("parse cbor document failed");

        let payload = parse_payload(&attestation_document.payload).expect("parse payload failed");
        verify(attestation_document, payload).expect("remote attestation verification failed");
    }
}
