//! AWS Nitro Enclave Document material
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the repo for
//! information on licensing and copyright.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use rustls_pemfile::Item;
use std::collections::BTreeMap;
use std::convert::TryInto;
use std::fmt::Write;
use std::time::SystemTime;

pub const DEFAULT_ENCLAVE_ENDPOINT: &str = "https://tlsn.eternis.ai/enclave/attestation";
pub const AWS_ROOT_CERT_PEM: &str = include_str!("aws_root.pem");
// The AWS Nitro Attestation Document.
// This is described in
// https://docs.aws.amazon.com/ko_kr/enclaves/latest/user/verify-root.html
// under the heading "Attestation document specification"
#[derive(Debug)]
pub struct AttestationDocument {
    pub module_id: String,
    pub timestamp: u64,
    pub digest: String,
    pub pcrs: Vec<Vec<u8>>,
    pub certificate: Vec<u8>,
    pub cabundle: Vec<Vec<u8>>,
    pub public_key: Option<Vec<u8>>,
    pub user_data: Option<Vec<u8>>,
    pub nonce: Option<Vec<u8>>,
}

pub struct CoseSign1Envelope {
    pub protected: Vec<u8>,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}

pub struct AttestationVerifier {
    trusted_root_cert: Vec<u8>,
}

impl AttestationVerifier {
    pub fn new(trusted_root_cert: Vec<u8>) -> Self {
        Self { trusted_root_cert }
    }

    pub fn from_pem(trusted_root_cert: &str) -> Result<Self, String> {
        let cert = rustls_pemfile::read_one_from_slice(trusted_root_cert.as_bytes());
        let cert = cert
            .map_err(|e| format!("couldn't parse PEM input: {:?}", e))?
            .ok_or("no items in PEM input".to_string())?
            .0;

        if let Item::X509Certificate(der) = cert {
            Ok(AttestationVerifier::new(der.to_vec()))
        } else {
            Err("no certificate in PEM input".to_string())
        }
    }

    /// Fetches the attestation document from the enclave endpoint.
    ///
    /// # Arguments
    ///
    /// * `nonce` - A string slice that holds the nonce value.
    ///
    /// # Returns
    ///
    /// * `Result<Vec<u8>, String>` - A result containing the attestation document as a vector of bytes on success, or an error message on failure.
    pub fn authenticate(
        &self,
        document_data: &[u8],
        time: SystemTime,
    ) -> Result<AttestationDocument, String> {
        let root_cert = self.trusted_root_cert.clone();

        // Following the steps here: https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
        // Step 1. Decode the CBOR object and map it to a COSE_Sign1 structure
        let envelope = AttestationVerifier::parse(document_data)
            .map_err(|err| format!("AttestationVerifier::authenticate parse failed:{:?}", err))?;
        let payload = envelope.payload;
        // Step 2. Exract the attestation document from the COSE_Sign1 structure
        let document = AttestationVerifier::parse_payload(&payload)
            .map_err(|err| format!("AttestationVerifier::authenticate failed:{:?}", err))?;

        // Step 3. Verify the certificate's chain
        let mut certs: Vec<rustls::Certificate> = Vec::new();
        for this_cert in document.cabundle.clone().iter().rev() {
            let cert = rustls::Certificate(this_cert.to_vec());
            certs.push(cert);
        }
        let cert = rustls::Certificate(document.certificate.clone());
        certs.push(cert);

        let mut root_store = rustls::RootCertStore::empty();
        root_store
            .add(&rustls::Certificate(root_cert))
            .map_err(|err| {
                format!(
                    "AttestationVerifier::authenticate failed to add trusted root cert:{:?}",
                    err
                )
            })?;

        let verifier = rustls::server::AllowAnyAuthenticatedClient::new(root_store);
        let _verified = verifier
            .verify_client_cert(
                &rustls::Certificate(document.certificate.clone()),
                &certs,
                time,
            )
            .map_err(|err| {
                format!(
                    "AttestationVerifier::authenticate verify_client_cert failed:{:?}",
                    err
                )
            })?;
        // if verify_client_cert didn't generate an error, authentication passed

        // Step 4. Ensure the attestation document is properly signed
        let authenticated = {
            let sig_structure = aws_nitro_enclaves_cose::CoseSign1::from_bytes(document_data)
                .map_err(|err| {
                    format!("AttestationVerifier::authenticate failed to load document_data as COSESign1 structure:{:?}", err)
                })?;
            let cert = openssl::x509::X509::from_der(&document.certificate)
                .map_err(|err| {
                    format!("AttestationVerifier::authenticate failed to parse document.certificate as X509 certificate:{:?}", err)
                })?;
            let public_key = cert.public_key()
                .map_err(|err| {
                    format!("AttestationVerifier::authenticate failed to extract public key from certificate:{:?}", err)
                })?;
            let _pub_ec_key = public_key.ec_key().map_err(|err| {
                format!(
                    "AttestationVerifier::authenticate failed to get ec_key from public_key:{:?}",
                    err
                )
            })?;
            sig_structure.verify_signature::<aws_nitro_enclaves_cose::crypto::Openssl>(&public_key)
                .map_err(|err| {
                    format!("AttestationVerifier::authenticate failed to verify signature on sig_structure:{:?}", err)
                })?
        };
        if !authenticated {
            Err(
                "AttestationVerifier::authenticate invalid COSE certificate for provided key"
                    .to_string(),
            )
        } else {
            Ok(document)
        }
    }

    fn parse(document_data: &[u8]) -> Result<CoseSign1Envelope, String> {
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
        }
        .to_vec();
        let _unprotected = match &elements[1] {
            serde_cbor::Value::Map(unprot) => unprot,
            _ => panic!(
                "AttestationVerifier::parse Unknown field unprotected:{:?}",
                elements[1]
            ),
        }
        .to_owned();
        let payload = match &elements[2] {
            serde_cbor::Value::Bytes(payld) => payld,
            _ => panic!(
                "AttestationVerifier::parse Unknown field payload:{:?}",
                elements[2]
            ),
        }
        .to_vec();
        let signature = match &elements[3] {
            serde_cbor::Value::Bytes(sig) => sig,
            _ => panic!(
                "AttestationVerifier::parse Unknown field signature:{:?}",
                elements[3]
            ),
        }
        .to_vec();
        Ok(CoseSign1Envelope {
            protected,
            payload,
            signature,
        })
    }

    fn parse_payload(payload: &Vec<u8>) -> Result<AttestationDocument, String> {
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

        let module_id: String =
            match document_map.get(&serde_cbor::Value::Text("module_id".to_string())) {
                Some(serde_cbor::Value::Text(val)) => val.to_string(),
                _ => {
                    return Err(
                        "AttestationVerifier::parse_payload module_id is wrong type or not present"
                            .to_string(),
                    )
                }
            };

        let timestamp: i128 =
            match document_map.get(&serde_cbor::Value::Text("timestamp".to_string())) {
                Some(serde_cbor::Value::Integer(val)) => *val,
                _ => {
                    return Err(
                        "AttestationVerifier::parse_payload timestamp is wrong type or not present"
                            .to_string(),
                    )
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
                _ => return Err(
                    "AttestationVerifier::parse_payload certificate is wrong type or not present"
                        .to_string(),
                ),
            };

        let pcrs: Vec<Vec<u8>> = match document_map
            .get(&serde_cbor::Value::Text("pcrs".to_string()))
        {
            Some(serde_cbor::Value::Map(map)) => {
                let mut ret_vec: Vec<Vec<u8>> = Vec::new();
                let num_entries:i128 = map.len().try_into()
                    .map_err(|err| format!("AttestationVerifier::parse_payload failed to convert pcrs len into i128:{:?}", err))?;
                for x in 0..num_entries {
                    match map.get(&serde_cbor::Value::Integer(x)) {
                        Some(serde_cbor::Value::Bytes(inner_vec)) => {
                            ret_vec.push(inner_vec.to_vec());
                        },
                        _ => return Err("AttestationVerifier::parse_payload pcrs inner vec is wrong type or not there?".to_string()),
                    }
                }
                ret_vec
            }
            _ => {
                return Err(
                    "AttestationVerifier::parse_payload pcrs is wrong type or not present"
                        .to_string(),
                )
            }
        };

        for (i, pcr) in pcrs.iter().enumerate() {
            let pcr_str = pcr.iter().fold(String::new(), |mut acc, b| {
                let _ = write!(acc, "{:02x}", b); // infallible
                acc
            });
            println!("PCR {}: {}", i, pcr_str);
        }

        let nonce: Option<Vec<u8>> =
            match document_map.get(&serde_cbor::Value::Text("nonce".to_string())) {
                Some(serde_cbor::Value::Bytes(val)) => Some(val.to_vec()),
                None => None,
                _ => {
                    return Err(
                        "AttestationVerifier::parse_payload nonce is wrong type or not present"
                            .to_string(),
                    )
                }
            };

        println!("nonce:{:?}", nonce);

        let user_data: Option<Vec<u8>> =
            match document_map.get(&serde_cbor::Value::Text("user_data".to_string())) {
                Some(serde_cbor::Value::Bytes(val)) => Some(val.to_vec()),
                None => None,
                Some(_null) => None,
            };

        let digest: String = match document_map.get(&serde_cbor::Value::Text("digest".to_string()))
        {
            Some(serde_cbor::Value::Text(val)) => val.to_string(),
            _ => {
                return Err(
                    "AttestationVerifier::parse_payload digest is wrong type or not present"
                        .to_string(),
                )
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
                                return Err(
                                    "AttestationVerifier::parse_payload inner_vec is wrong type"
                                        .to_string(),
                                )
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

        Ok(AttestationDocument {
            module_id,
            timestamp,
            digest,
            pcrs,
            certificate,
            cabundle,
            public_key,
            user_data,
            nonce,
        })
    }
}

pub fn fetch_attestation_document(
    enclave_endpoint: &str,
    nonce: [u8; 20],
) -> Result<Vec<u8>, String> {
    use reqwest::blocking::Client;
    use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};

    let url = format!("{}?nonce={}", enclave_endpoint, hex::encode(nonce));

    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, HeaderValue::from_static("attestation-client"));

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .default_headers(headers)
        .build()
        .map_err(|e| format!("Failed to build client: {}", e))?;

    let response = client
        .get(&url)
        .send()
        .map_err(|e| format!("Failed to send request: {}", e))?;

    if !response.status().is_success() {
        return Err(format!("Request failed with status: {}", response.status()));
    }

    let decoded_response = response
        .text()
        .map_err(|e| format!("Failed to read response body as text: {}", e))?;

    BASE64
        .decode(decoded_response.trim())
        .map_err(|e| format!("Failed to decode base64: {}", e))
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use rand::Rng;
    use rustls_pemfile::Item;

    use super::*;

    #[test]
    fn test_authenticate() {
        // @note : nonce is 20 bytes and should be random in practice
        let nonce: [u8; 20] = rand::thread_rng().gen();

        let cert = rustls_pemfile::read_one_from_slice(AWS_ROOT_CERT_PEM.as_bytes());
        let cert = cert.unwrap().unwrap().0;

        let attestation_verifier = if let Item::X509Certificate(der) = cert {
            AttestationVerifier::new(der.to_vec())
        } else {
            panic!("not a certificate");
        };

        // Test authentication failure
        let invalid_document_data = std::fs::read_to_string("src/invalid_attestation")
            .expect("Failed to read example_attestation file");
        let invalid_document_data = BASE64
            .decode(invalid_document_data.trim())
            .expect("Failed to decode base64 data");
        let result = attestation_verifier.authenticate(&invalid_document_data, SystemTime::now());

        assert!(
            result.is_err(),
            "Authentication should fail with invalid data"
        );

        // Test authentication from file
        let document_data = std::fs::read_to_string("src/example_attestation")
            .expect("Failed to read example_attestation file");
        let document_data = BASE64
            .decode(document_data.trim())
            .expect("Failed to decode base64 data");
        let result = attestation_verifier.authenticate(
            &document_data,
            UNIX_EPOCH
                .checked_add(Duration::from_secs(1722458896))
                .expect("UNIX time should be valid"),
        );

        assert!(
            result.is_ok(),
            "Authentication should succeed with valid file data and appropriate timestamp"
        );

        let result = attestation_verifier.authenticate(&document_data, SystemTime::now());
        assert!(
            result.is_err(),
            "Authentication should fail with valid file data but invalid timestamp"
        );

        // Test remote authentication
        let document_data = fetch_attestation_document(DEFAULT_ENCLAVE_ENDPOINT, nonce).unwrap();
        let result = attestation_verifier.authenticate(&document_data, SystemTime::now());

        assert!(
            result.is_ok(),
            "Authentication should succeed with valid remote data"
        );

        // Test with invalid root certificate
        let cert = std::fs::read_to_string("src/aws_root_invalid.pem")
            .expect("Failed to read invalid root certificate");
        let cert = rustls_pemfile::read_one_from_slice(cert.as_bytes());
        let cert = cert.unwrap().unwrap().0;

        let invalid_attestation_verifier = if let Item::X509Certificate(der) = cert {
            AttestationVerifier::new(der.to_vec())
        } else {
            panic!("not a certificate");
        };

        let result = invalid_attestation_verifier.authenticate(&document_data, SystemTime::now());

        println!("result:{:?}", result.as_ref().err());
        assert!(
            result.is_err(),
            "Authentication should fail with invalid root certificate"
        );
    }
}
