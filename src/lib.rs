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

use aws_nitro_enclaves_cose::crypto::Hash;
use aws_nitro_enclaves_cose::sign::SigStructure;
use base64::{engine::general_purpose::STANDARD, Engine};
use hex;
use openssl::pkey::Public;
use pem::{encode, EncodeConfig, Pem};
use reqwest;
use std::collections::BTreeMap;
use std::convert::TryInto;
use x509_cert::{der::Decode, Certificate};
const DEFAULT_ENCLAVE_ENDPOINT: &str = "https://tlsn.eternis.ai/enclave/attestation";
const DEFAULT_ROOT_CERT_PATH: &str = "src/aws_root.pem";
// The AWS Nitro Attestation Document.
// This is described in
// https://docs.aws.amazon.com/ko_kr/enclaves/latest/user/verify-root.html
// under the heading "Attestation document specification"
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

pub struct AttestationVerifier {
    trusted_root_cert: Vec<u8>,
    enclave_endpoint: String,
}

impl AttestationVerifier {
    pub fn new(trusted_root_cert_path: Option<String>, enclave_endpoint: Option<String>) -> Self {
        let trusted_root_cert_path =
            trusted_root_cert_path.unwrap_or_else(|| DEFAULT_ROOT_CERT_PATH.to_string());

        let trusted_root_cert_pem = std::fs::read_to_string(&trusted_root_cert_path)
            .expect("Failed to read aws_root.pem file");
        let trusted_root_cert = rustls_pemfile::certs(&mut trusted_root_cert_pem.as_bytes())
            .into_iter()
            .next()
            .expect("No certificates found in PEM file")
            .unwrap()
            .to_vec();

        Self {
            trusted_root_cert: trusted_root_cert,
            enclave_endpoint: enclave_endpoint.unwrap_or(DEFAULT_ENCLAVE_ENDPOINT.to_string()),
        }
    }

    // pub fn verify_x509_signature(cert_data: &[u8]) -> Result<bool, Box<dyn std::error::Error>> {
    //     use rsa::pkcs1v15::{Signature, VerifyingKey};
    //     use rsa::signature::Verifier;
    //     use sha2::{Digest, Sha256};
    //     use spki::SignatureAlgorithm;
    //     use x509_cert::der::{Decode, Encode};
    //     use x509_cert::Certificate;
    //     // Parse the certificate
    //     let cert = Certificate::from_der(cert_data)?;
    //     // Extract the TBS (to-be-signed) certificate
    //     let tbs_certificate = cert.tbs_certificate;

    //     // Get the signature algorithm
    //     let signature_algorithm = cert.signature_algorithm.oid;

    //     // Get the signature
    //     let sig_bytes = cert.signature.as_bytes().unwrap().to_vec();
    //     let signature = Signature::from(sig_bytes.into_boxed_slice());

    //     // Get the public key
    //     let public_key = &cert.tbs_certificate.subject_public_key_info;

    //     // Verify the signature based on the algorithm
    //     match signature_algorithm.to_string().as_str() {
    //         "1.2.840.113549.1.1.11" => {
    //             // sha256WithRSAEncryption
    //             // Create a verifying key from the public key
    //             let verifying_key =
    //                 VerifyingKey::<Sha256>::new(public_key.subject_public_key).unwrap();

    //             // Create a Sha256 hash of the TBS certificate
    //             let mut hasher = Sha256::new();
    //             hasher.update(&tbs_certificate.to_der()?);
    //             let digest = hasher.finalize();

    //             // Verify the signature
    //             verifying_key
    //                 .verify(&digest, &Signature::try_from(signature)?)
    //                 .map_err(|e| e.into())
    //         }
    //         // Add other signature algorithms as needed
    //         _ => Err("Unsupported signature algorithm".into()),
    //     }
    // }

    /// Fetches the attestation document from the enclave endpoint.
    ///
    /// # Arguments
    ///
    /// * `nonce` - A string slice that holds the 40 bytesnonce value.
    ///
    /// # Returns
    ///
    /// * `Result<Vec<u8>, String>` - A result containing the attestation document as a vector of bytes on success, or an error message on failure.

    pub fn authenticate(
        &self,
        nonce: Option<&str>,
        document_data: Option<&[u8]>,
        trusted_root_cert: Option<Vec<u8>>,
    ) -> Result<AttestationDocument, String> {
        let document_data = if let Some(data) = document_data {
            &data.to_vec()
        } else {
            &self
                .fetch_attestation_document(nonce.unwrap_or(""))
                .map_err(|err| format!("Failed to fetch attestation document: {:?}", err))?
        };
        println!("{}", base64::encode(&document_data));

        let root_cert = trusted_root_cert.unwrap_or(self.trusted_root_cert.clone());

        // Following the steps here: https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
        // Step 1. Decode the CBOR object and map it to a COSE_Sign1 structure

        let (_protected, payload, _signature) = AttestationVerifier::parse(document_data)
            .map_err(|err| format!("AttestationVerifier::authenticate parse failed:{:?}", err))?;

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

        // println!("find intermediates certs:{:?}", certs.len());
        // for cert in &certs {
        //     let x509_cert = x509_cert::Certificate::from_der(&cert.0).unwrap();
        //     let issuer = x509_cert.tbs_certificate.issuer;
        //     let pubkey_info = x509_cert.tbs_certificate.subject_public_key_info;
        //     println!(
        //         "Subject: {:?}",
        //         x509_cert.tbs_certificate.subject.to_string()
        //     );
        //     println!(
        //         "Public Key: {:?}",
        //         pubkey_info.subject_public_key.as_bytes().unwrap()
        //     );
        //     let pem_certificate = format!(
        //         "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
        //         STANDARD.encode(&cert.0)
        //     );
        //     println!("{}\n==========================", pem_certificate);
        // }

        let verifier = rustls::server::AllowAnyAuthenticatedClient::new(root_store);
        let _verified = verifier
            .verify_client_cert(
                &rustls::Certificate(document.certificate.clone()),
                &certs,
                std::time::SystemTime::now(),
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

            let cert =   openssl::x509::X509::from_der(&document.certificate)
                .map_err(|err| {
                    format!("AttestationVerifier::authenticate failed to parse document.certificate as X509 certificate:{:?}", err)
                })?;
            let public_key = cert.public_key()
                .map_err(|err| {
                    format!("AttestationVerifier::authenticate failed to extract public key from certificate:{:?}", err)
                })?;

            use aws_nitro_enclaves_cose::crypto::SigningPublicKey;

            let public_key_der = public_key
                .public_key_to_der()
                .map_err(|err| format!("Failed to convert public key to DER format: {:?}", err))?;

            println!("public_key_der: {:?}", public_key_der);
            let key: &dyn SigningPublicKey = public_key.as_ref();
            println!("signature algorithm: {:?}", key.get_parameters().unwrap());

            let public_key_hex =
                hex::encode(public_key.public_key_to_der().map_err(|err| {
                    format!("Failed to convert public key to DER format: {:?}", err)
                })?);

            println!("Public Key (hex): {}", public_key_hex);
            let pem = public_key
                .public_key_to_pem()
                .map_err(|err| format!("Failed to convert public key to PEM format: {:?}", err))?;
            println!("PEM Public Key:\n{}", String::from_utf8(pem).unwrap());

            println!("Signature: {:?}", _signature);

            //print sig_structure
            //@test
            let sig_structure_2 = SigStructure::new_sign1(&_protected, &payload).unwrap();
            let sig_structure_bytes = sig_structure_2.as_bytes().unwrap();
            //println!("sig_structure_bytes: {:?}", sig_structure_bytes);
            use openssl::hash::{hash, MessageDigest};
            let struct_digest = hash(MessageDigest::sha384(), &sig_structure_bytes).unwrap();
            println!("struct_digest: {:?}", &struct_digest);

            let result = public_key.verify(struct_digest.as_ref(), &_signature);
            println!("result verification 2: {:?}", result);
            ////////

            //veriy signature
            let result = sig_structure.verify_signature::<aws_nitro_enclaves_cose::crypto::Openssl>(&public_key)
                .map_err(|err| {
                    format!("AttestationVerifier::authenticate failed to verify signature on sig_structure:{:?}", err)
                })?;
            result
        };
        if !authenticated {
            return Err(format!(
                "AttestationVerifier::authenticate invalid COSE certificate for provided key"
            ));
        } else {
            return Ok(document);
        }
    }

    fn parse(document_data: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
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

        Ok((protected.to_vec(), payload.to_vec(), signature.to_vec()))
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
                    return Err(format!(
                        "AttestationVerifier::parse_payload module_id is wrong type or not present"
                    ))
                }
            };

        let timestamp: i128 =
            match document_map.get(&serde_cbor::Value::Text("timestamp".to_string())) {
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

        let digest: String = match document_map.get(&serde_cbor::Value::Text("digest".to_string()))
        {
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

        Ok(AttestationDocument {
            module_id: module_id,
            timestamp: timestamp,
            digest: digest,
            pcrs: pcrs,
            certificate: certificate,
            cabundle: cabundle,
            public_key: public_key,
            user_data: user_data,
            nonce: nonce,
        })
    }

    pub fn fetch_attestation_document(&self, nonce: &str) -> Result<Vec<u8>, String> {
        use reqwest::blocking::Client;
        use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};

        let url = format!("{}?nonce={}", self.enclave_endpoint, nonce);

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

        base64::decode(decoded_response.trim())
            .map_err(|e| format!("Failed to decode base64: {}", e))
    }
}

use rustls_pemfile::{certs, pkcs8_private_keys};
use std::io::BufReader;

#[cfg(test)]
mod tests {
    use rand_core::RngCore;
    use rsa::signature::SignerMut;
    use rustls::internal::msgs::base;
    use rustls::sign;
    use x509_cert::der::Encode;

    use super::*;

    use p384::ecdsa::{Signature, SigningKey, VerifyingKey};
    use p384::NistP384;
    use rand_core::OsRng;
    use rsa::signature::Verifier;

    #[test]
    fn test_authenticate() {
        let nonce = "0000000000000000000000000000000000000001";
        let attestation_verifier = AttestationVerifier::new(None, None);

        // Test successful authentication
        let result = attestation_verifier.authenticate(Some(nonce), None, None);

        println!("result:{:?}", result.as_ref().err());
        assert!(
            result.is_ok(),
            "Authentication should succeed with valid data"
        );
    }

    #[test]
    fn test_authenticate_from_file() {
        // From file
        let document_data = std::fs::read_to_string("src/example_attestation")
            .expect("Failed to read example_attestation file");
        let document_data =
            base64::decode(document_data.trim()).expect("Failed to decode base64 data");

        let attestation_verifier = AttestationVerifier::new(None, None);

        // Test successful authentication
        let result = attestation_verifier.authenticate(None, Some(&document_data), None);

        println!("result:{:?}", result.as_ref().err());
        assert!(
            result.is_ok(),
            "Authentication should succeed with valid data"
        );
    }

    #[test]
    fn test_authenticate_fail() {
        let attestation_verifier = AttestationVerifier::new(None, None);

        //try with invalid nonce (too short)
        let nonce = "000000000000000000000000000000000000001";
        let result = attestation_verifier.authenticate(Some(nonce), None, None);

        println!("result:{:?}", result.as_ref().err());
        assert!(
            result.is_err(),
            "Authentication should fail with invalid nonce"
        );

        // Test authentication failure
        let invalid_document_data = std::fs::read_to_string("src/invalid_attestation")
            .expect("Failed to read example_attestation file");
        let invalid_document_data =
            base64::decode(invalid_document_data.trim()).expect("Failed to decode base64 data");
        let result = attestation_verifier.authenticate(None, Some(&invalid_document_data), None);

        assert!(
            result.is_err(),
            "Authentication should fail with invalid data"
        );

        // Test with invalid root certificate
        let nonce = "0000000000000000000000000000000000000001"; // valid nonce
        let invalid_root_cert = vec![0; 10]; // Invalid certificate
        let result = attestation_verifier.authenticate(Some(nonce), None, Some(invalid_root_cert));

        println!("result:{:?}", result.as_ref().err());
        assert!(
            result.is_err(),
            "Authentication should fail with invalid root certificate"
        );
    }

    #[test]
    fn test_sig_es384_from_newkey() {
        let mut rng = OsRng;
        let mut rand_bytes = [0u8; 32];
        rng.fill_bytes(&mut rand_bytes);

        // // Generate a new signing key
        // let mut signing_key: SigningKey = SigningKey::random(&mut rng);

        let bytes = [
            128, 30, 145, 80, 235, 100, 39, 24, 33, 47, 98, 31, 233, 19, 212, 38, 71, 80, 189, 104,
            183, 3, 34, 212, 91, 178, 86, 230, 133, 233, 255, 135, 91, 109, 240, 12, 140, 134, 201,
            30, 122, 116, 254, 172, 12, 178, 62, 17,
        ];
        let mut signing_key: SigningKey = SigningKey::from_bytes(&bytes.into()).unwrap();
        println!("signing_key: {:?}", signing_key.to_bytes());

        // @note OK
        // Sign the message digest with the signing key
        let msg = b"ahi";

        // @bug signature is not ok = deterministic
        let signature: Signature = signing_key.sign(msg);
        println!(
            "base64 signature {:?}",
            base64::encode(signature.to_bytes())
        );
        println!("base64 signature {:?}", signature.to_der().as_bytes());

        // @note pubkey ok when verifying with chatgpt
        let verifying_key = signing_key.verifying_key();
        println!(
            "verifying_key: {:?}",
            hex::encode(verifying_key.to_sec1_bytes())
        );
        // Convert verifying_key to PEM format
        // let pem = pem::Pem::new("CERTIFICATE", verifying_key.to_sec1_bytes());
        // println!("pem: {:?}", pem);

        // verify with signature here
        // verifying_key.verify(msg, &signature).unwrap_or_else(|e| {
        //     println!("Signature verification failed: {}", e);
        //     ();

        //@note verify signature from bytes, works
        let signature_from_bytes = Signature::from_der(signature.to_der().as_bytes()).unwrap();
        println!(
            "signature_from_bytes{:?}",
            base64::encode(signature.to_der().as_bytes())
        );

        //@bug use signature produced by js code
        // Idk if the sig is a der format
        // this does not work, probably bc not der format
        //@bug  bc it's not DER
        let sig_bytes = base64::decode("MGUCMEuIiSc5M4EPxTAybvfqeAS3P5nHz25Wg6JVrvF0NYJValDUrT58oGy66TPvDq+RBQIxAOK6hWd3zuqrHYG4U++I8g0Jy+FJipD9dvq6eXeB9vNQDQ1A11oGqn+akIw93IM+pQ==").unwrap();
        //let signature_from_bytes_js = Signature::from_der(&sig_bytes).unwrap();

        verifying_key
            .verify(msg, &signature_from_bytes)
            .unwrap_or_else(|e| {
                println!("Signature verification failed: {}", e);
                ()
            });
    }

    #[test]
    fn test_sig_es384_without_openssl() {
        let sig_bytes = [
            132, 106, 83, 105, 103, 110, 97, 116, 117, 114, 101, 49, 68, 161, 1, 56, 34, 64, 89,
            17, 93, 169, 105, 109, 111, 100, 117, 108, 101, 95, 105, 100, 120, 39, 105, 45, 48, 98,
            98, 102, 49, 98, 102, 101, 50, 51, 50, 98, 56, 99, 50, 99, 101, 45, 101, 110, 99, 48,
            49, 57, 49, 98, 97, 51, 53, 99, 57, 100, 49, 98, 55, 55, 97, 102, 100, 105, 103, 101,
            115, 116, 102, 83, 72, 65, 51, 56, 52, 105, 116, 105, 109, 101, 115, 116, 97, 109, 112,
            27, 0, 0, 1, 145, 195, 148, 238, 45, 100, 112, 99, 114, 115, 176, 0, 88, 48, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 88, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 88, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 3, 88, 48, 103, 28, 161, 227, 40, 247, 80, 21, 178, 174, 238, 96, 99, 156,
            197, 37, 43, 200, 53, 216, 187, 105, 4, 68, 209, 248, 226, 191, 66, 96, 247, 61, 193,
            183, 30, 7, 161, 74, 119, 12, 125, 11, 236, 172, 110, 179, 181, 63, 4, 88, 48, 211, 82,
            207, 163, 27, 141, 197, 244, 133, 108, 159, 168, 24, 27, 25, 237, 18, 245, 218, 35,
            136, 58, 196, 236, 114, 149, 48, 245, 13, 193, 211, 127, 26, 195, 135, 106, 122, 243,
            155, 212, 222, 122, 42, 234, 209, 77, 20, 203, 5, 88, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 88, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 7, 88, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 88,
            48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 88, 48, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 88, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 11, 88, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 12, 88, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 13, 88, 48,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 14, 88, 48, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 15, 88, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 107, 99, 101, 114, 116, 105, 102, 105, 99, 97, 116, 101, 89, 2,
            127, 48, 130, 2, 123, 48, 130, 2, 1, 160, 3, 2, 1, 2, 2, 16, 1, 145, 186, 53, 201, 209,
            183, 122, 0, 0, 0, 0, 102, 218, 0, 204, 48, 10, 6, 8, 42, 134, 72, 206, 61, 4, 3, 3,
            48, 129, 142, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 19, 48, 17, 6, 3, 85,
            4, 8, 12, 10, 87, 97, 115, 104, 105, 110, 103, 116, 111, 110, 49, 16, 48, 14, 6, 3, 85,
            4, 7, 12, 7, 83, 101, 97, 116, 116, 108, 101, 49, 15, 48, 13, 6, 3, 85, 4, 10, 12, 6,
            65, 109, 97, 122, 111, 110, 49, 12, 48, 10, 6, 3, 85, 4, 11, 12, 3, 65, 87, 83, 49, 57,
            48, 55, 6, 3, 85, 4, 3, 12, 48, 105, 45, 48, 98, 98, 102, 49, 98, 102, 101, 50, 51, 50,
            98, 56, 99, 50, 99, 101, 46, 117, 115, 45, 101, 97, 115, 116, 45, 49, 46, 97, 119, 115,
            46, 110, 105, 116, 114, 111, 45, 101, 110, 99, 108, 97, 118, 101, 115, 48, 30, 23, 13,
            50, 52, 48, 57, 48, 53, 49, 57, 48, 52, 52, 49, 90, 23, 13, 50, 52, 48, 57, 48, 53, 50,
            50, 48, 52, 52, 52, 90, 48, 129, 147, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49,
            19, 48, 17, 6, 3, 85, 4, 8, 12, 10, 87, 97, 115, 104, 105, 110, 103, 116, 111, 110, 49,
            16, 48, 14, 6, 3, 85, 4, 7, 12, 7, 83, 101, 97, 116, 116, 108, 101, 49, 15, 48, 13, 6,
            3, 85, 4, 10, 12, 6, 65, 109, 97, 122, 111, 110, 49, 12, 48, 10, 6, 3, 85, 4, 11, 12,
            3, 65, 87, 83, 49, 62, 48, 60, 6, 3, 85, 4, 3, 12, 53, 105, 45, 48, 98, 98, 102, 49,
            98, 102, 101, 50, 51, 50, 98, 56, 99, 50, 99, 101, 45, 101, 110, 99, 48, 49, 57, 49,
            98, 97, 51, 53, 99, 57, 100, 49, 98, 55, 55, 97, 46, 117, 115, 45, 101, 97, 115, 116,
            45, 49, 46, 97, 119, 115, 48, 118, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 5, 43,
            129, 4, 0, 34, 3, 98, 0, 4, 13, 57, 68, 163, 172, 239, 111, 1, 76, 50, 181, 138, 20,
            66, 58, 128, 85, 72, 83, 3, 250, 181, 211, 251, 35, 124, 60, 69, 57, 73, 189, 176, 102,
            117, 81, 137, 119, 46, 239, 200, 244, 92, 84, 4, 63, 241, 205, 42, 61, 134, 114, 217,
            51, 247, 10, 210, 198, 14, 153, 208, 78, 146, 164, 73, 22, 142, 126, 94, 198, 246, 85,
            63, 9, 249, 46, 92, 234, 134, 190, 52, 226, 192, 6, 154, 39, 233, 170, 81, 1, 165, 229,
            135, 200, 117, 229, 197, 163, 29, 48, 27, 48, 12, 6, 3, 85, 29, 19, 1, 1, 255, 4, 2,
            48, 0, 48, 11, 6, 3, 85, 29, 15, 4, 4, 3, 2, 6, 192, 48, 10, 6, 8, 42, 134, 72, 206,
            61, 4, 3, 3, 3, 104, 0, 48, 101, 2, 48, 35, 40, 7, 164, 203, 131, 244, 248, 136, 179,
            36, 22, 246, 109, 34, 134, 190, 100, 7, 58, 16, 83, 211, 16, 180, 78, 126, 75, 204, 42,
            87, 159, 6, 255, 225, 203, 191, 74, 131, 53, 138, 241, 244, 3, 218, 233, 237, 161, 2,
            49, 0, 153, 64, 216, 69, 138, 166, 146, 104, 193, 135, 218, 171, 221, 239, 20, 115,
            243, 34, 108, 109, 14, 208, 131, 195, 48, 2, 116, 170, 169, 134, 93, 104, 109, 165,
            100, 48, 50, 159, 23, 56, 204, 151, 78, 226, 86, 227, 229, 203, 104, 99, 97, 98, 117,
            110, 100, 108, 101, 132, 89, 2, 21, 48, 130, 2, 17, 48, 130, 1, 150, 160, 3, 2, 1, 2,
            2, 17, 0, 249, 49, 117, 104, 27, 144, 175, 225, 29, 70, 204, 180, 228, 231, 248, 86,
            48, 10, 6, 8, 42, 134, 72, 206, 61, 4, 3, 3, 48, 73, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19,
            2, 85, 83, 49, 15, 48, 13, 6, 3, 85, 4, 10, 12, 6, 65, 109, 97, 122, 111, 110, 49, 12,
            48, 10, 6, 3, 85, 4, 11, 12, 3, 65, 87, 83, 49, 27, 48, 25, 6, 3, 85, 4, 3, 12, 18, 97,
            119, 115, 46, 110, 105, 116, 114, 111, 45, 101, 110, 99, 108, 97, 118, 101, 115, 48,
            30, 23, 13, 49, 57, 49, 48, 50, 56, 49, 51, 50, 56, 48, 53, 90, 23, 13, 52, 57, 49, 48,
            50, 56, 49, 52, 50, 56, 48, 53, 90, 48, 73, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85,
            83, 49, 15, 48, 13, 6, 3, 85, 4, 10, 12, 6, 65, 109, 97, 122, 111, 110, 49, 12, 48, 10,
            6, 3, 85, 4, 11, 12, 3, 65, 87, 83, 49, 27, 48, 25, 6, 3, 85, 4, 3, 12, 18, 97, 119,
            115, 46, 110, 105, 116, 114, 111, 45, 101, 110, 99, 108, 97, 118, 101, 115, 48, 118,
            48, 16, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 5, 43, 129, 4, 0, 34, 3, 98, 0, 4, 252, 2,
            84, 235, 166, 8, 193, 243, 104, 112, 226, 154, 218, 144, 190, 70, 56, 50, 146, 115,
            110, 137, 75, 255, 246, 114, 217, 137, 68, 75, 80, 81, 229, 52, 164, 177, 246, 219,
            227, 192, 188, 88, 26, 50, 183, 177, 118, 7, 14, 222, 18, 214, 154, 63, 234, 33, 27,
            102, 231, 82, 207, 125, 209, 221, 9, 95, 111, 19, 112, 244, 23, 8, 67, 217, 220, 16, 1,
            33, 228, 207, 99, 1, 40, 9, 102, 68, 135, 201, 121, 98, 132, 48, 77, 197, 63, 244, 163,
            66, 48, 64, 48, 15, 6, 3, 85, 29, 19, 1, 1, 255, 4, 5, 48, 3, 1, 1, 255, 48, 29, 6, 3,
            85, 29, 14, 4, 22, 4, 20, 144, 37, 181, 13, 217, 5, 71, 231, 150, 195, 150, 250, 114,
            157, 207, 153, 169, 223, 75, 150, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 1,
            134, 48, 10, 6, 8, 42, 134, 72, 206, 61, 4, 3, 3, 3, 105, 0, 48, 102, 2, 49, 0, 163,
            127, 47, 145, 161, 201, 189, 94, 231, 184, 98, 124, 22, 152, 210, 85, 3, 142, 31, 3,
            67, 249, 91, 99, 169, 98, 140, 61, 57, 128, 149, 69, 161, 30, 188, 191, 46, 59, 85,
            216, 174, 238, 113, 180, 195, 214, 173, 243, 2, 49, 0, 162, 243, 155, 22, 5, 178, 112,
            40, 165, 221, 75, 160, 105, 181, 1, 110, 101, 180, 251, 222, 143, 224, 6, 29, 106, 83,
            25, 127, 156, 218, 245, 217, 67, 188, 97, 252, 43, 235, 3, 203, 111, 238, 141, 35, 2,
            243, 223, 246, 89, 2, 195, 48, 130, 2, 191, 48, 130, 2, 69, 160, 3, 2, 1, 2, 2, 17, 0,
            216, 118, 4, 248, 65, 63, 172, 93, 173, 254, 42, 198, 151, 253, 49, 72, 48, 10, 6, 8,
            42, 134, 72, 206, 61, 4, 3, 3, 48, 73, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83,
            49, 15, 48, 13, 6, 3, 85, 4, 10, 12, 6, 65, 109, 97, 122, 111, 110, 49, 12, 48, 10, 6,
            3, 85, 4, 11, 12, 3, 65, 87, 83, 49, 27, 48, 25, 6, 3, 85, 4, 3, 12, 18, 97, 119, 115,
            46, 110, 105, 116, 114, 111, 45, 101, 110, 99, 108, 97, 118, 101, 115, 48, 30, 23, 13,
            50, 52, 48, 57, 48, 52, 49, 52, 51, 50, 53, 53, 90, 23, 13, 50, 52, 48, 57, 50, 52, 49,
            53, 51, 50, 53, 53, 90, 48, 100, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 15,
            48, 13, 6, 3, 85, 4, 10, 12, 6, 65, 109, 97, 122, 111, 110, 49, 12, 48, 10, 6, 3, 85,
            4, 11, 12, 3, 65, 87, 83, 49, 54, 48, 52, 6, 3, 85, 4, 3, 12, 45, 101, 99, 50, 56, 99,
            98, 98, 97, 97, 101, 48, 56, 48, 57, 52, 100, 46, 117, 115, 45, 101, 97, 115, 116, 45,
            49, 46, 97, 119, 115, 46, 110, 105, 116, 114, 111, 45, 101, 110, 99, 108, 97, 118, 101,
            115, 48, 118, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 5, 43, 129, 4, 0, 34, 3, 98,
            0, 4, 101, 244, 14, 220, 43, 150, 80, 108, 175, 254, 86, 242, 236, 173, 201, 179, 116,
            167, 149, 1, 146, 157, 152, 57, 109, 22, 162, 128, 42, 206, 177, 95, 176, 187, 197,
            153, 225, 141, 103, 82, 175, 181, 207, 163, 53, 242, 88, 112, 115, 69, 85, 110, 38,
            166, 103, 129, 77, 160, 76, 4, 186, 219, 127, 12, 143, 211, 64, 75, 57, 248, 83, 6, 92,
            77, 183, 185, 201, 175, 110, 192, 46, 166, 98, 187, 63, 116, 124, 130, 119, 63, 109,
            228, 175, 122, 188, 157, 163, 129, 213, 48, 129, 210, 48, 18, 6, 3, 85, 29, 19, 1, 1,
            255, 4, 8, 48, 6, 1, 1, 255, 2, 1, 2, 48, 31, 6, 3, 85, 29, 35, 4, 24, 48, 22, 128, 20,
            144, 37, 181, 13, 217, 5, 71, 231, 150, 195, 150, 250, 114, 157, 207, 153, 169, 223,
            75, 150, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20, 36, 110, 92, 49, 206, 68, 132, 225,
            135, 68, 187, 18, 132, 43, 56, 23, 255, 183, 230, 29, 48, 14, 6, 3, 85, 29, 15, 1, 1,
            255, 4, 4, 3, 2, 1, 134, 48, 108, 6, 3, 85, 29, 31, 4, 101, 48, 99, 48, 97, 160, 95,
            160, 93, 134, 91, 104, 116, 116, 112, 58, 47, 47, 97, 119, 115, 45, 110, 105, 116, 114,
            111, 45, 101, 110, 99, 108, 97, 118, 101, 115, 45, 99, 114, 108, 46, 115, 51, 46, 97,
            109, 97, 122, 111, 110, 97, 119, 115, 46, 99, 111, 109, 47, 99, 114, 108, 47, 97, 98,
            52, 57, 54, 48, 99, 99, 45, 55, 100, 54, 51, 45, 52, 50, 98, 100, 45, 57, 101, 57, 102,
            45, 53, 57, 51, 51, 56, 99, 98, 54, 55, 102, 56, 52, 46, 99, 114, 108, 48, 10, 6, 8,
            42, 134, 72, 206, 61, 4, 3, 3, 3, 104, 0, 48, 101, 2, 48, 88, 22, 88, 172, 135, 160,
            77, 3, 99, 95, 149, 212, 203, 144, 16, 138, 113, 251, 44, 39, 210, 233, 15, 24, 226,
            118, 245, 62, 33, 224, 64, 223, 164, 251, 255, 78, 110, 226, 5, 60, 209, 254, 168, 200,
            222, 3, 52, 50, 2, 49, 0, 210, 158, 80, 25, 58, 184, 253, 223, 229, 118, 41, 207, 7,
            119, 79, 101, 48, 223, 182, 25, 149, 238, 133, 0, 220, 226, 25, 76, 25, 178, 198, 121,
            135, 155, 49, 14, 6, 96, 70, 174, 191, 213, 73, 49, 38, 72, 27, 110, 89, 3, 24, 48,
            130, 3, 20, 48, 130, 2, 153, 160, 3, 2, 1, 2, 2, 16, 69, 49, 162, 26, 104, 118, 246,
            60, 185, 186, 127, 142, 139, 134, 184, 46, 48, 10, 6, 8, 42, 134, 72, 206, 61, 4, 3, 3,
            48, 100, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 15, 48, 13, 6, 3, 85, 4, 10,
            12, 6, 65, 109, 97, 122, 111, 110, 49, 12, 48, 10, 6, 3, 85, 4, 11, 12, 3, 65, 87, 83,
            49, 54, 48, 52, 6, 3, 85, 4, 3, 12, 45, 101, 99, 50, 56, 99, 98, 98, 97, 97, 101, 48,
            56, 48, 57, 52, 100, 46, 117, 115, 45, 101, 97, 115, 116, 45, 49, 46, 97, 119, 115, 46,
            110, 105, 116, 114, 111, 45, 101, 110, 99, 108, 97, 118, 101, 115, 48, 30, 23, 13, 50,
            52, 48, 57, 48, 53, 49, 49, 51, 52, 50, 53, 90, 23, 13, 50, 52, 48, 57, 49, 49, 48, 56,
            51, 52, 50, 53, 90, 48, 129, 136, 49, 59, 48, 57, 6, 3, 85, 4, 3, 12, 50, 100, 54, 101,
            55, 49, 100, 50, 48, 52, 98, 57, 49, 52, 99, 52, 46, 122, 111, 110, 97, 108, 46, 117,
            115, 45, 101, 97, 115, 116, 45, 49, 46, 97, 119, 115, 46, 110, 105, 116, 114, 111, 45,
            101, 110, 99, 108, 97, 118, 101, 115, 49, 12, 48, 10, 6, 3, 85, 4, 11, 12, 3, 65, 87,
            83, 49, 15, 48, 13, 6, 3, 85, 4, 10, 12, 6, 65, 109, 97, 122, 111, 110, 49, 11, 48, 9,
            6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 11, 48, 9, 6, 3, 85, 4, 8, 12, 2, 87, 65, 49, 16,
            48, 14, 6, 3, 85, 4, 7, 12, 7, 83, 101, 97, 116, 116, 108, 101, 48, 118, 48, 16, 6, 7,
            42, 134, 72, 206, 61, 2, 1, 6, 5, 43, 129, 4, 0, 34, 3, 98, 0, 4, 72, 44, 16, 71, 129,
            48, 9, 157, 161, 178, 11, 71, 41, 199, 78, 130, 96, 188, 131, 198, 172, 14, 128, 122,
            117, 116, 8, 29, 11, 233, 141, 91, 120, 209, 0, 48, 182, 151, 244, 248, 75, 111, 123,
            151, 177, 96, 239, 184, 225, 160, 220, 242, 121, 186, 62, 120, 47, 209, 228, 170, 93,
            74, 79, 50, 68, 139, 173, 237, 158, 31, 183, 65, 28, 207, 66, 4, 152, 180, 48, 241,
            101, 151, 127, 38, 91, 17, 96, 168, 19, 142, 58, 145, 210, 137, 99, 25, 163, 129, 234,
            48, 129, 231, 48, 18, 6, 3, 85, 29, 19, 1, 1, 255, 4, 8, 48, 6, 1, 1, 255, 2, 1, 1, 48,
            31, 6, 3, 85, 29, 35, 4, 24, 48, 22, 128, 20, 36, 110, 92, 49, 206, 68, 132, 225, 135,
            68, 187, 18, 132, 43, 56, 23, 255, 183, 230, 29, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4,
            20, 180, 46, 169, 174, 144, 210, 117, 40, 13, 224, 96, 184, 84, 69, 182, 202, 70, 188,
            125, 109, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 1, 134, 48, 129, 128, 6, 3,
            85, 29, 31, 4, 121, 48, 119, 48, 117, 160, 115, 160, 113, 134, 111, 104, 116, 116, 112,
            58, 47, 47, 99, 114, 108, 45, 117, 115, 45, 101, 97, 115, 116, 45, 49, 45, 97, 119,
            115, 45, 110, 105, 116, 114, 111, 45, 101, 110, 99, 108, 97, 118, 101, 115, 46, 115,
            51, 46, 117, 115, 45, 101, 97, 115, 116, 45, 49, 46, 97, 109, 97, 122, 111, 110, 97,
            119, 115, 46, 99, 111, 109, 47, 99, 114, 108, 47, 52, 57, 99, 97, 102, 100, 55, 100,
            45, 54, 54, 54, 49, 45, 52, 100, 52, 101, 45, 97, 99, 52, 101, 45, 97, 51, 53, 50, 56,
            97, 99, 48, 50, 98, 100, 102, 46, 99, 114, 108, 48, 10, 6, 8, 42, 134, 72, 206, 61, 4,
            3, 3, 3, 105, 0, 48, 102, 2, 49, 0, 158, 237, 141, 66, 194, 121, 157, 220, 253, 37,
            145, 114, 170, 126, 185, 169, 52, 199, 167, 231, 113, 187, 125, 149, 144, 84, 9, 72,
            234, 244, 115, 19, 58, 13, 198, 198, 108, 234, 8, 179, 216, 108, 251, 222, 28, 184, 11,
            227, 2, 49, 0, 233, 82, 65, 67, 91, 200, 145, 134, 255, 210, 192, 250, 84, 226, 78,
            128, 172, 187, 3, 108, 190, 72, 117, 1, 110, 236, 109, 143, 69, 149, 172, 251, 97, 161,
            193, 18, 163, 234, 178, 217, 194, 23, 127, 50, 226, 223, 92, 215, 89, 2, 194, 48, 130,
            2, 190, 48, 130, 2, 68, 160, 3, 2, 1, 2, 2, 21, 0, 133, 253, 212, 41, 208, 10, 180, 55,
            94, 30, 65, 17, 221, 163, 100, 83, 148, 51, 201, 253, 48, 10, 6, 8, 42, 134, 72, 206,
            61, 4, 3, 3, 48, 129, 136, 49, 59, 48, 57, 6, 3, 85, 4, 3, 12, 50, 100, 54, 101, 55,
            49, 100, 50, 48, 52, 98, 57, 49, 52, 99, 52, 46, 122, 111, 110, 97, 108, 46, 117, 115,
            45, 101, 97, 115, 116, 45, 49, 46, 97, 119, 115, 46, 110, 105, 116, 114, 111, 45, 101,
            110, 99, 108, 97, 118, 101, 115, 49, 12, 48, 10, 6, 3, 85, 4, 11, 12, 3, 65, 87, 83,
            49, 15, 48, 13, 6, 3, 85, 4, 10, 12, 6, 65, 109, 97, 122, 111, 110, 49, 11, 48, 9, 6,
            3, 85, 4, 6, 19, 2, 85, 83, 49, 11, 48, 9, 6, 3, 85, 4, 8, 12, 2, 87, 65, 49, 16, 48,
            14, 6, 3, 85, 4, 7, 12, 7, 83, 101, 97, 116, 116, 108, 101, 48, 30, 23, 13, 50, 52, 48,
            57, 48, 53, 49, 52, 50, 51, 52, 49, 90, 23, 13, 50, 52, 48, 57, 48, 54, 49, 52, 50, 51,
            52, 49, 90, 48, 129, 142, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 19, 48, 17,
            6, 3, 85, 4, 8, 12, 10, 87, 97, 115, 104, 105, 110, 103, 116, 111, 110, 49, 16, 48, 14,
            6, 3, 85, 4, 7, 12, 7, 83, 101, 97, 116, 116, 108, 101, 49, 15, 48, 13, 6, 3, 85, 4,
            10, 12, 6, 65, 109, 97, 122, 111, 110, 49, 12, 48, 10, 6, 3, 85, 4, 11, 12, 3, 65, 87,
            83, 49, 57, 48, 55, 6, 3, 85, 4, 3, 12, 48, 105, 45, 48, 98, 98, 102, 49, 98, 102, 101,
            50, 51, 50, 98, 56, 99, 50, 99, 101, 46, 117, 115, 45, 101, 97, 115, 116, 45, 49, 46,
            97, 119, 115, 46, 110, 105, 116, 114, 111, 45, 101, 110, 99, 108, 97, 118, 101, 115,
            48, 118, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 5, 43, 129, 4, 0, 34, 3, 98, 0,
            4, 94, 210, 25, 193, 221, 145, 22, 243, 151, 251, 70, 49, 113, 193, 128, 159, 60, 179,
            47, 135, 77, 233, 22, 250, 90, 38, 73, 197, 82, 17, 118, 1, 214, 8, 128, 11, 167, 144,
            128, 73, 94, 199, 250, 187, 240, 148, 241, 186, 63, 228, 236, 21, 124, 220, 103, 227,
            40, 78, 65, 75, 144, 93, 150, 136, 95, 111, 118, 255, 200, 14, 118, 48, 180, 46, 109,
            1, 128, 96, 180, 153, 132, 17, 153, 153, 16, 90, 18, 87, 147, 23, 170, 244, 223, 205,
            66, 130, 163, 102, 48, 100, 48, 18, 6, 3, 85, 29, 19, 1, 1, 255, 4, 8, 48, 6, 1, 1,
            255, 2, 1, 0, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 2, 4, 48, 29, 6, 3, 85,
            29, 14, 4, 22, 4, 20, 27, 217, 20, 8, 8, 214, 231, 245, 40, 187, 113, 85, 219, 47, 209,
            151, 161, 248, 113, 76, 48, 31, 6, 3, 85, 29, 35, 4, 24, 48, 22, 128, 20, 180, 46, 169,
            174, 144, 210, 117, 40, 13, 224, 96, 184, 84, 69, 182, 202, 70, 188, 125, 109, 48, 10,
            6, 8, 42, 134, 72, 206, 61, 4, 3, 3, 3, 104, 0, 48, 101, 2, 49, 0, 245, 215, 159, 127,
            222, 182, 251, 182, 180, 121, 158, 193, 153, 214, 20, 195, 222, 94, 26, 171, 108, 18,
            107, 93, 189, 242, 135, 44, 245, 226, 239, 69, 18, 243, 248, 118, 196, 205, 22, 211,
            191, 82, 122, 172, 21, 253, 183, 61, 2, 48, 56, 182, 131, 55, 65, 226, 90, 50, 90, 171,
            140, 0, 49, 149, 22, 11, 94, 147, 171, 25, 12, 94, 18, 40, 25, 105, 64, 52, 181, 97,
            79, 167, 201, 69, 219, 193, 150, 95, 121, 219, 95, 36, 206, 90, 236, 19, 243, 49, 106,
            112, 117, 98, 108, 105, 99, 95, 107, 101, 121, 69, 100, 117, 109, 109, 121, 105, 117,
            115, 101, 114, 95, 100, 97, 116, 97, 88, 68, 18, 32, 198, 130, 188, 108, 129, 74, 103,
            72, 244, 144, 200, 200, 228, 142, 92, 64, 197, 5, 229, 201, 155, 11, 97, 123, 133, 205,
            199, 29, 35, 111, 42, 56, 18, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 101, 110, 111, 110, 99, 101, 84, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ];
        let sig_bytes = b"ahi";

        //parse cbor
        //verify x509
        // let publickey = cert.tbs_certificate.subject_public_key_info;

        //@ok parse pubkey
        // pubkey is hex in der format, it expects sec1
        let pubkey_string = "040b5b964978f6733083c0c4cb595e41166c3174ce8f5fda7e3e4f587fdac87f7ef89b95cfd54f2aefd74184b488b9aa23b2f393dfd51470f2513920f516a60bb9e774ad78a8a088a2d43de3696ea9986549161a1dcc2df5732e6c7ce628b6bcc5";
        let pubkey = hex::decode(pubkey_string).expect("Failed to decode hex public key");
        let verifying_key = VerifyingKey::from_sec1_bytes(&pubkey).expect("Invalid public key");
        let encoded_point = verifying_key.to_encoded_point(false);
        println!(
            " public key: {:?}",
            hex::encode(verifying_key.to_sec1_bytes())
        );

        //@note working with this signature (103 bytes)
        let signature = [
            48, 101, 2, 48, 75, 136, 137, 39, 57, 51, 129, 15, 197, 48, 50, 110, 247, 234, 120, 4,
            183, 63, 153, 199, 207, 110, 86, 131, 162, 85, 174, 241, 116, 53, 130, 85, 106, 80,
            212, 173, 62, 124, 160, 108, 186, 233, 51, 239, 14, 175, 145, 5, 2, 49, 0, 226, 186,
            133, 103, 119, 206, 234, 171, 29, 129, 184, 83, 239, 136, 242, 13, 9, 203, 225, 73,
            138, 144, 253, 118, 250, 186, 121, 119, 129, 246, 243, 80, 13, 13, 64, 215, 90, 6, 170,
            127, 154, 144, 140, 61, 220, 131, 62, 165,
        ];

        println!("signature: {:?}", base64::encode(&signature));

        //let signature = Signature::from_bytes(&signature.).expect("Invalid signature");
        // Create a Signature object from the raw signature bytes
        let signature = Signature::from_der(&signature).expect("Invalid signature");

        //@todo
        // Verify the signature
        verifying_key
            .verify(sig_bytes, &signature)
            .unwrap_or_else(|e| {
                println!("Signature verification failed: {}", e);
                ()
            });

        //assert!(result, "Signature verification failed");
    }
}
