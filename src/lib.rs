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

            //println!("public_key_der: {:?}", public_key_der);
            let key: &dyn SigningPublicKey = public_key.as_ref();
            //println!("signature algorithm: {:?}", key.get_parameters().unwrap());

            let public_key_hex =
                hex::encode(public_key.public_key_to_der().map_err(|err| {
                    format!("Failed to convert public key to DER format: {:?}", err)
                })?);

            println!("Public Key (hex): {}", public_key_hex);
            // let pem = public_key
            //     .public_key_to_pem()
            //     .map_err(|err| format!("Failed to convert public key to PEM format: {:?}", err))?;
            // println!("PEM Public Key:\n{}", String::from_utf8(pem).unwrap());

            println!("Signature: {:?}", _signature);

            //print sig_structure
            //@test

            let payload = sig_structure
                .get_payload::<aws_nitro_enclaves_cose::crypto::Openssl>(None)
                .unwrap();

            // println!("payload: {:?}", payload);
            // println!("_protected: {:?}", _protected);
            let sig_structure_2 = SigStructure::new_sign1(&_protected, &payload).unwrap();
            let sig_structure_bytes = sig_structure_2.as_bytes().unwrap();
            println!("sig_structure_bytes: {:?}", sig_structure_bytes);
            use openssl::hash::{hash, MessageDigest};
            let struct_digest = hash(MessageDigest::sha384(), &sig_structure_bytes).unwrap();
            //println!("struct_digest: {:?}", &struct_digest);

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
    fn test_sig_es384_from_existing_key() {
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

        //@ok working with this signature (103 bytes)
        // has to be in DER format
        let signature = [
            48, 101, 2, 48, 75, 136, 137, 39, 57, 51, 129, 15, 197, 48, 50, 110, 247, 234, 120, 4,
            183, 63, 153, 199, 207, 110, 86, 131, 162, 85, 174, 241, 116, 53, 130, 85, 106, 80,
            212, 173, 62, 124, 160, 108, 186, 233, 51, 239, 14, 175, 145, 5, 2, 49, 0, 226, 186,
            133, 103, 119, 206, 234, 171, 29, 129, 184, 83, 239, 136, 242, 13, 9, 203, 225, 73,
            138, 144, 253, 118, 250, 186, 121, 119, 129, 246, 243, 80, 13, 13, 64, 215, 90, 6, 170,
            127, 154, 144, 140, 61, 220, 131, 62, 165,
        ];

        //let signature = Signature::from_bytes(&signature.).expect("Invalid signature");
        // Create a Signature object from the raw signature bytes
        let signature = Signature::from_der(&signature).expect("Invalid signature");

        //@ok
        verifying_key
            .verify(sig_bytes, &signature)
            .unwrap_or_else(|e| {
                println!("Signature verification failed: {}", e);
                ()
            });

        //assert!(result, "Signature verification failed");
    }

    #[test]
    fn test_sig_es384_from_doc() {
        //@ok parse CBOR doc
        let document_data = std::fs::read_to_string("src/example_attestation")
            .expect("Failed to read example_attestation file");
        let document_data =
            base64::decode(document_data.trim()).expect("Failed to decode base64 data");

        let (_protected, payload, _signature) = AttestationVerifier::parse(&document_data)
            .map_err(|err| format!("AttestationVerifier::authenticate parse failed:{:?}", err))
            .unwrap();

        // Step 2. Exract the attestation document from the COSE_Sign1 structure
        let document = AttestationVerifier::parse_payload(&payload)
            .map_err(|err| format!("AttestationVerifier::authenticate failed:{:?}", err))
            .unwrap();

        //@ok parse public key, convert from der to sec1 format
        let cert =   openssl::x509::X509::from_der(&document.certificate)
        .map_err(|err| {
            format!("AttestationVerifier::authenticate failed to parse document.certificate as X509 certificate:{:?}", err)
        }).unwrap();

        let cert = x509_cert::Certificate::from_der(&document.certificate).unwrap();

        let public_key = cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .unwrap();
        println!("public key der: {:?}", public_key.clone());
        //sec1 doesnt comprise der headers
        let public_key = &public_key[public_key.len() - 97..];
        println!("public key sec1: {:?}", hex::encode(public_key));

        //@ok public key valid
        let verifying_key = VerifyingKey::from_sec1_bytes(&public_key).expect("Invalid public key");

        //@ok signature valid
        println!("signature: {:?}", _signature);

        //let signature = Signature::from_bytes(&signature.).expect("Invalid signature");
        // Create a Signature object from the raw signature bytes
        let signature = Signature::from_slice(&_signature).expect("Invalid signature");

        //@todo parse sig_bytes from doc

        //correspond to Signature1D
        let header = vec![132, 106, 83, 105, 103, 110, 97, 116, 117, 114, 101, 49, 68];
        let protected = _protected;
        let filler = vec![64, 89, 17, 95];
        let payload = payload;

        println!("payload: {:?}", payload);
        println!("protected: {:?}", protected);

        let mut sign_structure = Vec::new();
        sign_structure.extend_from_slice(&header);
        sign_structure.extend_from_slice(&protected);
        sign_structure.extend_from_slice(&filler);
        sign_structure.extend_from_slice(&payload);

        let sign_structure: Vec<u8> = sign_structure;
        println!("sign_structure: {:?}", sign_structure);

        //@bug
        // Verify the signature
        verifying_key
            .verify(&sign_structure, &signature)
            .unwrap_or_else(|e| {
                println!("Signature verification failed: {}", e);
                ()
            });

        //assert!(result, "Signature verification failed");
    }
}
