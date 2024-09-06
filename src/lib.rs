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

pub mod aws_attestation {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use hex;
    use reqwest;
    use std::collections::BTreeMap;
    use std::convert::TryInto;
    use x509_cert::{der::Decode, Certificate};

    const DEFAULT_ENCLAVE_ENDPOINT: &str = "https://tlsn.eternis.ai/enclave/attestation";
    const DEFAULT_ROOT_CERT_PATH: &str = "src/aws_root.pem";

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

    pub fn authenticate() -> Result<(), ()> {
        Ok(())
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

    //     base64::decode(decoded_response.trim())
    //         .map_err(|e| format!("Failed to decode base64: {}", e))
    // }

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
        fn test_sig_es384_from_newkey() {
            let mut rng = OsRng;
            let mut rand_bytes = [0u8; 32];
            rng.fill_bytes(&mut rand_bytes);

            // // Generate a new signing key
            // let mut signing_key: SigningKey = SigningKey::random(&mut rng);

            let bytes = [
                128, 30, 145, 80, 235, 100, 39, 24, 33, 47, 98, 31, 233, 19, 212, 38, 71, 80, 189,
                104, 183, 3, 34, 212, 91, 178, 86, 230, 133, 233, 255, 135, 91, 109, 240, 12, 140,
                134, 201, 30, 122, 116, 254, 172, 12, 178, 62, 17,
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
            // println!(
            //     "verifying_key: {:?}",
            //     hex::encode(verifying_key.to_sec1_bytes())
            // );
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
            // println!(
            //     " public key: {:?}",
            //     hex::encode(verifying_key.to_sec1_bytes())
            // );

            //@ok working with this signature (103 bytes)
            // has to be in DER format
            let signature = [
                48, 101, 2, 48, 75, 136, 137, 39, 57, 51, 129, 15, 197, 48, 50, 110, 247, 234, 120,
                4, 183, 63, 153, 199, 207, 110, 86, 131, 162, 85, 174, 241, 116, 53, 130, 85, 106,
                80, 212, 173, 62, 124, 160, 108, 186, 233, 51, 239, 14, 175, 145, 5, 2, 49, 0, 226,
                186, 133, 103, 119, 206, 234, 171, 29, 129, 184, 83, 239, 136, 242, 13, 9, 203,
                225, 73, 138, 144, 253, 118, 250, 186, 121, 119, 129, 246, 243, 80, 13, 13, 64,
                215, 90, 6, 170, 127, 154, 144, 140, 61, 220, 131, 62, 165,
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

            //@note from url
            // let attestation_verifier = AttestationVerifier::new(None, None);
            // let nonce = "0000000000000000000000000000000000000001";

            // let document_data = attestation_verifier
            //     .fetch_attestation_document(nonce)
            //     .map_err(|err| format!("Failed to fetch attestation document: {:?}", err))
            //     .expect("Failed to fetch attestation document");

            //println!("document_data: {:?}", base64::encode(document_data.clone()));

            //@note from file, using STD though
            // let document_data = std::fs::read_to_string("src/example_attestation")
            //     .expect("Failed to read example_attestation file");
            // let document_data =
            //     base64::decode(document_data.trim()).expect("Failed to decode base64 data");

            //@note from array
            let document_data = base64::decode("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").expect("decode doc failed");
            let (_protected, payload, _signature) = parse(&document_data)
                .map_err(|err| "AttestationVerifier::authenticate parse failed")
                .unwrap();

            // Step 2. Exract the attestation document from the COSE_Sign1 structure
            let document = parse_payload(&payload)
                .map_err(|err| "AttestationVerifier::authenticate failed")
                .unwrap();

            //@ok parse public key, convert from der to sec1 format
            let cert = x509_cert::Certificate::from_der(&document.certificate).unwrap();

            let public_key = cert
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .unwrap();

            //println!("public key der: {:?}", public_key.clone());
            //sec1 doesnt comprise der headers
            let public_key = &public_key[public_key.len() - 97..];
            //println!("public key sec1: {:?}", hex::encode(public_key));

            //@ok public key valid
            let verifying_key =
                VerifyingKey::from_sec1_bytes(&public_key).expect("Invalid public key");

            //@ok signature valid
            //println!("signature: {:?}", _signature);

            //let signature = Signature::from_bytes(&signature.).expect("Invalid signature");
            // Create a Signature object from the raw signature bytes
            let signature = Signature::from_slice(&_signature).expect("Invalid signature");

            //@ok parse sig_bytes from doc

            //correspond to Signature1D
            let header = [132, 106, 83, 105, 103, 110, 97, 116, 117, 114, 101, 49, 68];
            let protected = _protected;
            //@todo sometimes last byte is 96 sometimes 95, need to figure out why
            let filler = [64, 89, 17, 96];
            let payload = payload;

            let sign_structure = [
                header.as_ref(),
                protected.as_ref(),
                filler.as_ref(),
                payload.as_ref(),
            ]
            .concat();

            // let mut sign_structure = Vec::new();
            // sign_structure.extend_from_slice(&header);
            // sign_structure.extend_from_slice(&protected);
            // sign_structure.extend_from_slice(&filler);
            // sign_structure.extend_from_slice(&payload);

            // let sign_structure: Vec<u8> = sign_structure;
            //println!("sign_structure: {:?}", sign_structure);

            //println!("pcrs: {:?}", document.pcrs);
            //@ok
            // Verify the signature
            verifying_key.verify(&sign_structure, &signature).unwrap();

            //assert!(result, "Signature verification failed");
        }
    }
}
