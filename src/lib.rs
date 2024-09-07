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

#![no_std]

pub mod aws_attestation {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use core::convert::TryInto;
    use p384::ecdsa::{Signature, SigningKey, VerifyingKey};
    use rand_core::RngCore;
    use rsa::signature::SignerMut;
    use rsa::signature::Verifier;
    // use std::collections::BTreeMap;
    // use std::io::Read;
    use x509_cert::der::Encode;
    use x509_cert::{der::Decode, Certificate};

    const DEFAULT_ENCLAVE_ENDPOINT: &str = "https://tlsn.eternis.ai/enclave/attestation";
    const DEFAULT_ROOT_CERT_PATH: &str = "src/aws_root.pem";

    pub fn authenticate(
        _protected: &[u8; 4],
        _signature: &[u8; 96],
        _payload: &[u8; 4448],
        _certificate: &[u8; 640],
    ) -> Result<(), p384::ecdsa::Error> {
        //@ok parse public key, convert from der to sec1 format
        let cert = x509_cert::Certificate::from_der(_certificate).expect("decode x509 cert failed");

        let public_key = cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .expect("public key der failed");

        //println!("public key der: {:?}", public_key.clone());
        //sec1 doesnt comprise der headers
        let public_key = &public_key[public_key.len() - 97..];
        //println!("public key sec1: {:?}", hex::encode(public_key));

        //@ok public key valid
        let verifying_key = VerifyingKey::from_sec1_bytes(&public_key).expect("Invalid public key");

        // Create a Signature object from the raw signature bytes
        let signature = Signature::from_slice(_signature).expect("Invalid signature");

        //@ok parse sign structure = message
        //correspond to Signature1D
        const HEADER: [u8; 13] = [132, 106, 83, 105, 103, 110, 97, 116, 117, 114, 101, 49, 68];
        let protected = _protected;
        //@todo sometimes last byte is 96 sometimes 95, need to figure out why
        const FILLER: [u8; 4] = [64, 89, 17, 96];
        let payload = _payload;

        let sign_structure = [
            HEADER.as_ref(),
            protected.as_ref(),
            FILLER.as_ref(),
            payload.as_ref(),
        ]
        .concat();

        //println!("pcrs: {:?}", document.pcrs);
        //@ok
        // Verify the signature
        verifying_key.verify(&sign_structure, &signature)
    }

    // fn parse(document_data: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
    //     let cbor: serde_cbor::Value = serde_cbor::from_slice(document_data)
    //         .map_err(|err| format!("AttestationVerifier::parse from_slice failed:{:?}", err))?;
    //     let elements = match cbor {
    //         serde_cbor::Value::Array(elements) => elements,
    //         _ => panic!("AttestationVerifier::parse Unknown field cbor:{:?}", cbor),
    //     };
    //     let protected = match &elements[0] {
    //         serde_cbor::Value::Bytes(prot) => prot,
    //         _ => panic!(
    //             "AttestationVerifier::parse Unknown field protected:{:?}",
    //             elements[0]
    //         ),
    //     };
    //     let _unprotected = match &elements[1] {
    //         serde_cbor::Value::Map(unprot) => unprot,
    //         _ => panic!(
    //             "AttestationVerifier::parse Unknown field unprotected:{:?}",
    //             elements[1]
    //         ),
    //     };
    //     let payload = match &elements[2] {
    //         serde_cbor::Value::Bytes(payld) => payld,
    //         _ => panic!(
    //             "AttestationVerifier::parse Unknown field payload:{:?}",
    //             elements[2]
    //         ),
    //     };
    //     let signature = match &elements[3] {
    //         serde_cbor::Value::Bytes(sig) => sig,
    //         _ => panic!(
    //             "AttestationVerifier::parse Unknown field signature:{:?}",
    //             elements[3]
    //         ),
    //     };
    //     Ok((protected.to_vec(), payload.to_vec(), signature.to_vec()))
    // }
    // fn parse_payload(payload: &Vec<u8>) -> Result<AttestationDocument, String> {
    //     let document_data: serde_cbor::Value = serde_cbor::from_slice(payload.as_slice())
    //         .map_err(|err| format!("document parse failed:{:?}", err))?;
    //     let document_map: BTreeMap<serde_cbor::Value, serde_cbor::Value> = match document_data {
    //         serde_cbor::Value::Map(map) => map,
    //         _ => {
    //             return Err(format!(
    //                 "AttestationVerifier::parse_payload field ain't what it should be:{:?}",
    //                 document_data
    //             ))
    //         }
    //     };
    //     let module_id = match document_map.get(&serde_cbor::Value::Text(
    //         "module_id".try_into().expect("module_id_fail"),
    //     )) {
    //         Some(serde_cbor::Value::Text(val)) => val.to_string(),
    //         _ => {
    //             return Err(format!(
    //                 "AttestationVerifier::parse_payload module_id is wrong type or not present"
    //             ))
    //         }
    //     };
    //     let timestamp: i128 =
    //         match document_map.get(&serde_cbor::Value::Text("timestamp".to_string())) {
    //             Some(serde_cbor::Value::Integer(val)) => *val,
    //             _ => {
    //                 return Err(format!(
    //                     "AttestationVerifier::parse_payload timestamp is wrong type or not present"
    //                 ))
    //             }
    //         };
    //     let timestamp: u64 = timestamp.try_into().map_err(|err| {
    //         format!(
    //             "AttestationVerifier::parse_payload failed to convert timestamp to u64:{:?}",
    //             err
    //         )
    //     })?;
    //     let public_key: Option<Vec<u8>> =
    //         match document_map.get(&serde_cbor::Value::Text("public_key".to_string())) {
    //             Some(serde_cbor::Value::Bytes(val)) => Some(val.to_vec()),
    //             Some(_null) => None,
    //             None => None,
    //         };
    //     let certificate: Vec<u8> =
    //         match document_map.get(&serde_cbor::Value::Text("certificate".to_string())) {
    //             Some(serde_cbor::Value::Bytes(val)) => val.to_vec(),
    //             _ => {
    //                 return Err(format!(
    //                 "AttestationVerifier::parse_payload certificate is wrong type or not present"
    //             ))
    //             }
    //         };
    //     let pcrs: Vec<Vec<u8>> = match document_map
    //         .get(&serde_cbor::Value::Text("pcrs".to_string()))
    //     {
    //         Some(serde_cbor::Value::Map(map)) => {
    //             let mut ret_vec: Vec<Vec<u8>> = Vec::new();
    //             let num_entries:i128 = map.len().try_into()
    //                 .map_err(|err| format!("AttestationVerifier::parse_payload failed to convert pcrs len into i128:{:?}", err))?;
    //             for x in 0..num_entries {
    //                 match map.get(&serde_cbor::Value::Integer(x)) {
    //                     Some(serde_cbor::Value::Bytes(inner_vec)) => {
    //                         ret_vec.push(inner_vec.to_vec());
    //                     },
    //                     _ => return Err(format!("AttestationVerifier::parse_payload pcrs inner vec is wrong type or not there?")),
    //                 }
    //             }
    //             ret_vec
    //         }
    //         _ => {
    //             return Err(format!(
    //                 "AttestationVerifier::parse_payload pcrs is wrong type or not present"
    //             ))
    //         }
    //     };
    //     for (i, pcr) in pcrs.iter().enumerate() {
    //         let pcr_str = pcr.iter().map(|b| format!("{:02x}", b)).collect::<String>();
    //         // println!("PCR {}: {}", i, pcr_str);
    //     }
    //     let nonce: Option<Vec<u8>> =
    //         match document_map.get(&serde_cbor::Value::Text("nonce".to_string())) {
    //             Some(serde_cbor::Value::Bytes(val)) => Some(val.to_vec()),
    //             None => None,
    //             _ => {
    //                 return Err(format!(
    //                     "AttestationVerifier::parse_payload nonce is wrong type or not present"
    //                 ))
    //             }
    //         };
    //     println!("nonce:{:?}", nonce);
    //     let user_data: Option<Vec<u8>> =
    //         match document_map.get(&serde_cbor::Value::Text("user_data".to_string())) {
    //             Some(serde_cbor::Value::Bytes(val)) => Some(val.to_vec()),
    //             None => None,
    //             Some(_null) => None,
    //         };
    //     let digest: String = match document_map.get(&serde_cbor::Value::Text("digest".to_string()))
    //     {
    //         Some(serde_cbor::Value::Text(val)) => val.to_string(),
    //         _ => {
    //             return Err(format!(
    //                 "AttestationVerifier::parse_payload digest is wrong type or not present"
    //             ))
    //         }
    //     };
    //     let cabundle: Vec<Vec<u8>> =
    //         match document_map.get(&serde_cbor::Value::Text("cabundle".to_string())) {
    //             Some(serde_cbor::Value::Array(outer_vec)) => {
    //                 let mut ret_vec: Vec<Vec<u8>> = Vec::new();
    //                 for this_vec in outer_vec.iter() {
    //                     match this_vec {
    //                         serde_cbor::Value::Bytes(inner_vec) => {
    //                             ret_vec.push(inner_vec.to_vec());
    //                         }
    //                         _ => {
    //                             return Err(format!(
    //                                 "AttestationVerifier::parse_payload inner_vec is wrong type"
    //                             ))
    //                         }
    //                     }
    //                 }
    //                 ret_vec
    //             }
    //             _ => {
    //                 return Err(format!(
    //                 "AttestationVerifier::parse_payload cabundle is wrong type or not present:{:?}",
    //                 document_map.get(&serde_cbor::Value::Text("cabundle".to_string()))
    //             ))
    //             }
    //         };
    //     Ok(AttestationDocument {
    //         module_id: module_id,
    //         timestamp: timestamp,
    //         digest: digest,
    //         pcrs: pcrs,
    //         certificate: certificate,
    //         cabundle: cabundle,
    //         public_key: public_key,
    //         user_data: user_data,
    //         nonce: nonce,
    //     })
    // }
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

    //use rustls_pemfile::{certs, pkcs8_private_keys};

    #[cfg(test)]
    mod tests {

        use super::*;

        #[test]
        fn test_non_std() {
            let _protected: [u8; 4] = STANDARD
                .decode("oQE4Ig==")
                .expect("decode protected failed")
                .try_into()
                .expect("_protected slice with incorrect length");

            let _signature: [u8; 96] = STANDARD.decode("qE3P+ML3TW+s83KfRcpF4gFgZQXKkPGePqsxJm+R519w6QAxbNHDr8MZVykotcSojakIp5PdAUncFYDlVlcD48rE8uYjBiqY0ZJWbVFeinYdOEkwh6NllRRU6mR6oiwn")
                .expect("decode protected failed")
                .try_into()
                .expect("_signature slice with incorrect length");

            let _payload: [u8; 4448] = STANDARD.decode("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")
                .expect("decode protected failed")
                .try_into()
                .expect("_signature slice with incorrect length");

            let _certificate: [u8; 640] = STANDARD.decode("MIICfDCCAgGgAwIBAgIQAZG6NcnRt3oAAAAAZtteJzAKBggqhkjOPQQDAzCBjjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xEDAOBgNVBAcMB1NlYXR0bGUxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMTkwNwYDVQQDDDBpLTBiYmYxYmZlMjMyYjhjMmNlLnVzLWVhc3QtMS5hd3Mubml0cm8tZW5jbGF2ZXMwHhcNMjQwOTA2MTk1NTE2WhcNMjQwOTA2MjI1NTE5WjCBkzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xEDAOBgNVBAcMB1NlYXR0bGUxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMT4wPAYDVQQDDDVpLTBiYmYxYmZlMjMyYjhjMmNlLWVuYzAxOTFiYTM1YzlkMWI3N2EudXMtZWFzdC0xLmF3czB2MBAGByqGSM49AgEGBSuBBAAiA2IABPc9X/JjhQd9uvK6GFlkPiNMtkZI2Iy4KL4GfzKK07JRRIh9atGEuu1ByR5I9a9jt7FEnB8FBFr0EvAdg/90KfssfDr8J5csL4Rl0W2z/HPT1BO51sERz2SCv0YK7yquOaMdMBswDAYDVR0TAQH/BAIwADALBgNVHQ8EBAMCBsAwCgYIKoZIzj0EAwMDaQAwZgIxAKNWlT+MW4B0T00Awo0qHg3sE0Wu5dfDroi8XcffUKQW+oXPlvPv2UEcKNJMzo4kfwIxALXBNhVTEkzZlYWt3kQP319Yye5cJYzyVgUf0pKE6ABCl776birkytcNtSrORfGKqA==")
                .expect("decode protected failed")
                .try_into()
                .expect("_certfificate slice with incorrect length");

            let _ = authenticate(&_protected, &_signature, &_payload, &_certificate);
            //assert!(result, "Signature verification failed");
        }

        // #[test]
        // fn test_std() {
        //     //@ok parse CBOR doc
        //     //@note from url
        //     // let attestation_verifier = AttestationVerifier::new(None, None);
        //     // let nonce = "0000000000000000000000000000000000000001";
        //     // let document_data = attestation_verifier
        //     //     .fetch_attestation_document(nonce)
        //     //     .map_err(|err| format!("Failed to fetch attestation document: {:?}", err))
        //     //     .expect("Failed to fetch attestation document");
        //     //println!("document_data: {:?}", base64::encode(document_data.clone()));
        //     //@note from file, using STD though
        //     // let document_data = std::fs::read_to_string("src/example_attestation")
        //     //     .expect("Failed to read example_attestation file");
        //     // let document_data =
        //     //     STANDARD.decode(document_data.trim()).expect("Failed to decode base64 data");
        //     //@note from array, using STD functions as well
        //     let document_data = STANDARD.decode("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").expect("decode doc failed");
        //     let (_protected, payload, _signature) =
        //         parse(&document_data).expect("AttestationVerifier::authenticate parse failed");
        //     println!("_protected: {:?}", payload);
        //     println!("signature: {:?}", _signature);
        //     println!("_protected: {:?}", _protected);
        //     // Step 2. Exract the attestation document from the COSE_Sign1 structure
        //     let document =
        //         parse_payload(&payload).expect("AttestationVerifier::authenticate failed");
        //     //@ok parse public key, convert from der to sec1 format
        //     let cert = x509_cert::Certificate::from_der(&document.certificate).unwrap();
        //     let public_key = cert
        //         .tbs_certificate
        //         .subject_public_key_info
        //         .to_der()
        //         .expect("public key der failed");
        //     //println!("public key der: {:?}", public_key.clone());
        //     //sec1 doesnt comprise der headers
        //     let public_key = &public_key[public_key.len() - 97..];
        //     //println!("public key sec1: {:?}", hex::encode(public_key));
        //     //@ok public key valid
        //     let verifying_key =
        //         VerifyingKey::from_sec1_bytes(&public_key).expect("Invalid public key");
        //     //@ok signature valid
        //     //println!("signature: {:?}", _signature);
        //     //let signature = Signature::from_bytes(&signature.).expect("Invalid signature");
        //     // Create a Signature object from the raw signature bytes
        //     let signature = Signature::from_slice(&_signature).expect("Invalid signature");
        //     //@ok parse sig_bytes from doc
        //     //correspond to Signature1D
        //     let header = [132, 106, 83, 105, 103, 110, 97, 116, 117, 114, 101, 49, 68];
        //     let protected = _protected;
        //     //@todo sometimes last byte is 96 sometimes 95, need to figure out why
        //     let filler = [64, 89, 17, 96];
        //     let payload = payload;
        //     let sign_structure = [
        //         header.as_ref(),
        //         protected.as_ref(),
        //         filler.as_ref(),
        //         payload.as_ref(),
        //     ]
        //     .concat();
        //     //println!("pcrs: {:?}", document.pcrs);
        //     //@ok
        //     // Verify the signature
        //     verifying_key
        //         .verify(&sign_structure, &signature)
        //         .expect("Signature verification failed");
        //     //assert!(result, "Signature verification failed");
        // }
    }
}
