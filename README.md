# Verifier for AWS nitro enclave attestation

Verify AWS Nitro Enclave Attestation Documents with this minimal crate that works without using std library.
This makes this crate suitable for running in a WebAssembly environment.

## How verification works

Nitro enclave returns an AWS signed certificate.
To be valid an attestation document must have a valid certificate (verified against AWS root certificate), the certificate must not be expired, and the PCR values must correspond to the expect values.

If PCR values are zeroes it's probably because the nitro enclave is running in debug mode.

## How to test

Retrieve an attestation document from your nitro enclave running nitriding daemon by querying /enclave/attestation endpoint.

See here: https://github.com/brave/nitriding-daemon/blob/master/doc/http-api.md

## More docs on AWS Nitro Enclaves and Attestation Documents

What are AWS Nitro Enclaves? Here's some info: https://aws.amazon.com/ec2/nitro/nitro-enclaves/

Also, what are AWS Nitro Enclave Attestation Documents? Here's some more info: https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html

and here's some more: https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html

Now that you've read every word on those links (yeah, right), here's how to use this crate.

You should fetch the AWS Nitro Root Certificate from this link here: https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip

That link gives you the certificate in PEM format. The `authenticate` function above requires the certificate in DER format. Converting from PEM to DER is left as an exercise for the reader.

This crate is intended for use from rust projects. If you need support in another language, that is mostly left up to the reader. However, we have also implemented this functionality for the go programming language, available here: https://github.com/veracruz-project/go-nitro-enclave-attestation-document
