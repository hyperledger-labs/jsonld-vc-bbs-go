# jsonld-vc-bbs-go

`jsonld-vc-bbs-go` is a go module that can be used to implement the issuance, verification and selective disclosure of `BbsBlsSignature2020` W3C JSON-LD verifiable credentials.

## Table of Contents <!-- omit in toc -->

- [Description](#description)
- [How to use](#how-to-use)
  - [Usage example](#usage-example)
  - [Suites](#suites)
    - [SignatureSuite2020](#signaturesuite2020)
    - [SignatureProofSuite2020](#signatureproofsuite2020)
  - [Additional contexts](#additional-contexts)
- [Contributing](#contributing)

## Description

In the space of Digital Identity, W3C has defined a [mature standard](https://www.w3.org/TR/vc-di-bbs/) for BBS+ signed Verifiable Credentials in the format of JSON-LD (i.e. _JSON Linked-Data_).

The advantage of BBS+ credentials is mainly on the privacy side:

- they natively support selective disclosure;
- they achieve unlinkability between different presentations.

Therefore, they can be used in contexts where the privacy requirement is very sensitive.

## How to use

To add this module within your go project, run:

```shell
go get github.com/hyperledger-labs/jsonld-vc-bbs-go
```

### Usage example

A usage example can be found in this [main.go](./example/main.go). You can execute it by running:

```shell
go run example/main.go
```

### Suites

The library exposes 2 suites:

- `SignatureSuite2020`: suite to use to sign and verify a JSON-LD credential with a BBS+ keypair;
- `SignatureProofSuite2020`: suite to use to perform selective disclosure of a BBS+ JSON-LD credential.

#### SignatureSuite2020

The `SignatureSuite2020` presents the following interface:

```go
// Sign a JSON-LD credential
func (s *SignatureSuite2020) Sign(credential model.JsonLdCredentialNoProof) (model.JsonLdCredential, string, error)

// Verify a BBS+ JSON-LD credential
func (s *SignatureSuite2020) Verify(credential model.JsonLdCredential) *model.VerificationResult
```

#### SignatureProofSuite2020

The `SignatureProofSuite2020` presents the following interface:

```go
// Derive a selective disclosure proof from a BBS+ JSON-LD credential
func (s *SignatureProofSuite2020) DeriveProof(signedCredential model.JsonLdCredential, frameDocument model.JsonLdFrame, nonceBytes []byte) (model.JsonLdCredential, error)

// Verify a selective disclosure proof
func (s *SignatureProofSuite2020) VerifyProof(signedCredential model.JsonLdCredential) *model.VerificationResult
```

### Additional contexts

The library comes with some preloaded JSON-LD [contexts](./internal/context/). In case your credential requires additional context to use, you can pass it as follows:

```go
options := &model.SignatureSuiteOptions{
  Contexts: map[string]map[string]interface{}{
    "https://w3id.org/mycontext/v1": mycontextV1, // additional context
  },
}

issuerSuite := jsonldbbs.NewJsonLDBBSSignatureSuite(ipbBytes, iskBytes, options)
```

## Contributing

Any contribution is welcome. Here a list of the next steps to achieve:

- [ ] [**bbs-2023**](https://www.w3.org/TR/vc-di-bbs/) suite implementation;
- [ ] **Blind issuance** of the credential;
- [ ] **Unblinding** of blindly issued credential.
