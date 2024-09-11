# Go implementation of signature suite for JSON-LD BbsBlsSignature2020 Credentials

This package uses pure Golang to implement issuance and verification of BbsBlsSignature2020 W3C Credentials.

## Table of Contents <!-- omit in toc -->

- [How to use](#how-to-use)
- [Additional contexts](#additional-contexts)

## How to use

```go
package main

import (
 "encoding/hex"
 "encoding/json"
 "fmt"
 "log"

 jsonldbbs "github.com/hyperledger-labs/jsonld-vc-bbs-go"
 "github.com/hyperledger-labs/jsonld-vc-bbs-go/model"
)

func main() {
 blsPublicKeyHex := "98ae11750ca7abb2e8ad1a9e55bc7226c5475a961f2bf4867285be12a519f6ddb5671f999ffd0f3ee6a6b2ea16f6cfa90086c14307bfc4e8e07d9c703603177e96874d8cba268d6d01a34cd8b418a4ffcc3ce5376b339d049cadeba06f959399"
 blsPrivateKeyHex := "13e86bd1a774b4609108a920c2886394e76c8db8502fbc380d1a21f8be835cef"

 publicKey, _ := hex.DecodeString(blsPublicKeyHex)
 privateKey, _ := hex.DecodeString(blsPrivateKeyHex)

 // how to use custom options look at examples in `./interna/core/signature_suite_2020_test.go`
 issuerSuite := jsonldbbs.NewJsonLDBBSSignatureSuite2020(publicKey, privateKey, nil)

 documentNoSignatureJson := `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/citizenship/v1",
    "https://w3id.org/security/bbs/v1"
  ],
  "id": "https://issuer.oidp.uscis.gov/credentials/83627465",
  "type": ["VerifiableCredential", "PermanentResidentCard"],
  "name": "Permanent Resident Card",
  "issuanceDate": "2019-12-03T12:19:52Z",
  "expirationDate": "2029-12-03T12:19:52Z",
  "credentialSubject": {
    "id": "did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e",
    "type": ["PermanentResident", "Person"],
    "givenName": "Jace",
    "familyName": "Bowen",
    "gender": "Male",
    "residentSince": "2015-01-01",
    "lprCategory": "C09",
    "lprNumber": "223-45-198",
    "birthCountry": "Bahamas",
    "birthDate": "1990-11-22"
  }
}
`

 var documentNoSignature model.JsonLdCredentialNoProof
 json.Unmarshal([]byte(documentNoSignatureJson), &documentNoSignature)
 credential, jsonDoc, err := issuerSuite.Sign(documentNoSignature)
 if err != nil {
  log.Fatalf("Error %s", err.Error())
 }

 fmt.Println(jsonDoc)

 // verificaionSuite requires only publicKey
 verificationSuite := jsonldbbs.NewJsonLDBBSSignatureSuite2020(publicKey, nil, nil)
 result := verificationSuite.Verify(credential)

 fmt.Println(result)
}
```

Example of a signed credential

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/citizenship/v1",
    "https://w3id.org/security/bbs/v1"
  ],
  "credentialSubject": {
    "birthCountry": "Bahamas",
    "birthDate": "1990-11-22",
    "familyName": "Bowen",
    "gender": "Male",
    "givenName": "Jace",
    "id": "did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e",
    "lprCategory": "C09",
    "lprNumber": "223-45-198",
    "residentSince": "2015-01-01",
    "type": ["PermanentResident", "Person"]
  },
  "expirationDate": "2029-12-03T12:19:52Z",
  "id": "https://issuer.oidp.uscis.gov/credentials/83627465",
  "issuanceDate": "2019-12-03T12:19:52Z",
  "issuer": "did:key:zUC79S2TyLyjJmuMoac1q26XtCzhkTtywMo6DLRt5K9jgsCreBQ2NEYd5MZVHy8HZC39qEQ1gSZo2L4zXukMDhtWbCskzy3AZqjzQfdkixtxa2qE8unKXzvHMgE9PDQQEqKytkG",
  "name": "Permanent Resident Card",
  "proof": {
    "type": "BbsBlsSignature2020",
    "created": "2024-09-04T10:09:18Z",
    "proofPurpose": "assertionMethod",
    "verificationMethod": "did:key:zUC79S2TyLyjJmuMoac1q26XtCzhkTtywMo6DLRt5K9jgsCreBQ2NEYd5MZVHy8HZC39qEQ1gSZo2L4zXukMDhtWbCskzy3AZqjzQfdkixtxa2qE8unKXzvHMgE9PDQQEqKytkG#zUC79S2TyLyjJmuMoac1q26XtCzhkTtywMo6DLRt5K9jgsCreBQ2NEYd5MZVHy8HZC39qEQ1gSZo2L4zXukMDhtWbCskzy3AZqjzQfdkixtxa2qE8unKXzvHMgE9PDQQEqKytkG",
    "proofValue": "oa++SXD46hp7HycuIjm0GVU06bxMVbv3pIZC4hU51QU7vz8DxmqruHTgRPuEvRIjJBwAWNOGNt7TOPFCdbZN29lXCYGEEdggmzhGQLCUSO5piII+rIeX7smDmRiRs0TrbT5Q8wZwBBon253H9qgFvQ=="
  },
  "type": ["VerifiableCredential", "PermanentResidentCard"]
}
```

## Additional contexts

There is option to use custom contexts for credentials

```go
// all necessary imports

options := &model.SignatureSuiteOptions{
  Contexts: map[string]map[string]interface{}{
    "https://w3id.org/mycontext/v1": mycontextV1,
  },
}

issuerSuite := jsonldbbs.NewJsonLDBBSSignatureSuite(ipbBytes, iskBytes, options)

// rest of the code
```

Planned functionality:

- [x] Signing and verification of json-ld credentials based on BbsBlsSignature2020
- [x] Generation of selective disclosure BbsBlsSignatureProof2020
- [x] Verification of selective disclosure BbsBlsSignatureProof2020
- [ ] bbs-2023 implementation suite
- [ ] Blind issuance of the credential
- [ ] Unbliding of blindly issued credential

All feature or pull requests are welcomed
