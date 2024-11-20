package main

import (
	"encoding/hex"
	"encoding/json"
	"log"

	jsonldbbs "github.com/hyperledger-labs/jsonld-vc-bbs-go"
	"github.com/hyperledger-labs/jsonld-vc-bbs-go/model"
)

func main() {
	blsPublicKeyHex := "98ae11750ca7abb2e8ad1a9e55bc7226c5475a961f2bf4867285be12a519f6ddb5671f999ffd0f3ee6a6b2ea16f6cfa90086c14307bfc4e8e07d9c703603177e96874d8cba268d6d01a34cd8b418a4ffcc3ce5376b339d049cadeba06f959399"
	blsPrivateKeyHex := "13e86bd1a774b4609108a920c2886394e76c8db8502fbc380d1a21f8be835cef"

	publicKey, _ := hex.DecodeString(blsPublicKeyHex)
	privateKey, _ := hex.DecodeString(blsPrivateKeyHex)

	sampleUnsignedCred := `{
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

	sampleFrame := `{
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://w3id.org/citizenship/v1",
      "https://w3id.org/security/bbs/v1"
    ],
    "type": ["VerifiableCredential", "PermanentResidentCard"],
    "issuer": {},
    "issuanceDate": {},
    "credentialSubject": {
      "@explicit": true,
      "type": ["PermanentResident", "Person"],
      "birthDate": {}
    },
    "@explicit": true
  }
  `

	var unsignedCred model.JsonLdCredentialNoProof
	err := json.Unmarshal([]byte(sampleUnsignedCred), &unsignedCred)
	if err != nil {
		log.Fatalf("Error %s", err.Error())
	}

	// sign JSON-LD credential
	issuerSuite := jsonldbbs.NewJsonLDBBSSignatureSuite2020(publicKey, privateKey, nil)
	signedCred, serializedSignedCred, err := issuerSuite.Sign(unsignedCred)
	if err != nil {
		log.Fatalf("Error %s", err.Error())
	}
	log.Printf("Signed credential: %s\n", serializedSignedCred)

	// very JSON-LD credential
	verificationSuite := jsonldbbs.NewJsonLDBBSSignatureSuite2020(publicKey, nil, nil)
	result := verificationSuite.Verify(signedCred)
	if !result.Success {
		log.Fatalf("Error %s", result.Error.Error())
	}

	// read frame
	var frameDocument model.JsonLdFrame
	err = json.Unmarshal([]byte(sampleFrame), &frameDocument)
	if err != nil {
		log.Fatalf("Error %s", err.Error())
	}

	// selectively disclose credential
	sigProofSuite := jsonldbbs.NewJsonLDBBSSignatureProofSuite2020(publicKey, nil)
	proof, err := sigProofSuite.DeriveProof(signedCred, frameDocument, []byte("nonce"))
	if err != nil {
		log.Fatalf("Error %s", err.Error())
	}
	serializedProof, err := json.Marshal(proof)
	if err != nil {
		log.Fatalf("Error %s", err.Error())
	}
	log.Printf("Selective disclosed credential: %s\n", serializedProof)

	// verify disclosed credential
	result = sigProofSuite.VerifyProof(proof)
	if !result.Success {
		log.Fatalf("Error %s", result.Error.Error())
	}

	log.Println("All verified!")
}
