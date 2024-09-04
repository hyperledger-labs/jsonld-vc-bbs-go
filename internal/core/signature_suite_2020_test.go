package core_test

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	c "github.com/hyperledger-labs/jsonld-vc-bbs-go/constants"
	"github.com/hyperledger-labs/jsonld-vc-bbs-go/internal/core"
	"github.com/hyperledger-labs/jsonld-vc-bbs-go/model"
	"github.com/stretchr/testify/suite"
)

type SignatureSuite2020TestSuite struct {
	suite.Suite
	options *model.SignatureSuiteOptions
}

func TestSignatureSuiteTestSuite(t *testing.T) {
	suite.Run(t, new(SignatureSuite2020TestSuite))
}

func (s *SignatureSuite2020TestSuite) SetupTest() {
	var contextResidentCardV1 map[string]interface{}
	err := json.Unmarshal([]byte(ContextResidentCustomCardV1JSON), &contextResidentCardV1)
	s.NoError(err)

	s.options = &model.SignatureSuiteOptions{
		Contexts: map[string]map[string]interface{}{
			"https://w3id.org/citizenship/v1": contextResidentCardV1,
		},
	}

}

func (s *SignatureSuite2020TestSuite) TestSignatureCreation() {
	blsPublicKeyHex := "98ae11750ca7abb2e8ad1a9e55bc7226c5475a961f2bf4867285be12a519f6ddb5671f999ffd0f3ee6a6b2ea16f6cfa90086c14307bfc4e8e07d9c703603177e96874d8cba268d6d01a34cd8b418a4ffcc3ce5376b339d049cadeba06f959399"
	blsPrivateKeyHex := "13e86bd1a774b4609108a920c2886394e76c8db8502fbc380d1a21f8be835cef"

	publicKey, _ := hex.DecodeString(blsPublicKeyHex)
	privateKey, _ := hex.DecodeString(blsPrivateKeyHex)

	var docToSign model.JsonLDCredentialNoProof
	err := json.Unmarshal([]byte(documentNoSignature), &docToSign)
	s.NoError(err)

	subject := core.NewSignatureSuite2020(publicKey, privateKey, s.options)
	_, jsonCredential, err := subject.Sign(docToSign)
	s.NoError(err)

	// verify signature
	var signedCredential model.JsonLDCredential
	err = json.Unmarshal([]byte(jsonCredential), &signedCredential)
	s.NoError(err)

	subject = core.NewSignatureSuite2020(publicKey, nil, s.options)
	actualResult := subject.Verify(signedCredential)

	expectedResult := &model.VerificationResult{
		Success: true,
	}

	s.Equal(expectedResult, actualResult)
}

func (s *SignatureSuite2020TestSuite) TestUnhappyVerification() {
	blsPublicKeyHex := "98ae11750ca7abb2e8ad1a9e55bc7226c5475a961f2bf4867285be12a519f6ddb5671f999ffd0f3ee6a6b2ea16f6cfa90086c14307bfc4e8e07d9c703603177e96874d8cba268d6d01a34cd8b418a4ffcc3ce5376b339d049cadeba06f959399"
	publicKey, _ := hex.DecodeString(blsPublicKeyHex)
	// verify signature
	var signedCredential model.JsonLDCredential
	err := json.Unmarshal([]byte(documentWithSignature), &signedCredential)
	s.NoError(err)

	wrongSignatureValue := "g4MtdbRIz1gRaYshWf1EZprwNYxSHh40nVUgaZdmdPMLfTOwWl0jUeBg7ah5quGuGQvNcBWKdVdvxnk94fb0rjBREvX67YLwGxJQL2dt1GBd2tkxw4P1Qk9l3XcQfdxII1O5ywgX3VhwZxJcdNn6Zw=="

	signedCredential[c.CredentialFieldProof].(map[string]interface{})[c.CredentialFieldProofValue] = wrongSignatureValue

	subject := core.NewSignatureSuite2020(publicKey, nil, s.options)
	actaulResult := subject.Verify(signedCredential)

	expectedResult := &model.VerificationResult{
		Success: false,
		Error:   fmt.Errorf("signature verification failed: 'invalid BLS12-381 signature'"),
	}

	s.Equal(expectedResult, actaulResult)
}

func (s *SignatureSuite2020TestSuite) TestProvisionOfVerificationData() {
	blsPublicKeyHex := "98ae11750ca7abb2e8ad1a9e55bc7226c5475a961f2bf4867285be12a519f6ddb5671f999ffd0f3ee6a6b2ea16f6cfa90086c14307bfc4e8e07d9c703603177e96874d8cba268d6d01a34cd8b418a4ffcc3ce5376b339d049cadeba06f959399"
	publicKey, _ := hex.DecodeString(blsPublicKeyHex)

	var document model.JsonLDCredential
	err := json.Unmarshal([]byte(documentWithSignature), &document)
	s.NoError(err)

	subject := core.NewSignatureSuite2020(publicKey, nil, s.options)
	actualDataBytes, err := subject.ProvideSigningData(document)

	expectedDataBytes := [][]byte{
		[]byte(`_:c14n0 <http://purl.org/dc/terms/created> "2024-09-04T12:01:57Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .`),
		[]byte(`_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#BbsBlsSignature2020> .`),
		[]byte(`_:c14n0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .`),
		[]byte(`_:c14n0 <https://w3id.org/security#verificationMethod> <did:key:zUC79S2TyLyjJmuMoac1q26XtCzhkTtywMo6DLRt5K9jgsCreBQ2NEYd5MZVHy8HZC39qEQ1gSZo2L4zXukMDhtWbCskzy3AZqjzQfdkixtxa2qE8unKXzvHMgE9PDQQEqKytkG#zUC79S2TyLyjJmuMoac1q26XtCzhkTtywMo6DLRt5K9jgsCreBQ2NEYd5MZVHy8HZC39qEQ1gSZo2L4zXukMDhtWbCskzy3AZqjzQfdkixtxa2qE8unKXzvHMgE9PDQQEqKytkG> .`),
		[]byte(`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <customcard:customdata> _:c14n0 .`),
		[]byte(`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <http://schema.org/birthDate> "1990-11-22"^^<http://www.w3.org/2001/XMLSchema#dateTime> .`),
		[]byte(`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <http://schema.org/familyName> "Bowen" .`),
		[]byte(`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <http://schema.org/gender> "Male" .`),
		[]byte(`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <http://schema.org/givenName> "Jace" .`),
		[]byte(`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <customcard:MyType> .`),
		[]byte(`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .`),
		[]byte(`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#PermanentResident> .`),
		[]byte(`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <https://w3id.org/citizenship#birthCountry> "Bahamas" .`),
		[]byte(`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <https://w3id.org/citizenship#lprCategory> "C09" .`),
		[]byte(`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <https://w3id.org/citizenship#lprNumber> "223-45-198" .`),
		[]byte(`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <https://w3id.org/citizenship#residentSince> "2015-01-01"^^<http://www.w3.org/2001/XMLSchema#dateTime> .`),
		[]byte(`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <https://w3id.org/vdl#portraitMetadata> "{\"hash\":\"de701215430a0c4f940ffe830efd27f54cae0d9655d78dc3849272e7641c05eedd066588345caf9d4181d9f325e73a9950a967d6fe766a4a62e02876e73255ad\",\"key\":\"aab053a5e11e3360679ce1a42c7733063843854a1002c19186743d7432a2e467\",\"link\":\"https://registry.metadata/object/70a62792-eb95-4491-a77f-e53dde8034fb\"}"^^<http://www.w3.org/1999/02/22-rdf-syntax-ns#JSON> .`),
		[]byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <http://schema.org/name> "Permanent Resident Card" .`),
		[]byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#PermanentResidentCard> .`),
		[]byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .`),
		[]byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#credentialSubject> <did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> .`),
		[]byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#expirationDate> "2029-12-03T12:19:52Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .`),
		[]byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#issuanceDate> "2019-12-03T12:19:52Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .`),
		[]byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#issuer> <did:key:zUC79S2TyLyjJmuMoac1q26XtCzhkTtywMo6DLRt5K9jgsCreBQ2NEYd5MZVHy8HZC39qEQ1gSZo2L4zXukMDhtWbCskzy3AZqjzQfdkixtxa2qE8unKXzvHMgE9PDQQEqKytkG> .`),
		[]byte(`_:c14n0 <customdata:1_usk> "chgA6VtGQeRd/0rf1P6fCFm8t7ZU1Q8eMPM/+E9gsw8=" .`),
	}
	s.NoError(err)
	s.Equal(expectedDataBytes, actualDataBytes)

	// verify that input document was not modified in previous operations
	var expectedDocument model.JsonLDCredential
	err = json.Unmarshal([]byte(documentWithSignature), &expectedDocument)
	s.NoError(err)

	s.Equal(expectedDocument, document)
}

var ContextResidentCustomCardV1JSON = `{
  "@context": {
    "@version": 1.1,
    "@protected": true,
    "name": "http://schema.org/name",
    "description": "http://schema.org/description",
    "identifier": "http://schema.org/identifier",
    "image": {
      "@id": "http://schema.org/image",
      "@type": "@id"
    },
    "PermanentResidentCard": {
      "@id": "https://w3id.org/citizenship#PermanentResidentCard",
      "@context": {
        "@version": 1.1,
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "description": "http://schema.org/description",
        "name": "http://schema.org/name",
        "identifier": "http://schema.org/identifier",
        "image": {
          "@id": "http://schema.org/image",
          "@type": "@id"
        }
      }
    },
    "PermanentResident": {
      "@id": "https://w3id.org/citizenship#PermanentResident",
      "@context": {
        "@version": 1.1,
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "ctzn": "https://w3id.org/citizenship#",
        "schema": "http://schema.org/",
        "xsd": "http://www.w3.org/2001/XMLSchema#",
        "birthCountry": "ctzn:birthCountry",
        "birthDate": {
          "@id": "schema:birthDate",
          "@type": "xsd:dateTime"
        },
        "commuterClassification": "ctzn:commuterClassification",
        "familyName": "schema:familyName",
        "gender": "schema:gender",
        "givenName": "schema:givenName",
        "lprCategory": "ctzn:lprCategory",
        "lprNumber": "ctzn:lprNumber",
        "residentSince": {
          "@id": "ctzn:residentSince",
          "@type": "xsd:dateTime"
        },
        "portraitMetadata": {
          "@id": "https://w3id.org/vdl#portraitMetadata",
          "@type": "@json"
        }
      }
    },
    "Person": "http://schema.org/Person",
    "MyType": {
      "@id": "customcard:MyType",
      "@context": {
        "@version": 1.1,
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "customdata": {
          "@id": "customcard:customdata",
          "@context": {
            "@version": 1.1,
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "usk": "customdata:1_usk"
          }
        }
      }
    }
  }
}
`

var documentNoSignature = `{
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
    "type": ["PermanentResident", "Person", "MyType"],
    "givenName": "Jace",
    "familyName": "Bowen",
    "gender": "Male",
    "residentSince": "2015-01-01",
    "lprCategory": "C09",
    "lprNumber": "223-45-198",
    "birthCountry": "Bahamas",
    "birthDate": "1990-11-22",
    "portraitMetadata": {
      "link": "https://registry.metadata/object/70a62792-eb95-4491-a77f-e53dde8034fb",
      "key": "aab053a5e11e3360679ce1a42c7733063843854a1002c19186743d7432a2e467",
      "hash": "de701215430a0c4f940ffe830efd27f54cae0d9655d78dc3849272e7641c05eedd066588345caf9d4181d9f325e73a9950a967d6fe766a4a62e02876e73255ad"
    },
    "customdata": {
      "usk": "chgA6VtGQeRd/0rf1P6fCFm8t7ZU1Q8eMPM/+E9gsw8="
    }
  }
}`

var documentWithSignature = `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/citizenship/v1",
    "https://w3id.org/security/bbs/v1"
  ],
  "type": [
    "VerifiableCredential",
    "PermanentResidentCard"
  ],
  "expirationDate": "2029-12-03T12:19:52Z",
  "id": "https://issuer.oidp.uscis.gov/credentials/83627465",
  "issuanceDate": "2019-12-03T12:19:52Z",
  "issuer": "did:key:zUC79S2TyLyjJmuMoac1q26XtCzhkTtywMo6DLRt5K9jgsCreBQ2NEYd5MZVHy8HZC39qEQ1gSZo2L4zXukMDhtWbCskzy3AZqjzQfdkixtxa2qE8unKXzvHMgE9PDQQEqKytkG",
  "name": "Permanent Resident Card",
  "credentialSubject": {
    "birthCountry": "Bahamas",
    "birthDate": "1990-11-22",
    "customdata": {
      "usk": "chgA6VtGQeRd/0rf1P6fCFm8t7ZU1Q8eMPM/+E9gsw8="
    },
    "familyName": "Bowen",
    "gender": "Male",
    "givenName": "Jace",
    "id": "did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e",
    "lprCategory": "C09",
    "lprNumber": "223-45-198",
    "portraitMetadata": {
      "hash": "de701215430a0c4f940ffe830efd27f54cae0d9655d78dc3849272e7641c05eedd066588345caf9d4181d9f325e73a9950a967d6fe766a4a62e02876e73255ad",
      "key": "aab053a5e11e3360679ce1a42c7733063843854a1002c19186743d7432a2e467",
      "link": "https://registry.metadata/object/70a62792-eb95-4491-a77f-e53dde8034fb"
    },
    "residentSince": "2015-01-01",
    "type": [
      "PermanentResident",
      "Person",
      "MyType"
    ]
  },
  "proof": {
    "type": "BbsBlsSignature2020",
    "created": "2024-09-04T12:01:57Z",
    "proofPurpose": "assertionMethod",
    "verificationMethod": "did:key:zUC79S2TyLyjJmuMoac1q26XtCzhkTtywMo6DLRt5K9jgsCreBQ2NEYd5MZVHy8HZC39qEQ1gSZo2L4zXukMDhtWbCskzy3AZqjzQfdkixtxa2qE8unKXzvHMgE9PDQQEqKytkG#zUC79S2TyLyjJmuMoac1q26XtCzhkTtywMo6DLRt5K9jgsCreBQ2NEYd5MZVHy8HZC39qEQ1gSZo2L4zXukMDhtWbCskzy3AZqjzQfdkixtxa2qE8unKXzvHMgE9PDQQEqKytkG",
    "proofValue": "g4Ti+S46CqfJ28VNVwZqToFxR/omqo1Ti1IHg6OPT5pIEMsjDX3S224rLteFcSvwYgqu6YcmHLH6uwQGhbZZ72z+ViGTWaGy5Zz1mF8kT4NJIIIYm67M7JyZPvmgipkifg6EBb0fs5vG8hBQE9nyDA=="
  }
}`
