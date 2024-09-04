package core_test

import (
	"encoding/json"
	"testing"

	"github.com/hyperledger-labs/jsonld-vc-bbs-go/internal/core"
	"github.com/hyperledger-labs/jsonld-vc-bbs-go/model"
	"github.com/stretchr/testify/suite"
)

type NormalizerTestSuite struct {
	suite.Suite
}

func TestNormalizerTestSuite(t *testing.T) {
	suite.Run(t, new(NormalizerTestSuite))
}

func (s *NormalizerTestSuite) TestProofNormalization() {
	subject := core.NewNormalizer(nil)

	unsignedProof := `{
		"@context": [
			"https://www.w3.org/2018/credentials/v1",
			"https://w3id.org/security/bbs/v1"
		],
		"type": "BbsBlsSignature2020",
		"created": "2024-07-24T11:49:36Z",
		"proofPurpose": "assertionMethod",
		"verificationMethod": "did:key:zUC73gNPc1EnZmDDjYJzE8Bk89VRhuZPQYXFnSiSUZvX9N1i7N5VtMbJyowDR46rtARHLJYRVf7WMbGLb43s9tfTyKF9KFF22vBjXZRomcwtoQJmMNUSY7tfzyhLEy58dwUz3WD#zUC73gNPc1EnZmDDjYJzE8Bk89VRhuZPQYXFnSiSUZvX9N1i7N5VtMbJyowDR46rtARHLJYRVf7WMbGLb43s9tfTyKF9KFF22vBjXZRomcwtoQJmMNUSY7tfzyhLEy58dwUz3WD"
	}`

	expected := []string{
		`_:c14n0 <http://purl.org/dc/terms/created> "2024-07-24T11:49:36Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .`,
		`_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#BbsBlsSignature2020> .`,
		`_:c14n0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .`,
		`_:c14n0 <https://w3id.org/security#verificationMethod> <did:key:zUC73gNPc1EnZmDDjYJzE8Bk89VRhuZPQYXFnSiSUZvX9N1i7N5VtMbJyowDR46rtARHLJYRVf7WMbGLb43s9tfTyKF9KFF22vBjXZRomcwtoQJmMNUSY7tfzyhLEy58dwUz3WD#zUC73gNPc1EnZmDDjYJzE8Bk89VRhuZPQYXFnSiSUZvX9N1i7N5VtMbJyowDR46rtARHLJYRVf7WMbGLb43s9tfTyKF9KFF22vBjXZRomcwtoQJmMNUSY7tfzyhLEy58dwUz3WD> .`,
	}

	actual, err := subject.Normalize(unsignedProof)
	s.NoError(err)
	s.Equal(expected, actual)
}

func (s *NormalizerTestSuite) TestCredentialNormalization() {
	var contextResidentCardV1 map[string]interface{}
	err := json.Unmarshal([]byte(contextResidentCardV1Json), &contextResidentCardV1)
	s.NoError(err)

	options := &model.SignatureSuiteOptions{
		Contexts: map[string]map[string]interface{}{
			"https://w3id.org/citizenship/v1": contextResidentCardV1,
		},
	}

	subject := core.NewNormalizer(options)

	var credentialJsonLD = `{
		"@context": [
			"https://www.w3.org/2018/credentials/v1",
			"https://w3id.org/citizenship/v1",
			"https://w3id.org/security/bbs/v1"
		],
		"id": "https://issuer.oidp.uscis.gov/credentials/83627465",
		"type": ["VerifiableCredential", "PermanentResidentCard"],
		"issuer": "did:key:zUC73gNPc1EnZmDDjYJzE8Bk89VRhuZPQYXFnSiSUZvX9N1i7N5VtMbJyowDR46rtARHLJYRVf7WMbGLb43s9tfTyKF9KFF22vBjXZRomcwtoQJmMNUSY7tfzyhLEy58dwUz3WD",
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
	}`

	expected := []string{
		`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <http://schema.org/birthDate> "1990-11-22"^^<http://www.w3.org/2001/XMLSchema#dateTime> .`,
		`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <http://schema.org/familyName> "Bowen" .`,
		`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <http://schema.org/gender> "Male" .`,
		`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <http://schema.org/givenName> "Jace" .`,
		`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .`,
		`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#PermanentResident> .`,
		`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <https://w3id.org/citizenship#birthCountry> "Bahamas" .`,
		`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <https://w3id.org/citizenship#lprCategory> "C09" .`,
		`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <https://w3id.org/citizenship#lprNumber> "223-45-198" .`,
		`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <https://w3id.org/citizenship#residentSince> "2015-01-01"^^<http://www.w3.org/2001/XMLSchema#dateTime> .`,
		`<https://issuer.oidp.uscis.gov/credentials/83627465> <http://schema.org/name> "Permanent Resident Card" .`,
		`<https://issuer.oidp.uscis.gov/credentials/83627465> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#PermanentResidentCard> .`,
		`<https://issuer.oidp.uscis.gov/credentials/83627465> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .`,
		`<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#credentialSubject> <did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> .`,
		`<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#expirationDate> "2029-12-03T12:19:52Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .`,
		`<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#issuanceDate> "2019-12-03T12:19:52Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .`,
		`<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#issuer> <did:key:zUC73gNPc1EnZmDDjYJzE8Bk89VRhuZPQYXFnSiSUZvX9N1i7N5VtMbJyowDR46rtARHLJYRVf7WMbGLb43s9tfTyKF9KFF22vBjXZRomcwtoQJmMNUSY7tfzyhLEy58dwUz3WD> .`,
	}

	actual, err := subject.Normalize(credentialJsonLD)
	s.NoError(err)
	s.Equal(expected, actual)
}

var contextResidentCardV1Json = `{
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
    "Person": "http://schema.org/Person"
  }
}`
