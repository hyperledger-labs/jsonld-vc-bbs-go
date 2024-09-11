package core_test

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/hyperledger-labs/jsonld-vc-bbs-go/internal/core"
	"github.com/hyperledger-labs/jsonld-vc-bbs-go/model"
	"github.com/stretchr/testify/suite"
)

type SignatureProofSuite2020TestSuite struct {
	suite.Suite
	options *model.SignatureSuiteOptions
}

func TestSignatureProofSuite2020TestSuite(t *testing.T) {
	suite.Run(t, new(SignatureProofSuite2020TestSuite))
}

func (s *SignatureProofSuite2020TestSuite) SetupTest() {
	var contextResidentCardV1 map[string]interface{}
	customResidentCardContextBytes, err := os.ReadFile("testdata/customResidentCardContext.json")
	s.NoError(err)
	err = json.Unmarshal(customResidentCardContextBytes, &contextResidentCardV1)
	s.NoError(err)

	s.options = &model.SignatureSuiteOptions{
		Contexts: map[string]map[string]interface{}{
			"https://w3id.org/citizenship/v1": contextResidentCardV1,
		},
	}
}

func (s *SignatureProofSuite2020TestSuite) TestCreateProofAndVerify() {
	blsPublicKeyHex := "98ae11750ca7abb2e8ad1a9e55bc7226c5475a961f2bf4867285be12a519f6ddb5671f999ffd0f3ee6a6b2ea16f6cfa90086c14307bfc4e8e07d9c703603177e96874d8cba268d6d01a34cd8b418a4ffcc3ce5376b339d049cadeba06f959399"
	publicKey, _ := hex.DecodeString(blsPublicKeyHex)
	subject := core.NewSignatureProofSuite2020(publicKey, s.options)

	nonceB64 := "4mmd5EVmGd0POg+/4M2l0A=="
	nonceBytes, _ := base64.StdEncoding.DecodeString(nonceB64)

	// retrieve signed credential
	var signedCredential model.JsonLdCredential
	signedCredentialBytes, err := os.ReadFile("testdata/signedCredential.json")
	s.NoError(err)
	err = json.Unmarshal(signedCredentialBytes, &signedCredential)
	s.NoError(err)

	// retrieve framed document
	var frameDocument model.JsonLdFrame
	frameBytes, err := os.ReadFile("testdata/frame.json")
	s.NoError(err)
	err = json.Unmarshal(frameBytes, &frameDocument)
	s.NoError(err)

	// derive the proof
	proof, err := subject.DeriveProof(signedCredential, frameDocument, nonceBytes)
	s.NoError(err)

	// check
	actualResult := subject.VerifyProof(proof)
	expectedResult := &model.VerificationResult{
		Success: true,
	}
	s.Equal(expectedResult, actualResult)
}

func (s *SignatureProofSuite2020TestSuite) TestCreateMultipleProofsAndVerify() {
	blsPublicKeyHex := "98ae11750ca7abb2e8ad1a9e55bc7226c5475a961f2bf4867285be12a519f6ddb5671f999ffd0f3ee6a6b2ea16f6cfa90086c14307bfc4e8e07d9c703603177e96874d8cba268d6d01a34cd8b418a4ffcc3ce5376b339d049cadeba06f959399"
	publicKey, _ := hex.DecodeString(blsPublicKeyHex)
	subject := core.NewSignatureProofSuite2020(publicKey, s.options)

	nonceB64 := "4mmd5EVmGd0POg+/4M2l0A=="
	nonceBytes, _ := base64.StdEncoding.DecodeString(nonceB64)

	// retrieve signed credential
	var signedCredential model.JsonLdCredential
	signedCredentialBytes, err := os.ReadFile("testdata/multipleSignedCredential.json")
	s.NoError(err)
	err = json.Unmarshal(signedCredentialBytes, &signedCredential)
	s.NoError(err)

	// retrieve framed document
	var frameDocument model.JsonLdFrame
	frameBytes, err := os.ReadFile("testdata/frame.json")
	s.NoError(err)
	err = json.Unmarshal(frameBytes, &frameDocument)
	s.NoError(err)

	// derive the proof
	proof, err := subject.DeriveProof(signedCredential, frameDocument, nonceBytes)
	s.NoError(err)

	// check
	actualResult := subject.VerifyProof(proof)
	expectedResult := &model.VerificationResult{
		Success: true,
	}
	s.Equal(expectedResult, actualResult)
}

func (s *SignatureProofSuite2020TestSuite) TestVerifyProof() {
	blsPublicKeyHex := "98ae11750ca7abb2e8ad1a9e55bc7226c5475a961f2bf4867285be12a519f6ddb5671f999ffd0f3ee6a6b2ea16f6cfa90086c14307bfc4e8e07d9c703603177e96874d8cba268d6d01a34cd8b418a4ffcc3ce5376b339d049cadeba06f959399"
	publicKey, _ := hex.DecodeString(blsPublicKeyHex)
	subject := core.NewSignatureProofSuite2020(publicKey, s.options)

	// test derived proof
	var derivedProof model.JsonLdCredential
	derivedProofBytes, err := os.ReadFile("testdata/derivedProof.json")
	s.NoError(err)
	err = json.Unmarshal(derivedProofBytes, &derivedProof)
	s.NoError(err)

	// check
	actualResult := subject.VerifyProof(derivedProof)
	expectedResult := &model.VerificationResult{
		Success: true,
	}
	s.Equal(expectedResult, actualResult)
}
