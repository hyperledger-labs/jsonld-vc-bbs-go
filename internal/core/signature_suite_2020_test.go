package core_test

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
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

func (s *SignatureSuite2020TestSuite) TestSignatureCreationAndVerification() {
	blsPublicKeyHex := "98ae11750ca7abb2e8ad1a9e55bc7226c5475a961f2bf4867285be12a519f6ddb5671f999ffd0f3ee6a6b2ea16f6cfa90086c14307bfc4e8e07d9c703603177e96874d8cba268d6d01a34cd8b418a4ffcc3ce5376b339d049cadeba06f959399"
	blsPrivateKeyHex := "13e86bd1a774b4609108a920c2886394e76c8db8502fbc380d1a21f8be835cef"
	publicKey, _ := hex.DecodeString(blsPublicKeyHex)
	privateKey, _ := hex.DecodeString(blsPrivateKeyHex)
	subject := core.NewSignatureSuite2020(publicKey, privateKey, s.options)

	// retrieve unsigned credential
	var docToSign model.JsonLdCredentialNoProof
	unsignedCredentialBytes, err := os.ReadFile("testdata/unsignedCredential.json")
	s.NoError(err)
	err = json.Unmarshal(unsignedCredentialBytes, &docToSign)
	s.NoError(err)

	// sign credential
	_, jsonCredential, err := subject.Sign(docToSign)
	s.NoError(err)

	// verify signature
	subject = core.NewSignatureSuite2020(publicKey, nil, s.options)
	var signedCredential model.JsonLdCredential
	err = json.Unmarshal([]byte(jsonCredential), &signedCredential)
	s.NoError(err)

	// check
	actualResult := subject.Verify(signedCredential)
	expectedResult := &model.VerificationResult{
		Success: true,
	}
	s.Equal(expectedResult, actualResult)
}

func (s *SignatureSuite2020TestSuite) TestHappyVerification() {
	blsPublicKeyHex := "98ae11750ca7abb2e8ad1a9e55bc7226c5475a961f2bf4867285be12a519f6ddb5671f999ffd0f3ee6a6b2ea16f6cfa90086c14307bfc4e8e07d9c703603177e96874d8cba268d6d01a34cd8b418a4ffcc3ce5376b339d049cadeba06f959399"
	publicKey, _ := hex.DecodeString(blsPublicKeyHex)
	subject := core.NewSignatureSuite2020(publicKey, nil, s.options)

	// retrieve signed credential
	var signedCredential model.JsonLdCredential
	signedCredentialBytes, err := os.ReadFile("testdata/signedCredential.json")
	s.NoError(err)
	err = json.Unmarshal(signedCredentialBytes, &signedCredential)
	s.NoError(err)

	// check
	actualResult := subject.Verify(signedCredential)
	expectedResult := &model.VerificationResult{
		Success: true,
	}
	s.Equal(expectedResult, actualResult)
}

func (s *SignatureSuite2020TestSuite) TestUnhappyVerification() {
	blsPublicKeyHex := "98ae11750ca7abb2e8ad1a9e55bc7226c5475a961f2bf4867285be12a519f6ddb5671f999ffd0f3ee6a6b2ea16f6cfa90086c14307bfc4e8e07d9c703603177e96874d8cba268d6d01a34cd8b418a4ffcc3ce5376b339d049cadeba06f959399"
	publicKey, _ := hex.DecodeString(blsPublicKeyHex)
	subject := core.NewSignatureSuite2020(publicKey, nil, s.options)

	// retrieve signed credential
	var signedCredential model.JsonLdCredential
	signedCredentialBytes, err := os.ReadFile("testdata/signedCredential.json")
	s.NoError(err)
	err = json.Unmarshal(signedCredentialBytes, &signedCredential)
	s.NoError(err)

	// change signature
	wrongSignatureValue := "g4MtdbRIz1gRaYshWf1EZprwNYxSHh40nVUgaZdmdPMLfTOwWl0jUeBg7ah5quGuGQvNcBWKdVdvxnk94fb0rjBREvX67YLwGxJQL2dt1GBd2tkxw4P1Qk9l3XcQfdxII1O5ywgX3VhwZxJcdNn6Zw=="
	signedCredential[c.CredentialFieldProof].(map[string]interface{})[c.CredentialFieldProofValue] = wrongSignatureValue

	// check
	actualResult := subject.Verify(signedCredential)
	expectedResult := &model.VerificationResult{
		Success: false,
		Error:   fmt.Errorf("signature verification failed: 'invalid BLS12-381 signature'"),
	}
	s.Equal(expectedResult, actualResult)
}

func (s *SignatureSuite2020TestSuite) TestProvisionOfVerificationData() {
	blsPublicKeyHex := "98ae11750ca7abb2e8ad1a9e55bc7226c5475a961f2bf4867285be12a519f6ddb5671f999ffd0f3ee6a6b2ea16f6cfa90086c14307bfc4e8e07d9c703603177e96874d8cba268d6d01a34cd8b418a4ffcc3ce5376b339d049cadeba06f959399"
	publicKey, _ := hex.DecodeString(blsPublicKeyHex)
	subject := core.NewSignatureSuite2020(publicKey, nil, s.options)

	// retrieve signed credential
	var credential model.JsonLdCredential
	signedCredentialBytes, err := os.ReadFile("testdata/signedCredential.json")
	s.NoError(err)
	err = json.Unmarshal(signedCredentialBytes, &credential)
	s.NoError(err)

	// retrieve expected normalization
	expectedResultBytes, err := os.ReadFile("testdata/signedCredentialNormalized.json")
	s.NoError(err)
	var expectedData []string
	err = json.Unmarshal(expectedResultBytes, &expectedData)
	s.NoError(err)
	expectedResult := make([][]byte, len(expectedData))
	for i, expected := range expectedData {
		expectedResult[i] = []byte(expected)
	}

	// check
	actualResult, err := subject.ProvideSigningData(credential)
	s.NoError(err)
	s.Equal(expectedResult, actualResult)

	// verify that input credential was not modified in previous operations
	var expectedCredential model.JsonLdCredential
	err = json.Unmarshal(signedCredentialBytes, &expectedCredential)
	s.NoError(err)

	s.Equal(expectedCredential, credential)
}
