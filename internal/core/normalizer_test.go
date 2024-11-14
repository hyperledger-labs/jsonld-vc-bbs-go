package core_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/hyperledger-labs/jsonld-vc-bbs-go/internal/core"
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

	proofJSONLdBytes, err := os.ReadFile("testdata/unsignedProof.json")
	s.NoError(err)

	var expected []string
	expectedResultBytes, err := os.ReadFile("testdata/unsignedProofNormalized.json")
	s.NoError(err)
	err = json.Unmarshal(expectedResultBytes, &expected)
	s.NoError(err)

	actual, err := subject.Normalize(string(proofJSONLdBytes))
	s.NoError(err)
	s.Equal(expected, actual)
}

func (s *NormalizerTestSuite) TestCredentialNormalization() {
	subject := core.NewNormalizer(nil)

	credentialJSONLdBytes, err := os.ReadFile("testdata/unsignedPermanentResidentCard.json")
	s.NoError(err)

	var expected []string
	expectedResultBytes, err := os.ReadFile("testdata/unsignedPermanentResidentCardNormalized.json")
	s.NoError(err)
	err = json.Unmarshal(expectedResultBytes, &expected)
	s.NoError(err)

	actual, err := subject.Normalize(string(credentialJSONLdBytes))
	s.NoError(err)

	s.Equal(expected, actual)
}
