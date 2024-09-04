package core_test

import (
	"encoding/hex"
	"testing"

	"github.com/hyperledger-labs/jsonld-vc-bbs-go/internal/core"
	"github.com/stretchr/testify/suite"
)

type KeyEncoderTestSuite struct {
	suite.Suite

	subject core.KeyEncoder
}

func TestKeyEncoderTestSuite(t *testing.T) {
	suite.Run(t, new(KeyEncoderTestSuite))
}

func (s *KeyEncoderTestSuite) SetupTest() {
	s.subject = core.KeyEncoder{}
}

func (s *KeyEncoderTestSuite) TestCreationOfDidKey() {
	blsPublicKeyHex := "87fae47132975f345b38fafd53149f7a009b89dd94fdc54d5d051a29e185ed4870acc2453fbd2e307d1543dfb7fbfdb30cf0008df96c75e2e43975b7f92864b4bc6e3f2f1495748d80a36691f6feaeb8fe151c1bb35de9bff5ac21ff9e57aebe"
	expected := "did:key:zUC73gNPc1EnZmDDjYJzE8Bk89VRhuZPQYXFnSiSUZvX9N1i7N5VtMbJyowDR46rtARHLJYRVf7WMbGLb43s9tfTyKF9KFF22vBjXZRomcwtoQJmMNUSY7tfzyhLEy58dwUz3WD"

	key, err := hex.DecodeString(blsPublicKeyHex)
	s.NoError(err)

	actual, err := s.subject.CreateDidKey(key)
	s.NoError(err)
	s.Equal(expected, actual)
}

func (s *KeyEncoderTestSuite) TestCreationOfDidKeyVerificationMethod() {
	blsPublicKeyHex := "87fae47132975f345b38fafd53149f7a009b89dd94fdc54d5d051a29e185ed4870acc2453fbd2e307d1543dfb7fbfdb30cf0008df96c75e2e43975b7f92864b4bc6e3f2f1495748d80a36691f6feaeb8fe151c1bb35de9bff5ac21ff9e57aebe"
	expected := "did:key:zUC73gNPc1EnZmDDjYJzE8Bk89VRhuZPQYXFnSiSUZvX9N1i7N5VtMbJyowDR46rtARHLJYRVf7WMbGLb43s9tfTyKF9KFF22vBjXZRomcwtoQJmMNUSY7tfzyhLEy58dwUz3WD#zUC73gNPc1EnZmDDjYJzE8Bk89VRhuZPQYXFnSiSUZvX9N1i7N5VtMbJyowDR46rtARHLJYRVf7WMbGLb43s9tfTyKF9KFF22vBjXZRomcwtoQJmMNUSY7tfzyhLEy58dwUz3WD"

	key, err := hex.DecodeString(blsPublicKeyHex)
	s.NoError(err)

	actual, err := s.subject.CreateDidKeyVerificationMethod(key)
	s.NoError(err)
	s.Equal(expected, actual)
}
