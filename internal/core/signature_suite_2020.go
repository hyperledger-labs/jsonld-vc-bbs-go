package core

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	ml "github.com/IBM/mathlib"
	c "github.com/hyperledger-labs/jsonld-vc-bbs-go/constants"
	"github.com/hyperledger-labs/jsonld-vc-bbs-go/model"
	"github.com/hyperledger/aries-bbs-go/bbs"
)

// SignatureSuite2020 is initialized with:
//
//	publicKey []byte
//	privateKey []byte nullable, required when issuance is needed
//	options *model.SignatureSuiteOptions nullable, permits to add/overwrite default document loader and pre-defined contexts
//
// Default document loader will has following contexts pre-loaded:
//   - https://www.w3.org/2018/credentials/v1
//   - https://w3id.org/security/bbs/v1
//   - https://w3id.org/citizenship/v1
//   - https://w3id.org/vc-revocation-list-2020/v1
//
// If context is not found, document loader will try to download it from the internet
type SignatureSuite2020 struct {
	publicKey  []byte
	privateKey []byte
	keyEncoder *KeyEncoder
	normalizer *normalizer
	curve      *bbs.BBSG2Pub
}

// NewSignatureSuite2020 initializes and returns SignatureSuite
//
//	publicKey []byte
//	privateKey []byte nullable
//	options *model.SignatureSuiteOptions nullable
func NewSignatureSuite2020(publicKey, privateKey []byte, options *model.SignatureSuiteOptions) *SignatureSuite2020 {
	return &SignatureSuite2020{
		publicKey:  publicKey,
		privateKey: privateKey,
		keyEncoder: &KeyEncoder{},
		normalizer: NewNormalizer(options),
		curve:      bbs.New(ml.Curves[ml.BLS12_381_BBS]),
	}
}

// Sign Create a JSON-LD signed credential with a BbsBlsSignature2020 signature.
// Requires during initialization provision of publicKey and privateKey.
//
//	credential model.JsonLdCredentialNoProof The JSON-LD credential to be signed. If issuer is not specified, it will be added to the template based on "did:key" method.
//
// returns:
//
//	signedCredential model.JsonLdCredential
//	jsonCredential string JSON representation of the credential
//	err error
func (s *SignatureSuite2020) Sign(credential model.JsonLdCredentialNoProof) (model.JsonLdCredential, string, error) {
	credCopy := deepCopyMap(credential)
	s.addCredentialIssuerIfEmpty(credCopy)

	proof, err := s.createUnsignedProof()
	if err != nil {
		return nil, "", err
	}

	dataForSigning, err := s.prepareDataForSigning(credCopy, proof)
	if err != nil {
		return nil, "", err
	}

	signature, err := s.createBLSSignature(dataForSigning)
	if err != nil {
		return nil, "", err
	}

	proof.ProofValue = signature
	proof.Context = nil // Delete context since it is not needed for representation -> compact proof format
	// TODO: support the possibility to add the new proof to the list of existing proofs -> support array of proofs
	credCopy[c.CredentialFieldProof] = proof

	jsonLdDoc, err := json.Marshal(credCopy)
	if err != nil {
		return nil, "", err
	}

	return credCopy, string(jsonLdDoc), nil
}

// ProvideSigningData prepares the array of the messages which will be signed/verified during issuance process.
// According to specification, the array will be composed by the concatenation of:
//   - normalized "proof" messages
//   - normalized "document" messages
//
// arguments:
//
//	credential model.JsonLdCredential
//
// returns:
//
//	messages [][]byte
//	err error
func (s *SignatureSuite2020) ProvideSigningData(credential model.JsonLdCredential) ([][]byte, error) {
	credCopy := deepCopyMap(credential)

	proof, ok := credCopy[c.CredentialFieldProof].(model.JsonLdProof)
	if !ok {
		return nil, fmt.Errorf("provided JSON-LD credential doesn't contain object 'proof'")
	}

	delete(credCopy, c.CredentialFieldProof)
	delete(proof, c.CredentialFieldProofValue)

	fullProof, err := model.CredentialProofFromMap(proof, false)
	if err != nil {
		return nil, err
	}

	return s.prepareDataForSigning(credCopy, fullProof)
}

// Verify verifies a signed JSON-LD credential.
//
//	credential model.JsonLdCredential
//
// returns:
//
//	result *model.VerificationResult
func (s *SignatureSuite2020) Verify(credential model.JsonLdCredential) *model.VerificationResult {
	signingData, err := s.ProvideSigningData(credential)
	if err != nil {
		return &model.VerificationResult{
			Success: false,
			Error:   err,
		}
	}

	var signature []byte

	proof := credential[c.CredentialFieldProof].(model.JsonLdProof)
	if proofValue, ok := proof[c.CredentialFieldProofValue].(string); ok {
		signature, err = base64.StdEncoding.DecodeString(proofValue)
		if err != nil {
			return &model.VerificationResult{
				Error: fmt.Errorf("proof value could not be decoded from base64 '%s'", err.Error()),
			}
		}
	} else {
		return &model.VerificationResult{
			Success: false,
			Error:   fmt.Errorf("proof doesn't contain field '%s'", c.CredentialFieldProofValue),
		}
	}

	err = s.curve.Verify(signingData, signature, s.publicKey)
	if err != nil {
		return &model.VerificationResult{
			Success: false,
			Error:   fmt.Errorf("signature verification failed: '%s'", err.Error()),
		}
	}

	return &model.VerificationResult{
		Success: true,
	}
}

// createUnsignedProof Generate the skeleton of a JSON-LD proof.
//
// returns:
//
//	proof *model.CredentialProof
//	err error
func (s *SignatureSuite2020) createUnsignedProof() (*model.CredentialProof, error) {
	// TODO add option to use custom verification method
	verificationMethod, err := s.keyEncoder.CreateDidKeyVerificationMethod(s.publicKey)
	if err != nil {
		return nil, err
	}

	partialProof := model.JsonLdProof{
		c.CredentialFieldVerificationMethod: verificationMethod,
	}

	return model.CredentialProofFromMap(partialProof, false)
}

// prepareDataForSigning Transform a JSON-LD credential and the associated proof to a list of normalized messages
// that can be signed according to the specifications.
//
//	credential model.JsonLdCredentialNoProof The JSON-LD credential without the proof.
//	unsignedProof *model.CredentialProof The JSON-LD proof.
//
// returns:
//
//	messages [][]byte
//	err error
func (s *SignatureSuite2020) prepareDataForSigning(credential model.JsonLdCredentialNoProof, unsignedProof *model.CredentialProof) ([][]byte, error) {
	// 1. Normalize the JSON-LD unsigned credential
	credCopy, err := json.Marshal(credential)
	if err != nil {
		return nil, err
	}
	normalizedCredential, err := s.normalizer.Normalize(string(credCopy))
	if err != nil {
		return nil, err
	}

	// 2. Normalize the JSON-LD proof
	credCopy, err = json.Marshal(unsignedProof)
	if err != nil {
		return nil, err
	}

	normalizedProof, err := s.normalizer.Normalize(string(credCopy))
	if err != nil {
		return nil, err
	}

	// according to specification normalized proof messages come before the normalized credential messages
	stringsForSigning := append(normalizedProof, normalizedCredential...)
	bytesForSigning := make([][]byte, len(stringsForSigning))
	for i, s := range stringsForSigning {
		bytesForSigning[i] = []byte(s)
	}

	return bytesForSigning, nil
}

// createBLSSignature Generate a BBS signature over an array of messages.
//
//	dataForSigning [][]byte The messages to sign.
//
// returns:
//
//	signature string Base64 encoded string
//	err error
func (s *SignatureSuite2020) createBLSSignature(dataForSigning [][]byte) (string, error) {
	signatureBytes, err := s.curve.Sign(dataForSigning, s.privateKey)
	if err != nil {
		return "", nil
	}

	return base64.StdEncoding.EncodeToString(signatureBytes), nil
}

// addCredentialIssuerIfEmpty Add the field "issuer" to a JSON-LD credential to sign if empty.
//
//	credential model.JsonLdCredentialNoProof
func (s *SignatureSuite2020) addCredentialIssuerIfEmpty(credential model.JsonLdCredentialNoProof) {
	if _, ok := credential[c.CredentialFieldIssuer]; !ok {
		credential[c.CredentialFieldIssuer], _ = s.keyEncoder.CreateDidKey(s.publicKey)
	}
}
