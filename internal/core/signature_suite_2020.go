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

// NewSignatureSuite initializes and returns SignatureSuite
//
//	publicKey []byte
//	privateKey []byte nullable
//	options *model.SignatureSuiteOptions nullable
func NewSignatureSuite2020(publicKey, privateKey []byte, options *model.SignatureSuiteOptions) *SignatureSuite2020 {
	// TODO verify if initialisation was correct
	return &SignatureSuite2020{
		publicKey:  publicKey,
		privateKey: privateKey,
		keyEncoder: &KeyEncoder{},
		normalizer: NewNormalizer(options),
	}
}

// A SignatureSuite2020 is initialized with:
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
}

// Sign creates a JSON-LD BbsBlsSignature2020 Credential
// Requires during initialisation provision of publicKey and privateKey
// arguments:
//
//	credential model.JsonLDCredentialNoProof the template of the credential which should be signed.
//	 if issuer is not specified, it will be added to the template based on "did:key" method
//
// returns:
//
//	credential model.JsonLDCredential
//	credential string JSON representation of the credential
//	err error
func (s *SignatureSuite2020) Sign(credential model.JsonLDCredentialNoProof) (model.JsonLDCredential, string, error) {
	s.addCredentialIssuerIfEmpty(credential)

	proof, err := s.createUnsignedProof()
	if err != nil {
		return nil, "", err
	}

	dataForSigning, err := s.prepareDataForSigning(credential, proof)
	if err != nil {
		return nil, "", err
	}

	signature, err := s.createBLSSignature(dataForSigning)
	if err != nil {
		return nil, "", err
	}

	proof.ProofValue = signature
	// Delete context since it is not needed for representation
	proof.Context = nil
	credential[c.CredentialFieldProof] = proof

	jsonCredential, err := json.Marshal(credential)
	if err != nil {
		return nil, "", err
	}

	return model.JsonLDCredential(deepCopyMap(credential)), string(jsonCredential), nil
}

// ProvideSigningData prepares the array of the messages which will be signed/verified during issuance process
// According to specification, these array will be composed of concatenation of:
// - normalized "proof" messages
// - normalized "credential - proof" messages
//
// arguments:
//
//	credential map[string]interface{}
//
// returns:
//
//	messages [][]byte
//	err error
func (s *SignatureSuite2020) ProvideSigningData(credential map[string]interface{}) ([][]byte, error) {
	credentialCopy := deepCopyMap(credential)

	proof, ok := credentialCopy[c.CredentialFieldProof].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("provided credential doesn't contain object 'proof'")
	}

	delete(credentialCopy, c.CredentialFieldProof)
	delete(proof, c.CredentialFieldProofValue)

	fullProof, err := model.CredentialProofFromMap(proof)
	if err != nil {
		return nil, err
	}

	return s.prepareDataForSigning(model.JsonLDCredentialNoProof(credentialCopy), fullProof)
}

// Verify verifies signed credential. Requires during initialisation provision of only publicKey
//
// arguments:
//
//	credential model.JsonLDCredential
//
// returns:
//
//	result *model.VerificationResult
func (s *SignatureSuite2020) Verify(credential model.JsonLDCredential) *model.VerificationResult {
	signingData, err := s.ProvideSigningData(credential)
	if err != nil {
		return &model.VerificationResult{
			Success: false,
			Error:   err,
		}
	}

	var signature []byte

	proof := credential[c.CredentialFieldProof].(map[string]interface{})
	if proofValue, ok := proof[c.CredentialFieldProofValue].(string); ok {
		signature, err = base64.StdEncoding.DecodeString(proofValue)

		if err != nil {
			return &model.VerificationResult{
				Success: false,
				Error:   fmt.Errorf("proof value could not be decoded from base64 '%s'", err.Error()),
			}
		}
	} else {
		return &model.VerificationResult{
			Success: false,
			Error:   fmt.Errorf("credential proof doesn't contain field '%s'", c.CredentialFieldProofValue),
		}
	}

	bls := bbs.New(ml.Curves[ml.BLS12_381_BBS])

	err = bls.Verify(signingData, signature, s.publicKey)
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

// TODO add option to use custom verification method
func (s *SignatureSuite2020) createUnsignedProof() (*model.CredentialProof, error) {
	verificationMethod, err := s.keyEncoder.CreateDidKeyVerificationMethod(s.publicKey)
	if err != nil {
		return nil, err
	}

	partialProof := map[string]interface{}{
		c.CredentialFieldVerificationMethod: verificationMethod,
	}

	return model.CredentialProofFromMap(partialProof)
}

func (s *SignatureSuite2020) prepareDataForSigning(credential model.JsonLDCredentialNoProof, unsignedProof *model.CredentialProof) ([][]byte, error) {
	document, err := json.Marshal(credential)
	if err != nil {
		return nil, err
	}

	cononisedCredential, err := s.normalizer.Normalize(string(document))
	if err != nil {
		return nil, err
	}

	document, err = json.Marshal(unsignedProof)
	if err != nil {
		return nil, err
	}

	canonisedProof, err := s.normalizer.Normalize(string(document))
	if err != nil {
		return nil, err
	}

	// according to specification
	// canonised proof messages come before the canonised credential messages
	stringsForSigning := append(canonisedProof, cononisedCredential...)

	bytesForSigning := make([][]byte, len(stringsForSigning))
	for i, s := range stringsForSigning {
		bytesForSigning[i] = []byte(s)
	}

	return bytesForSigning, nil
}

// createBLSSignature
//
// returns:
//
//	signature string base64 encoded string
//	err error
func (s *SignatureSuite2020) createBLSSignature(dataForSigning [][]byte) (string, error) {
	bls := bbs.New(ml.Curves[ml.BLS12_381_BBS])
	signatureBytes, err := bls.Sign(dataForSigning, s.privateKey)
	if err != nil {
		return "", nil
	}

	return base64.StdEncoding.EncodeToString(signatureBytes), nil
}

func (s *SignatureSuite2020) addCredentialIssuerIfEmpty(credential model.JsonLDCredentialNoProof) {
	if _, ok := credential[c.CredentialFieldIssuer]; !ok {
		credential[c.CredentialFieldIssuer], _ = s.keyEncoder.CreateDidKey(s.publicKey)
	}
}
