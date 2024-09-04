package core

import (
	"encoding/json"
	"strings"

	"github.com/hyperledger-labs/jsonld-vc-bbs-go/internal/context"
	"github.com/hyperledger-labs/jsonld-vc-bbs-go/model"
	"github.com/piprate/json-gold/ld"
)

// NewNormalizer initialises normalizer struct
// arguments:
//
//	options *model.SignatureSuiteOptions nullable
//
// returns
//
//	*normalizer
func NewNormalizer(options *model.SignatureSuiteOptions) *normalizer {
	defaultLocalContexts := map[string]interface{}{
		"https://www.w3.org/2018/credentials/v1":      decodeOrPanic(context.ContextCredentialsV1),
		"https://w3id.org/security/bbs/v1":            decodeOrPanic(context.ContextBbsBlsSignature2020),
		"https://w3id.org/vc-revocation-list-2020/v1": decodeOrPanic(context.ContextVCRevocationList2020V1),
		"https://w3id.org/citizenship/v1":             decodeOrPanic(context.ContextResidentCardV1),
	}

	if options != nil && options.Contexts != nil {
		for key, value := range options.Contexts {
			defaultLocalContexts[key] = value
		}
	}

	var documentLoader ld.DocumentLoader

	if options == nil || options.DocumentLoader == nil {
		documentLoader = defaultDocumentLoader{
			localContexts: defaultLocalContexts,
			remoteDocumentLoader: ld.NewCachingDocumentLoader(
				ld.NewDefaultDocumentLoader(nil), // 'nil' means that default http.Client will be used
			),
		}
	} else {
		documentLoader = options.DocumentLoader
	}

	return &normalizer{
		documentLoader: documentLoader,
	}
}

// A normalizer implements operations for manipulations of json-ld documents.
// Supported operations:
// - Normalize
type normalizer struct {
	documentLoader ld.DocumentLoader
}

// A defaultDocumentLoader contains a set of predefined contexts for document normalisation
// A defaultDocumentLoader uses *ld.CachingDocumentLoader to fetch unknown contexts from the internet
type defaultDocumentLoader struct {
	remoteDocumentLoader *ld.CachingDocumentLoader
	localContexts        map[string]interface{}
}

func (l defaultDocumentLoader) LoadDocument(u string) (*ld.RemoteDocument, error) {
	if val, ok := l.localContexts[u]; ok {
		return &ld.RemoteDocument{
			Document:    val,
			DocumentURL: u,
			ContextURL:  u,
		}, nil
	}

	return l.remoteDocumentLoader.LoadDocument(u)
}

// Normalize performs normalization of json-ld document using
// format "application/n-quads" and algorithm "URDNA2015"
// arguments:
//
//	document string json-ld object
//
// returns:
//
//	messages []string array of string
//	err error if an error appeared during the normalisation: e.g. necesasry context was not found
func (n *normalizer) Normalize(document string) ([]string, error) {
	proc := ld.NewJsonLdProcessor()
	options := ld.NewJsonLdOptions("")
	options.Format = "application/n-quads"
	options.Algorithm = "URDNA2015"
	options.DocumentLoader = n.documentLoader

	var jsonRaw map[string]interface{}

	err := json.Unmarshal([]byte(document), &jsonRaw)
	if err != nil {
		return nil, err
	}

	normalizedTriples, err := proc.Normalize(jsonRaw, options)
	if err != nil {
		return nil, err
	}

	result := strings.Split(normalizedTriples.(string), "\n")
	if result[len(result)-1] == "" {
		result = result[:len(result)-1]
	}

	return result, nil
}
