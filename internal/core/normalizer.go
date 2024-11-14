package core

import (
	"encoding/json"
	"strings"

	c "github.com/hyperledger-labs/jsonld-vc-bbs-go/constants"
	"github.com/hyperledger-labs/jsonld-vc-bbs-go/internal/context"
	"github.com/hyperledger-labs/jsonld-vc-bbs-go/model"
	"github.com/piprate/json-gold/ld"
)

// NewNormalizer initializes normalizer struct
// arguments:
//
//	options *model.SignatureSuiteOptions nullable
//
// returns
//
//	normalizer *normalizer The normalizer instance.
func NewNormalizer(options *model.SignatureSuiteOptions) *normalizer {
	defaultLocalContexts := map[string]interface{}{
		c.ContextCredentialV1:           decodeOrPanic(context.ContextCredentialsV1),
		c.ContextSecurityBbsV1:          decodeOrPanic(context.ContextBbsBlsSignature2020),
		c.ContextVCRevocationList2020V1: decodeOrPanic(context.ContextVCRevocationList2020V1),
		c.ContextCitizenshipV1:          decodeOrPanic(context.ContextResidentCardV1),
		c.ContextSecurityV2:             decodeOrPanic(context.ContextSecurityV2),
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

// A defaultDocumentLoader contains a set of predefined contexts for document normalization
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

// Normalize Perform normalization of a JSON-LD document using
// format "application/n-quads" and algorithm "URDNA2015".
//
//	document string The JSON-LD document to normalize.
//
// returns:
//
//	messages []string array of string
//	err error if an error appeared during the normalization: e.g. necessary context was not found
func (n *normalizer) Normalize(document string) ([]string, error) {
	proc := ld.NewJsonLdProcessor()
	options := n.getStandardOptions()

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

// Compact Compact a JSON-LD document against a set of contexts.
//
//	document model.JsonLdCredential The JSON-LD document to compact.
//	context interface{} The contexts against which the document has to be compacted.
//
// returns:
//
//	compactedDocument model.JsonLdCredential
//	err error
func (n *normalizer) Compact(document model.JsonLdCredential, context interface{}) (model.JsonLdCredential, error) {
	proc := ld.NewJsonLdProcessor()
	options := n.getStandardOptions()

	result, err := proc.Compact(document, context, options)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// Frame Frame a JSON-LD document according to the passed frame.
//
//	input model.JsonLdCredential The document to frame.
//	frame model.JsonLdFrame The frame document.
//
// returns:
//
//	framedDocument model.JsonLdCredential
func (n *normalizer) Frame(input model.JsonLdCredential, frame model.JsonLdFrame) (model.JsonLdCredential, error) {
	proc := ld.NewJsonLdProcessor()
	options := n.getStandardOptions()
	options.OmitGraph = true

	result, err := proc.Frame(input, frame, options)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// getStandardOptions Get the list of options to use for the normalization.
func (n *normalizer) getStandardOptions() *ld.JsonLdOptions {
	options := ld.NewJsonLdOptions("")
	options.Format = "application/n-quads"
	options.Algorithm = "URDNA2015"
	options.DocumentLoader = n.documentLoader

	return options
}
