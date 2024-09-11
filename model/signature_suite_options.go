package model

import (
	"github.com/piprate/json-gold/ld"
)

// SignatureSuiteOptions Set of options to use to customize the signature suite behavior.
type SignatureSuiteOptions struct {
	DocumentLoader ld.DocumentLoader                 // optional custom document loader. If not provided, default will be used
	Contexts       map[string]map[string]interface{} // additional credential contexts, will be merges in the defaults
}
