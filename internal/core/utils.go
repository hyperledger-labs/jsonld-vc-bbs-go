package core

import (
	"encoding/json"
)

func deepCopyMap(m map[string]interface{}) map[string]interface{} {
	raw, _ := json.Marshal(m)

	var copy map[string]interface{}
	_ = json.Unmarshal(raw, &copy)

	return copy
}

func decodeOrPanic(doc string) map[string]interface{} {
	var jsonRaw map[string]interface{}

	err := json.Unmarshal([]byte(doc), &jsonRaw)
	if err != nil {
		panic(err)
	}

	return jsonRaw
}
