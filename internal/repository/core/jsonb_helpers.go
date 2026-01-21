package core

import (
	"encoding/json"
	"fmt"
)

// mapToJSONB converts a map to JSONB bytes for database storage
func mapToJSONB(data map[string]any) ([]byte, error) {
	if data == nil {
		return nil, nil
	}

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("marshal to JSON: %w", err)
	}

	return jsonBytes, nil
}

// jsonbToMap converts JSONB bytes from database to a map
func jsonbToMap(data []byte) map[string]any {
	if data == nil {
		return nil
	}

	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		// Log error but don't fail - return empty map
		return make(map[string]any)
	}

	return result
}

// jsonbToBytes converts any struct to JSON bytes for export
func jsonbToBytes(data any) ([]byte, error) {
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("marshal to JSON bytes: %w", err)
	}

	return jsonBytes, nil
}

// stringMapToJSONB converts a map[string]string to JSONB bytes
func stringMapToJSONB(data map[string]string) ([]byte, error) {
	if data == nil {
		return nil, nil
	}

	// Convert to map[string]any
	anyMap := make(map[string]any, len(data))
	for k, v := range data {
		anyMap[k] = v
	}

	return mapToJSONB(anyMap)
}

// jsonbToStringMap converts JSONB bytes to a map[string]string
func jsonbToStringMap(data []byte) map[string]string {
	if data == nil {
		return nil
	}

	var result map[string]string
	if err := json.Unmarshal(data, &result); err != nil {
		return make(map[string]string)
	}

	return result
}
