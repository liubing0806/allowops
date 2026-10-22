package execd

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

const MaxRequestBytes = 128 * 1024
const MaxParameterBytes = 64 * 1024

type Request struct {
	CatalogID      string         `json:"catalog_id"`
	CatalogVersion int64          `json:"catalog_version"`
	Action         string         `json:"action"`
	Params         map[string]any `json:"params"`
	Filters        map[string]any `json:"filters,omitempty"`
}

// DecodeJSON preserves integer precision and rejects duplicate keys at every depth.
// Errors never include input values, which may contain credentials.
func DecodeJSON(data []byte, out any) error {
	return DecodeJSONDepth(data, out, 32)
}

func DecodeJSONDepth(data []byte, out any, maxDepth int) error {
	if !utf8.Valid(data) {
		return errors.New("INVALID_JSON")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := checkValue(d, 0, maxDepth); err != nil {
		return errors.New("INVALID_JSON")
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("INVALID_JSON")
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return errors.New("INVALID_JSON")
	}
	return nil
}

func checkValue(d *json.Decoder, depth, maxDepth int) error {
	if depth > maxDepth {
		return errors.New("depth")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if delim == '{' {
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return errors.New("duplicate")
			}
			seen[name] = true
			if err := checkValue(d, depth+1, maxDepth); err != nil {
				return err
			}
		}
	} else if delim == '[' {
		for d.More() {
			if err := checkValue(d, depth+1, maxDepth); err != nil {
				return err
			}
		}
	} else {
		return errors.New("delimiter")
	}
	_, err = d.Token()
	return err
}

func DecodeParameters(data []byte) (map[string]any, error) {
	if len(data) > MaxParameterBytes {
		return nil, errors.New("PARAMETERS_TOO_LARGE")
	}
	var input map[string]any
	if err := DecodeJSON(data, &input); err != nil || input == nil {
		return nil, errors.New("INVALID_PARAMETERS")
	}
	return input, nil
}

func ReadRequest(input io.Reader) (Request, error) {
	var request Request
	data, err := io.ReadAll(io.LimitReader(input, MaxRequestBytes+1))
	if err != nil {
		return request, errors.New("INPUT_READ_FAILED")
	}
	if len(data) > MaxRequestBytes {
		return request, errors.New("INPUT_TOO_LARGE")
	}
	if err := DecodeJSON(data, &request); err != nil {
		return request, err
	}
	if request.CatalogID == "" || request.CatalogVersion <= 0 || request.Action == "" || request.Params == nil {
		return request, errors.New("INVALID_REQUEST")
	}
	data, err = json.Marshal(request.Params)
	if err != nil || len(data) > MaxParameterBytes {
		return request, errors.New("PARAMETERS_TOO_LARGE")
	}
	return request, nil
}
