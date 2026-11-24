// Package credfile reads the host-local database credential file shared by the
// database builtins: a root-owned, mode 0600 regular file that holds one JSON
// object with username and password.
package credfile

import (
	"encoding/json"
	"errors"
	"io"
)

// Credential is the content of a credential file.
type Credential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Decode parses exactly one JSON object with the string fields username and
// password. The username must not be empty; the password may be.
func Decode(r io.Reader) (Credential, error) {
	var fields struct {
		Username *string `json:"username"`
		Password *string `json:"password"`
	}
	d := json.NewDecoder(r)
	d.DisallowUnknownFields()
	if err := d.Decode(&fields); err != nil || fields.Username == nil || *fields.Username == "" || fields.Password == nil {
		return Credential{}, errors.New("credential must contain JSON username and password strings")
	}
	if d.Decode(new(any)) != io.EOF {
		return Credential{}, errors.New("credential must contain exactly one JSON object")
	}
	return Credential{Username: *fields.Username, Password: *fields.Password}, nil
}
