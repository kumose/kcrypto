// Copyright (C) Kumo inc. and its affiliates.
// Author: Jeff.li lijippy@163.com
// All rights reserved.
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//

package kcrypto

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"

	cjson "github.com/gibson042/canonicaljson-go"
)

// KeyInfo is the manifest structure of a single key
type KeyInfo struct {
	Type   string            `json:"keytype"`
	Value  map[string]string `json:"keyval"`
	Scheme string            `json:"scheme"`
}

func NewKeyInfo() *KeyInfo {
	return &KeyInfo{}
}

// IsPrivate detect if this is a private key
func (ki *KeyInfo) IsPrivate() bool {
	return len(ki.Value["private"]) > 0
}

// IsPrivate detect if this is a private key
func (ki *KeyInfo) IsPublic() bool {
	return len(ki.Value["public"]) > 0
}

func (ki *KeyInfo) Empty() bool {
	return !ki.IsPublic() && !ki.IsPrivate()
}

// Save saves a KeyInfo object to a JSON file
func (ki *KeyInfo) Save(dst string, privMode os.FileMode) error {
	if ki.Empty() {
		return fmt.Errorf("KeyInfo is empty")
	}
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, found := ki.Value["private"]; found {
		err = f.Chmod(privMode)
		if err != nil {
			return err
		}
	}
	return json.NewEncoder(f).Encode(*ki)
}

// Load loads a KeyInfo object from a JSON file
func (ki *KeyInfo) Load(src string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()

	return json.NewDecoder(f).Decode(ki)
}

// Load loads a KeyInfo object from a JSON file
func (ki *KeyInfo) PubData() (string, error) {
	if ki.IsPublic() {
		return ki.Value["public"], nil
	}

	return "", fmt.Errorf("key info not public type")
}

func (ki *KeyInfo) PrivData() (string, error) {
	if ki.IsPrivate() {
		return ki.Value["private"], nil
	}

	return "", fmt.Errorf("key info not private type")
}

// Load loads a KeyInfo object from a JSON file
func (ki *KeyInfo) CheckType() (CryptoType, error) {
	if ki.Empty() {
		return INVALID_TYPE, fmt.Errorf("key info empty")
	}
	var tmpType CryptoType
	err := tmpType.Set(ki.Type)
	if err != nil {
		return INVALID_TYPE, err
	}
	var tmpSchema CryptoType
	err = tmpSchema.SetScheme(ki.Scheme)
	if err != nil {
		return INVALID_TYPE, err
	}
	if tmpSchema != tmpType {
		return INVALID_TYPE, fmt.Errorf("key info type and schema not match")
	}
	return tmpSchema, nil
}

// ID returns the hash id of the key
func (ki *KeyInfo) ID() (string, error) {
	payload, err := cjson.Marshal(*ki)
	if err != nil {
		// XXX: maybe we can assume that the error should always be nil since the KeyInfo struct is valid
		return "", err
	}
	sum := sha256.Sum256(payload)
	return fmt.Sprintf("%x", sum), nil
}
