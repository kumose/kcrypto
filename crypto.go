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
	"crypto"
	"errors"
	"fmt"

	"github.com/kumose/kprinter"
	"github.com/kumose/kutils"
)

var (
	ErrorEmptyKey = errors.New("error on key empty, check if the key has been initialized")
	// ErrorUnsupportedKeyType means we don't supported this type of key
	ErrorUnsupportedKeyType = errors.New("provided key type not supported")
)

const (
	RSAKeyLength = 2048
)

// PublicKey is a public key available to KMOPT
type PublicKey interface {
	// Type returns the type of the key, e.g. RSA
	Type() CryptoType

	// Key returns the raw public key
	Key() crypto.PublicKey

	// SetKey set raw public key
	SetKey(crypto.PublicKey) error

	// Pem returns the raw private key in PEM format
	Pem() ([]byte, error)

	// Pem returns the raw private key in PEM format
	ParsePem([]byte) error

	// KeyInfo pack KeyInfo for public key
	KeyInfo() (*KeyInfo, error)
}

// PrivKey is the private key that provide signature method
type PrivateKey interface {
	Empty() bool
	// Type returns the type of the key, e.g. RSA
	Type() CryptoType

	// Signer returns the signer of the private key
	Signer() crypto.Signer
	// Public returns public key of the PrivKey
	Public() PublicKey

	// Key returns the raw public key
	Key() crypto.PrivateKey

	SetKey(crypto.PrivateKey) error

	// Pem returns the raw private key in PEM format
	Pem() ([]byte, error)
	// Pem returns the raw private key in PEM format
	ParsePem([]byte) error
	// KeyInfo pack KeyInfo for public key
	KeyInfo() (*KeyInfo, error)

	/// Generate private key for this key
	Generate() error
}

func NewPublicKey(ty CryptoType) (PublicKey, error) {
	if ty == ED25519_TYPE {
		return NewEd25519PubKey(), nil
	}
	if ty == ECDSA_P256_TYPE {
		return nil, ErrorUnsupportedKeyType
	}
	if ty == ECDSA_TYPE {
		return nil, ErrorUnsupportedKeyType
	}
	if ty == RSA_TYPE {
		return NewRSAPublicKey(), nil
	}
	return nil, fmt.Errorf("provided key type not supported %d", ty)
}

// NewPrivateKey
func NewPrivateKey(ty CryptoType) (PrivateKey, error) {
	if ty == ED25519_TYPE {
		return NewEd25519PrivKey(), nil
	}
	if ty == ECDSA_P256_TYPE {
		return nil, ErrorUnsupportedKeyType
	}
	if ty == ECDSA_TYPE {
		return nil, ErrorUnsupportedKeyType
	}
	if ty == RSA_TYPE {
		return NewRSAPrivKey(), nil
	}
	return nil, fmt.Errorf("provided key type not supported %d", ty)
}

func LoadKeyInfo(info *KeyInfo) (PrivateKey, PublicKey, error) {
	if info == nil {
		return nil, nil, fmt.Errorf("key info is nil")
	}

	if info.Empty() {
		return nil, nil, fmt.Errorf("key info is empty")
	}

	var privK PrivateKey = nil

	var pubK PublicKey = nil
	var err error

	if info.IsPrivate() {
		privK, err = loadPrivateKeyInfo(info)
		if err != nil {
			return nil, nil, err
		}
	}
	if info.IsPublic() {
		pubK, err = loadPublicKeyInfo(info)
		if err != nil {
			return nil, nil, err
		}
	}

	return privK, pubK, nil
}

func loadPrivateKeyInfo(info *KeyInfo) (PrivateKey, error) {
	t, err := info.CheckType()
	if err != nil {
		return nil, err
	}
	d, err := info.PrivData()
	if err != nil {
		return nil, err
	}

	k, err := NewPrivateKey(t)
	if err != nil {
		return nil, err
	}
	err = k.ParsePem([]byte(d))
	if err != nil {
		return nil, err
	}

	return k, nil
}

func loadPublicKeyInfo(info *KeyInfo) (PublicKey, error) {
	t, err := info.CheckType()
	if err != nil {
		return nil, err
	}
	d, err := info.PubData()
	if err != nil {
		return nil, err
	}

	k, err := NewPublicKey(t)
	if err != nil {
		return nil, err
	}
	err = k.ParsePem([]byte(d))
	if err != nil {
		return nil, err
	}

	return k, nil
}

func LoadKeyInfoFile(filePath string) (PrivateKey, PublicKey, error) {
	ki := NewKeyInfo()
	err := ki.Load(filePath)
	if err != nil {
		return nil, nil, err
	}
	return LoadKeyInfo(ki)
}

func GenKeyPair(ty CryptoType, privatePath, publicPath string) error {
	if kutils.IsExist(privatePath) {
		kprinter.Warnf("Warning: private key already exists (%s), skipped", privatePath)
		return nil
	}

	if kutils.IsExist(publicPath) {
		kprinter.Warnf("Warning: public key already exists (%s), skipped", publicPath)
		return nil
	}

	ki, err := NewPrivateKey(ty)
	if err != nil {
		return err
	}

	err = ki.Generate()
	if err != nil {
		return err
	}

	privInfo, err := ki.KeyInfo()
	if err != nil {
		return err
	}

	pubKey := ki.Public()
	pubInfo, err := pubKey.KeyInfo()
	if err != nil {
		return err
	}

	err = privInfo.Save(privatePath, 0600)
	if err != nil {
		return err
	}
	kprinter.Infof("Private key has been written to %s", privatePath)

	err = pubInfo.Save(publicPath, 0622)
	if err != nil {
		return err
	}

	kprinter.Infof("public key has been written to %s", publicPath)
	return nil
}

func ShowKeyInfo(ki *KeyInfo) error {
	if ki.Empty() {
		kprinter.Warnf("key is empty")
		return nil
	}
	t, err := ki.CheckType()
	if err != nil {
		return err
	}

	hid, err := ki.ID()
	if err != nil {
		return err
	}
	kprinter.Printf(kprinter.Yellowf, "ID: %s\n", hid)
	kprinter.Printf(kprinter.Yellowf, "short type: %s\n", t.Short())
	kprinter.Printf(kprinter.Yellowf, "type: %s\n", t.Type())
	kprinter.Printf(kprinter.Yellowf, "schme: %s\n", t.Schema())
	if ki.IsPublic() {
		d, err := ki.PubData()
		if err != nil {
			return err
		}
		kprinter.Printf(kprinter.Yellowf, "content type: public\n")
		kprinter.Printf(kprinter.Greenf, "%s\n", d)
	}
	if ki.IsPrivate() {
		d, err := ki.PrivData()
		if err != nil {
			return err
		}
		kprinter.Printf(kprinter.Yellowf, "content type: public\n")
		kprinter.Printf(kprinter.Greenf, "%s\n", d)
	}
	return nil
}

func ShowKeyInfoFile(dst string) error {
	kprinter.Printf(kprinter.Yellowf, "*********************************************************\n")
	kprinter.Printf(kprinter.Yellowf, "Key Path: %s\n", dst)
	pub, pri, err := LoadKeyInfoFile(dst)
	if err != nil {
		return err
	}

	if pub != nil {
		pi, err := pub.KeyInfo()
		if err != nil {
			return err
		}
		err = ShowKeyInfo(pi)
		if err != nil {
			return err
		}
	}
	if pri != nil {
		pi, err := pri.KeyInfo()
		if err != nil {
			return err
		}
		err = ShowKeyInfo(pi)
		if err != nil {
			return err
		}
	}
	return nil
}
