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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

type RSAPubKey struct {
	key *rsa.PublicKey
}

func NewRSAPublicKey() PublicKey {
	return &RSAPubKey{}
}

func (p *RSAPubKey) Empty() bool {
	return p.key == nil
}

func (p *RSAPubKey) Type() CryptoType {
	return RSA_TYPE
}

func (p *RSAPubKey) Key() crypto.PublicKey {
	return p.key
}

// SetKey set raw public key
func (p *RSAPubKey) SetKey(k crypto.PublicKey) error {
	rsaKey, ok := k.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("expected *rsa.PublicKey, got %T", k)
	}
	p.key = rsaKey
	return nil
}

func (p *RSAPubKey) Pem() ([]byte, error) {
	if p.Empty() {
		return nil, ErrorEmptyKey
	}

	asn1Bytes, err := x509.MarshalPKIXPublicKey(p.key)
	if err != nil {
		return nil, err
	}
	pemKey := &pem.Block{
		Type:  "RAS PUBLIC KEY",
		Bytes: asn1Bytes,
	}
	return pem.EncodeToMemory(pemKey), nil
}

func (p *RSAPubKey) ParsePem(key []byte) error {
	if key == nil {
		return fmt.Errorf("error on parse rsa key, but the pem is empty")
	}
	block, _ := pem.Decode(key)
	if block == nil {
		return fmt.Errorf("error on parse rsa key, check if the key is valid")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}

	rsaKey, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("expected *rsa.PublicKey, got %T", pubInterface)
	}
	p.key = rsaKey
	return nil
}

func (p *RSAPubKey) KeyInfo() (*KeyInfo, error) {
	if p.Empty() {
		return nil, ErrorEmptyKey
	}
	bytes, err := p.Pem()
	if err != nil {
		return nil, err
	}
	return &KeyInfo{
		Type:   p.Type().Type(),
		Scheme: p.Type().Schema(),
		Value: map[string]string{
			"public": string(bytes),
		},
	}, nil
}

type RSAPrivKey struct {
	key *rsa.PrivateKey
}

func NewRSAPrivKey() PrivateKey {
	return &RSAPrivKey{}
}

func (p *RSAPrivKey) Empty() bool {
	return p.key == nil
}

func (p *RSAPrivKey) Type() CryptoType {
	return RSA_TYPE
}

func (p *RSAPrivKey) Signer() crypto.Signer {
	return p.key
}

func (p *RSAPrivKey) Public() PublicKey {
	if p.Empty() {
		return nil
	}
	pubKey := &RSAPubKey{}
	pubKey.SetKey(&p.key.PublicKey)
	return pubKey
}

func (p *RSAPrivKey) Key() crypto.PrivateKey {
	return p.key
}

func (p *RSAPrivKey) SetKey(k crypto.PrivateKey) error {
	rsaKey, ok := k.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("expected *rsa.PrivateKey, got %T", k)
	}
	p.key = rsaKey
	return nil
}

func (p *RSAPrivKey) Pem() ([]byte, error) {
	if p.Empty() {
		return nil, ErrorEmptyKey
	}

	asn1Bytes := x509.MarshalPKCS1PrivateKey(p.key)
	pemKey := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: asn1Bytes,
	}
	return pem.EncodeToMemory(pemKey), nil
}

func (p *RSAPrivKey) ParsePem(key []byte) error {
	if key == nil {
		return fmt.Errorf("error on parse rsa key, but the pem is empty")
	}
	block, _ := pem.Decode(key)
	if block == nil {
		return fmt.Errorf("error on parse rsa key, check if the key is valid")
	}
	privInterface, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	p.key = privInterface
	return nil
}

func (p *RSAPrivKey) KeyInfo() (*KeyInfo, error) {
	if p.Empty() {
		return nil, ErrorEmptyKey
	}
	bytes, err := p.Pem()
	if err != nil {
		return nil, err
	}
	return &KeyInfo{
		Type:   p.Type().Type(),
		Scheme: p.Type().Schema(),
		Value: map[string]string{
			"private": string(bytes),
		},
	}, nil
}

func (p *RSAPrivKey) Generate() error {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate RSA private key: %v", err)
	}
	p.key = privKey
	return nil
}
