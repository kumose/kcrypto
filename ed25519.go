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
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

type Ed25519PubKey struct {
	key ed25519.PublicKey
}

func NewEd25519PubKey() PublicKey {
	return &Ed25519PubKey{}
}

func (p *Ed25519PubKey) Empty() bool {
	return len(p.key) == 0
}

func (p *Ed25519PubKey) Type() CryptoType {
	return ED25519_TYPE
}

func (p *Ed25519PubKey) Key() crypto.PublicKey {
	if p.Empty() {
		return nil
	}
	return p.key
}

// SetKey set raw public key
func (p *Ed25519PubKey) SetKey(k crypto.PublicKey) error {
	ed25519Key, ok := k.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("expected ed25519.PublicKey, got %T", k)
	}
	p.key = ed25519Key
	return nil
}

func (p *Ed25519PubKey) Pem() ([]byte, error) {
	if p.Empty() {
		return nil, ErrorEmptyKey
	}

	asn1Bytes, err := x509.MarshalPKIXPublicKey(p.key)
	if err != nil {
		return nil, err
	}
	pemKey := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}
	return pem.EncodeToMemory(pemKey), nil
}

func (p *Ed25519PubKey) ParsePem(key []byte) error {
	if key == nil {
		return fmt.Errorf("error on parse ed25519 key, but the pem is empty")
	}
	block, _ := pem.Decode(key)
	if block == nil {
		return fmt.Errorf("error on parse ed25519 key, check if the key is valid")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}

	ed25519Key, ok := pubInterface.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("expected ed25519 public key, got %T", pubInterface)
	}
	p.key = ed25519Key
	return nil
}

func (p *Ed25519PubKey) KeyInfo() (*KeyInfo, error) {
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

type Ed25519PrivKey struct {
	key ed25519.PrivateKey
}

func NewEd25519PrivKey() PrivateKey {
	return &Ed25519PrivKey{}
}

func (p *Ed25519PrivKey) Empty() bool {
	return len(p.key) == 0
}

func (p *Ed25519PrivKey) Type() CryptoType {
	return ED25519_TYPE
}

func (p *Ed25519PrivKey) Signer() crypto.Signer {
	if p.Empty() {
		return nil
	}
	return p.key
}

func (p *Ed25519PrivKey) Public() PublicKey {
	if p.Empty() {
		return nil
	}
	pubKey := &Ed25519PubKey{}
	pubKey.SetKey(p.key.Public())
	return pubKey
}

func (p *Ed25519PrivKey) Key() crypto.PrivateKey {
	if p.Empty() {
		return nil
	}
	return p.key
}

func (p *Ed25519PrivKey) SetKey(k crypto.PrivateKey) error {
	edKey, ok := k.(ed25519.PrivateKey)
	if !ok {
		return fmt.Errorf("expected ed25519.PrivateKey, got %T", k)
	}
	p.key = edKey
	return nil
}

func (p *Ed25519PrivKey) Pem() ([]byte, error) {
	if p.Empty() {
		return nil, ErrorEmptyKey
	}

	asn1Bytes, err := x509.MarshalPKCS8PrivateKey(p.key)
	if err != nil {
		return nil, err
	}
	pemKey := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: asn1Bytes,
	}
	return pem.EncodeToMemory(pemKey), nil
}

func (p *Ed25519PrivKey) ParsePem(key []byte) error {
	if key == nil {
		return fmt.Errorf("error on parse ed25519 key, but the pem is empty")
	}
	block, _ := pem.Decode(key)
	if block == nil {
		return fmt.Errorf("error on parse ed25519 key, check if the key is valid")
	}
	privInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return err
	}

	ed25519Key, ok := privInterface.(ed25519.PrivateKey)
	if !ok {
		return fmt.Errorf("expected ed25519 private key, got %T", privInterface)
	}
	p.key = ed25519Key
	return nil
}

func (p *Ed25519PrivKey) KeyInfo() (*KeyInfo, error) {
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

func (p *Ed25519PrivKey) Generate() error {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate ed25519 private key: %v", err)
	}
	p.key = privKey
	return nil
}
