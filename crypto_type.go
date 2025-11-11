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
	"fmt"
)


 const (
	KeyTypeEd25519                = "ed25519"
	KeyTypeECDSA_SHA2_P256_COMPAT = "ecdsa-sha2-nistp256"
	KeyTypeECDSA_SHA2_P256        = "ecdsa"
	KeyTypeRSASSA_PSS_SHA256      = "rsa"
	KeySchemeEd25519              = "ed25519"
	KeySchemeECDSA_SHA2_P256      = "ecdsa-sha2-nistp256"
	KeySchemeECDSA_SHA2_P384      = "ecdsa-sha2-nistp384"
	KeySchemeRSASSA_PSS_SHA256    = "rsassa-pss-sha256"
)

type CryptoInfo struct {
	Short  string
	Type   string
	Schema string
}

var (
	InvalidCryptoInvalid = "INVALID"

	CryptoInfoList = []CryptoInfo{
		{
			Short:  "ed25519",
			Type:   KeyTypeEd25519,
			Schema: KeySchemeEd25519,
		},
		{
			Short:  "ecdsa-p256",
			Type:   KeyTypeECDSA_SHA2_P256_COMPAT,
			Schema: KeySchemeECDSA_SHA2_P256,
		},
		{
			Short:  "ecdsa",
			Type:   KeyTypeECDSA_SHA2_P256,
			Schema: KeySchemeECDSA_SHA2_P384,
		},
		{
			Short:  "rsa",
			Type:   KeyTypeRSASSA_PSS_SHA256,
			Schema: KeySchemeRSASSA_PSS_SHA256,
		},
	}
)

const (
	ED25519_TYPE    = 0
	RSA_TYPE        = 3
	ECDSA_P256_TYPE = 1
	ECDSA_TYPE      = 2
	INVALID_TYPE    = 4
)

func CryptoShortList(splite string) string {
	ret := CryptoInfoList[0].Short
	for i := 1; i < len(CryptoInfoList); i++ {
		ret = ret + splite + CryptoInfoList[i].Short
	}
	return ret
}

func CryptoTypeList(splite string) string {
	ret := CryptoInfoList[0].Type
	for i := 1; i < len(CryptoInfoList); i++ {
		ret = ret + splite + CryptoInfoList[i].Type
	}
	return ret
}

func CryptoSchemaList(splite string) string {
	ret := CryptoInfoList[0].Schema
	for i := 1; i < len(CryptoInfoList); i++ {
		ret = ret + splite + CryptoInfoList[i].Schema
	}
	return ret
}

type CryptoType int

func (l *CryptoType) String() string {
	if int(*l) >= 0 && int(*l) < len(CryptoInfoList) {
		return fmt.Sprintf("short:%s type:%s schema:%s",
			CryptoInfoList[*l].Short,
			CryptoInfoList[*l].Type,
			CryptoInfoList[*l].Schema)
	}
	return fmt.Sprintf("short:%s type:%s schema:%s",
		InvalidCryptoInvalid,
		InvalidCryptoInvalid,
		InvalidCryptoInvalid)
}

func (l *CryptoType) SetShort(value string) error {
	for i := 0; i < len(CryptoInfoList); i++ {
		if CryptoInfoList[i].Short == value {
			*l = CryptoType(i)
			return nil
		}
	}
	return fmt.Errorf("invalid crypto short type: %s, it should be oneof [%s]", value, CryptoShortList("|"))
}

func (l *CryptoType) Set(value string) error {
	for i := 0; i < len(CryptoInfoList); i++ {
		if CryptoInfoList[i].Type == value {
			*l = CryptoType(i)
			return nil
		}
	}
	return fmt.Errorf("invalid crypto type: %s, it should be oneof [%s]", value, CryptoTypeList("|"))
}

func (l *CryptoType) SetScheme(value string) error {
	for i := 0; i < len(CryptoInfoList); i++ {
		if CryptoInfoList[i].Schema == value {
			*l = CryptoType(i)
			return nil
		}
	}
	return fmt.Errorf("invalid crypto type: %s, it should be oneof [%s]", value, CryptoSchemaList("|"))
}

func (l *CryptoType) SetInt(value int) error {
	if value > 0 && value < len(CryptoInfoList) {
		*l = CryptoType(value)
		return nil
	}
	return fmt.Errorf("invalid crypto type: %d, it should be in range [0, %d]", value, len(CryptoInfoList))
}

func (l CryptoType) Short() string {
	if int(l) >= 0 && int(l) < len(CryptoInfoList) {
		return CryptoInfoList[l].Short
	}
	return InvalidCryptoInvalid
}

func (l CryptoType) Type() string {
	if int(l) >= 0 && int(l) < len(CryptoInfoList) {
		return CryptoInfoList[l].Type
	}
	return InvalidCryptoInvalid
}

func (l CryptoType) Schema() string {
	if int(l) >= 0 && int(l) < len(CryptoInfoList) {
		return CryptoInfoList[l].Schema
	}
	return InvalidCryptoInvalid
}

func (l CryptoType) Boolean() bool {
	if int(l) >= 0 && int(l) < len(CryptoInfoList) {
		return true
	}
	return false
}
