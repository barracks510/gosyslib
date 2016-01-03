// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Package SSHUtil provides some additional utilites to the
// golang.org/x/crypto/ssh libraries. These including methods for validating and
// parsing public keys.
package sshutil

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// SSH Public key struct as defined by the rfc4253 section 6.6
type OpenSSHPublicKey struct {
	algorithm string
	key       []byte
}

// An array of algorithms accepted by the SSH protocol.
var Algorithms = []string{
	ssh.KeyAlgoRSA,
	ssh.KeyAlgoDSA,
	ssh.KeyAlgoECDSA256,
	ssh.KeyAlgoECDSA384,
	ssh.KeyAlgoECDSA521,
}

func ValidateOpenSSHPublicKey(key OpenSSHPublicKey) error {
	_, err := ssh.ParsePublicKey(key.key)
	return err
}

// When given the contents of an public key file, this will return with a
// OpenSSHPublicKey struct that contains the contents of the keyfile. The
// comment section of the keyfile is ignored. The contents of the keyfile are
// not validated.
func ParseKeyfile(dotpub string) (key OpenSSHPublicKey, err error) {
	content := strings.Fields(dotpub)
	switch len(content) {
	case 1:
		decoded, err := base64.StdEncoding.DecodeString(content[0])
		if err != nil {
			return key, err
		}
		key.key = []byte(decoded)
		key.algorithm, err = GetAlgorithm(key.key)
		return key, nil
	case 2, 3:
		decoded, err := base64.StdEncoding.DecodeString(content[1])
		if err != nil {
			return key, err
		}
		key.key = []byte(decoded)
		_, ok := checkAlgorithm(content[0])
		if !ok {
			return key, errors.New("Cannot Parse: Bad Algorithm")
		}
		key.algorithm = content[0]
		test, err := GetAlgorithm(key.key)
		if err != nil {
			return key, err
		}
		if key.algorithm != test {
			return key, errors.New("Cannot Parse: Bad Keyformat")
		}
		return key, nil
	}
	return key, errors.New("Cannot Parse: Non-compliant Input")
}

// Given a byte array of SSH Key bytes, GetAlgorithm will deduce the public key
// format identifier. This is always included with traditional SSH Key
// algorithms as RSA and DSA.
func GetAlgorithm(key []byte) (string, error) {
	algo, _, ok := ParseDecodedKey(key)
	if !ok {
		return "", errors.New("Cannot Determine Algorithm: Bad Key")
	}
	return string(algo), nil
}

func checkAlgorithm(s string) (out string, ok bool) {
	for _, algorithm := range Algorithms {
		if s == algorithm {
			return algorithm, true
		}
	}
	return "", false
}

// Given a byte array of SSH Key bytes, ParseDecodedKey returns the public key
// format identifier as well as the remainder of the key data and a read OK
// return. This is implemented internally in crypto/ssh as parseString, but is
// included here as a general utility parser. If only the algorithm is wanted,
// GetAlgorithm provides better functionality.
func ParseDecodedKey(in []byte) (out, rest []byte, ok bool) {
	if len(in) < 4 {
		return
	}
	length := binary.BigEndian.Uint32(in)
	in = in[4:]
	if uint32(len(in)) < length {
		return
	}
	out = in[:length]
	rest = in[length:]
	ok = true
	return
}

func GetFingerPrint(key OpenSSHPublicKey, algo string) (fp string, err error) {
	pubkey, err := ssh.ParsePublicKey(key.key)
	if err != nil {
		return "", errors.New("Cannot Get Fingerprint: Cannot Parse")
	}

	var cs []byte
	switch algo {
	case "md5":
		tmp := md5.Sum(pubkey.Marshal())
		cs = tmp[:]
	case "sha224":
		tmp := sha256.Sum224(pubkey.Marshal())
		cs = tmp[:]
	case "sha256":
		tmp := sha256.Sum256(pubkey.Marshal())
		cs = tmp[:]
	case "sha384":
		tmp := sha512.Sum384(pubkey.Marshal())
		cs = tmp[:]
	case "sha512":
		tmp := sha512.Sum512(pubkey.Marshal())
		cs = tmp[:]
	default:
		tmp := sha256.Sum256(pubkey.Marshal())
		cs = tmp[:]
	}
	switch algo {
	case "md5":
		for i := 0; i < len(cs); i++ {
			fp = fmt.Sprintf("%s%0.2x", fp, cs[i])
			if i != len(cs)-1 {
				fp = fp + ":"
			}
		}
	default:
		fp = base64.StdEncoding.EncodeToString(cs)
	}
	return
}
