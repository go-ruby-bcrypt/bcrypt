// Copyright (c) the go-ruby-bcrypt/bcrypt authors
//
// SPDX-License-Identifier: BSD-3-Clause

package bcrypt

import (
	"crypto/rand"
	"encoding/base64"
	"regexp"
	"strconv"

	"golang.org/x/crypto/blowfish"
)

// Engine mirrors Ruby's BCrypt::Engine: the low-level surface that hashes a
// secret against a salt, generates salts, and validates secrets and salts. Its
// methods are exposed as package functions on the Engine value returned by
// DefaultEngine, but are also available directly as package-level functions.
type Engine struct{}

// Engine cost constants, matching BCrypt::Engine.
const (
	// DefaultCost is the cost used when none is given (BCrypt::Engine::DEFAULT_COST).
	DefaultCost = 12
	// MinCost is the minimum cost the algorithm supports (BCrypt::Engine::MIN_COST).
	MinCost = 4
	// MaxCost is the maximum cost the algorithm supports (BCrypt::Engine::MAX_COST).
	MaxCost = 31
	// MaxSecretBytesize is the byte length secrets are truncated to before
	// hashing (BCrypt::Engine::MAX_SECRET_BYTESIZE). Older bcrypt libraries
	// truncated here and the gem keeps doing so for forward compatibility.
	MaxSecretBytesize = 72
	// MaxSaltLength is the raw salt length in bytes (BCrypt::Engine::MAX_SALT_LENGTH).
	MaxSaltLength = 16
)

// bcrypt encoding: the non-standard "./A-Za-z0-9" radix-64 alphabet the C
// bcrypt uses, identical to golang.org/x/crypto/bcrypt's internal encoding.
const bcAlphabet = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

var bcEncoding = base64.NewEncoding(bcAlphabet)

// magicCipherData is the IV for the 64 Blowfish encryption rounds: the string
// "OrpheanBeholderScryDoubt" in big-endian bytes.
var magicCipherData = []byte{
	0x4f, 0x72, 0x70, 0x68,
	0x65, 0x61, 0x6e, 0x42,
	0x65, 0x68, 0x6f, 0x6c,
	0x64, 0x65, 0x72, 0x53,
	0x63, 0x72, 0x79, 0x44,
	0x6f, 0x75, 0x62, 0x74,
}

// saltRe / hashRe are the exact grammars BCrypt::Engine.valid_salt? and
// BCrypt::Password.valid_hash? use.
var (
	saltRe = regexp.MustCompile(`^\$[0-9a-z]{2,}\$[0-9]{2,}\$[A-Za-z0-9./]{22,}$`)
	hashRe = regexp.MustCompile(`^\$[0-9a-z]{2}\$[0-9]{2}\$[A-Za-z0-9./]{53}$`)
)

// randRead is indirected so tests can drive salt generation deterministically
// and exercise the error branch.
var randRead = rand.Read

// bcBase64Encode encodes src with the bcrypt alphabet, stripping trailing '='.
func bcBase64Encode(src []byte) []byte {
	n := bcEncoding.EncodedLen(len(src))
	dst := make([]byte, n)
	bcEncoding.Encode(dst, src)
	for n > 0 && dst[n-1] == '=' {
		n--
	}
	return dst[:n]
}

// bcBase64Decode decodes src, which the encoder emitted without padding.
func bcBase64Decode(src []byte) ([]byte, error) {
	if pad := (4 - len(src)%4) % 4; pad != 0 {
		buf := make([]byte, len(src)+pad)
		copy(buf, src)
		for i := len(src); i < len(buf); i++ {
			buf[i] = '='
		}
		src = buf
	}
	dst := make([]byte, bcEncoding.DecodedLen(len(src)))
	n, err := bcEncoding.Decode(dst, src)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}

// expensiveBlowfishSetup performs the bcrypt key schedule: cost-many rounds of
// alternating key/salt expansion over a Blowfish cipher, byte-for-byte the same
// as golang.org/x/crypto/bcrypt (including the trailing-NUL key quirk). csalt
// must be the 16 raw salt bytes; the key is never empty (the appended NUL makes
// it length >= 1), so NewSaltedCipher cannot error here.
func expensiveBlowfishSetup(key []byte, cost uint32, csalt []byte) *blowfish.Cipher {
	// Bug compatibility with C bcrypt: the trailing NUL of the key string is
	// used during expansion.
	ckey := append(key[:len(key):len(key)], 0)

	c, _ := blowfish.NewSaltedCipher(ckey, csalt)
	rounds := uint64(1) << cost
	for i := uint64(0); i < rounds; i++ {
		blowfish.ExpandKey(ckey, c)
		blowfish.ExpandKey(csalt, c)
	}
	return c
}

// rawHash computes the 31-char bcrypt checksum for a (already truncated) secret,
// cost and raw 16-byte salt. It is the crypto core __bc_crypt maps to.
func rawHash(secret []byte, cost int, csalt []byte) []byte {
	cipherData := make([]byte, len(magicCipherData))
	copy(cipherData, magicCipherData)

	c := expensiveBlowfishSetup(secret, uint32(cost), csalt)
	for i := 0; i < 24; i += 8 {
		for j := 0; j < 64; j++ {
			c.Encrypt(cipherData[i:i+8], cipherData[i:i+8])
		}
	}
	// Bug compatibility: only 23 of the 24 encrypted bytes are encoded.
	return bcBase64Encode(cipherData[:23])
}

// ValidSecret reports whether secret is acceptable, mirroring
// BCrypt::Engine.valid_secret? (which accepts anything coercible to a string).
// A Go []byte is always valid.
func ValidSecret(secret []byte) bool { return secret != nil }

// ValidSalt reports whether salt matches the bcrypt salt grammar
// (BCrypt::Engine.valid_salt?).
func ValidSalt(salt string) bool { return saltRe.MatchString(salt) }

// GenerateSalt returns a random salt of the form "$2a$NN$...." for the given
// cost. A cost <= 0 returns ErrInvalidCost; a cost below MinCost is raised to
// MinCost, matching BCrypt::Engine.generate_salt.
func GenerateSalt(cost int) (string, error) {
	if cost <= 0 {
		return "", ErrInvalidCost
	}
	if cost < MinCost {
		cost = MinCost
	}
	raw := make([]byte, MaxSaltLength)
	if _, err := randRead(raw); err != nil {
		return "", err
	}
	return "$2a$" + twoDigit(cost) + "$" + string(bcBase64Encode(raw)), nil
}

// HashSecret hashes secret against a valid salt, returning the full
// "$2a$NN$...."-form hash. Secrets longer than MaxSecretBytesize are truncated,
// exactly like BCrypt::Engine.hash_secret. An invalid salt returns ErrInvalidSalt.
func HashSecret(secret []byte, salt string) (string, error) {
	if !ValidSecret(secret) {
		return "", ErrInvalidSecret
	}
	if !ValidSalt(salt) {
		return "", ErrInvalidSalt
	}
	if len(secret) > MaxSecretBytesize {
		secret = secret[:MaxSecretBytesize]
	}
	// ValidSalt guaranteed the shape "$vv$NN$<22+ radix-64 chars>": salt[4:6] is
	// two digits and salt[7:29] is 22 chars from the bcrypt alphabet, so neither
	// the cost parse nor the salt decode below can fail.
	csalt, _ := bcBase64Decode([]byte(salt[7 : 7+22]))
	cost, _ := strconv.Atoi(salt[4:6])
	checksum := rawHash(secret, cost, csalt)
	// Reassemble with the salt prefix through the encoded salt (29 chars).
	return salt[:29] + string(checksum), nil
}

// twoDigit renders n as a zero-padded two-digit decimal ("04", "12", "31").
func twoDigit(n int) string {
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}

// AutodetectCost extracts the cost embedded in a salt or hash string
// (BCrypt::Engine.autodetect_cost: salt[4..5].to_i). It returns 0 for a string
// too short to carry a cost.
func AutodetectCost(salt string) int {
	if len(salt) < 6 {
		return 0
	}
	n, _ := strconv.Atoi(salt[4:6])
	return n
}
