// Copyright (c) the go-ruby-bcrypt/bcrypt authors
//
// SPDX-License-Identifier: BSD-3-Clause

package bcrypt

import "strconv"

// Password is a parsed bcrypt password hash, mirroring Ruby's BCrypt::Password
// (which subclasses String). Its String form is the stored "$2a$NN$...." hash;
// Equal / EqualString compare a candidate secret against it in constant time.
type Password struct {
	hash     string // the full "$2a$NN$...." string
	version  string // e.g. "2a"
	cost     int    // e.g. 12
	salt     string // the first 29 chars: "$2a$NN$<22-char salt>"
	checksum string // the trailing 31-char digest
}

// CreateOption configures Create; the only knob the gem exposes is :cost.
type CreateOption func(*createOptions)

type createOptions struct {
	cost int
}

// WithCost sets the cost factor for Create (the gem's :cost option).
func WithCost(cost int) CreateOption {
	return func(o *createOptions) { o.cost = cost }
}

// Create hashes secret and returns a *Password, mirroring
// BCrypt::Password.create. Without WithCost it uses DefaultCost. A cost above
// MaxCost returns ErrCostTooHigh (the gem raises ArgumentError); a cost below
// MinCost is raised to MinCost by the salt generator.
func Create(secret []byte, opts ...CreateOption) (*Password, error) {
	o := createOptions{cost: DefaultCost}
	for _, fn := range opts {
		fn(&o)
	}
	if o.cost > MaxCost {
		return nil, ErrCostTooHigh
	}
	salt, err := GenerateSalt(o.cost)
	if err != nil {
		return nil, err
	}
	h, err := HashSecret(secret, salt)
	if err != nil {
		return nil, err
	}
	// h was produced from a freshly generated salt, so it is a well-formed hash
	// by construction; parse it without re-validating.
	return parseHash(h), nil
}

// CreateString is Create for a string secret.
func CreateString(secret string, opts ...CreateOption) (*Password, error) {
	return Create([]byte(secret), opts...)
}

// NewPassword parses a stored hash into a *Password, mirroring
// BCrypt::Password.new. A string that is not a valid bcrypt hash returns
// ErrInvalidHash.
func NewPassword(rawHash string) (*Password, error) {
	if !ValidHash(rawHash) {
		return nil, ErrInvalidHash
	}
	return parseHash(rawHash), nil
}

// parseHash builds a *Password from a hash already known to be well-formed.
func parseHash(rawHash string) *Password {
	v, cost, salt, checksum := splitHash(rawHash)
	return &Password{
		hash:     rawHash,
		version:  v,
		cost:     cost,
		salt:     salt,
		checksum: checksum,
	}
}

// ValidHash reports whether h matches the bcrypt hash grammar
// (BCrypt::Password.valid_hash?).
func ValidHash(h string) bool { return hashRe.MatchString(h) }

// splitHash breaks a valid hash into version, cost, salt (first 29 chars) and
// checksum (trailing 31 chars), exactly like BCrypt::Password#split_hash.
func splitHash(h string) (version string, cost int, salt, checksum string) {
	// h is "$v$cc$<22-char salt><31-char checksum>"; already validated.
	version = h[1:3]
	cost, _ = strconv.Atoi(h[4:6])
	salt = h[:29]
	checksum = h[len(h)-31:]
	return
}

// Equal reports whether secret is the secret this hash was derived from,
// comparing in constant time (BCrypt::Password#==). It re-hashes secret against
// this password's salt and compares the result to the stored hash.
func (p *Password) Equal(secret []byte) bool {
	h, err := HashSecret(secret, p.salt)
	if err != nil {
		return false
	}
	if h == "" || p.hash == "" || len(h) != len(p.hash) {
		return false
	}
	var res byte
	for i := 0; i < len(p.hash); i++ {
		res |= p.hash[i] ^ h[i]
	}
	return res == 0
}

// EqualString is Equal for a string secret.
func (p *Password) EqualString(secret string) bool { return p.Equal([]byte(secret)) }

// String returns the stored hash (BCrypt::Password#to_s).
func (p *Password) String() string { return p.hash }

// Version returns the algorithm version, e.g. "2a" (BCrypt::Password#version).
func (p *Password) Version() string { return p.version }

// Cost returns the cost factor (BCrypt::Password#cost).
func (p *Password) Cost() int { return p.cost }

// Salt returns the salt portion, the first 29 chars including version and cost
// (BCrypt::Password#salt).
func (p *Password) Salt() string { return p.salt }

// Checksum returns the trailing digest (BCrypt::Password#checksum).
func (p *Password) Checksum() string { return p.checksum }
