// Copyright (c) the go-ruby-bcrypt/bcrypt authors
//
// SPDX-License-Identifier: BSD-3-Clause

package bcrypt

import "errors"

// The package's sentinel errors mirror the exception hierarchy of the Ruby
// bcrypt gem's BCrypt::Errors module: InvalidSecret, InvalidCost, InvalidSalt
// and InvalidHash. A caller can match them with errors.Is.
var (
	// ErrInvalidSecret is returned when a secret cannot be coerced to a string
	// (BCrypt::Errors::InvalidSecret). In this Go port a []byte / string secret
	// is always valid, so this only surfaces from the low-level engine guard.
	ErrInvalidSecret = errors.New("bcrypt: invalid secret")

	// ErrInvalidCost is returned when a cost is not numeric and > 0
	// (BCrypt::Errors::InvalidCost), matching Engine.generate_salt.
	ErrInvalidCost = errors.New("bcrypt: cost must be numeric and > 0")

	// ErrInvalidSalt is returned when a salt does not match the bcrypt salt
	// grammar (BCrypt::Errors::InvalidSalt).
	ErrInvalidSalt = errors.New("bcrypt: invalid salt")

	// ErrInvalidHash is returned when a stored hash does not match the bcrypt
	// hash grammar (BCrypt::Errors::InvalidHash).
	ErrInvalidHash = errors.New("bcrypt: invalid hash")

	// ErrCostTooHigh is returned by Password.create when the requested cost
	// exceeds MaxCost. The gem raises a bare ArgumentError here.
	ErrCostTooHigh = errors.New("bcrypt: cost exceeds the maximum allowed")
)
