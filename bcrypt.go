// Copyright (c) the go-ruby-bcrypt/bcrypt authors
//
// SPDX-License-Identifier: BSD-3-Clause

// Package bcrypt is a pure-Go (no cgo) reimplementation of Ruby's bcrypt gem —
// BCrypt::Password and BCrypt::Engine — for hashing and verifying passwords with
// the OpenBSD bcrypt() algorithm.
//
// It produces and consumes the same "$2a$NN$...." hashes the gem does: a hash
// Create emits verifies under the gem's Password#==, and a gem-emitted hash
// verifies under Password.Equal. Secrets longer than 72 bytes are truncated
// exactly like the gem (and the older C libraries it stays compatible with), so
// hashes cross-verify in both directions at the 72-byte edge.
//
// The crypto core is the OpenBSD bcrypt key schedule over
// golang.org/x/crypto/blowfish; there is no cgo and no C bcrypt. It is the
// password-hashing backend for go-embedded-ruby, but is a standalone, reusable
// module — a sibling of go-ruby-yaml, go-ruby-regexp and go-ruby-erb.
//
// # Quick start
//
//	pw, _ := bcrypt.CreateString("secret", bcrypt.WithCost(12))
//	pw.EqualString("secret") // true
//	pw.EqualString("nope")   // false
//
//	stored, _ := bcrypt.NewPassword(pw.String())
//	stored.Cost()    // 12
//	stored.Version() // "2a"
package bcrypt

// Version is the version of this Go port. It is independent of the upstream
// Ruby gem's version.
const Version = "0.1.0"
