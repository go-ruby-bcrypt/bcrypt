<p align="center"><img src="https://raw.githubusercontent.com/go-ruby-bcrypt/brand/main/social/go-ruby-bcrypt-bcrypt.png" alt="go-ruby-bcrypt/bcrypt" width="720"></p>

# bcrypt — go-ruby-bcrypt

[![Docs](https://img.shields.io/badge/docs-mkdocs--material-DC2626)](https://go-ruby-bcrypt.github.io/docs/)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.26.4%2B-00ADD8)](https://go.dev/dl/)
[![Coverage](https://img.shields.io/badge/coverage-100%25-1a7f37)](#tests--coverage)

**A pure-Go (no cgo) reimplementation of Ruby's [`bcrypt`](https://github.com/bcrypt-ruby/bcrypt-ruby)
gem** — `BCrypt::Password` and `BCrypt::Engine` — for hashing and verifying
passwords with the OpenBSD bcrypt() algorithm. It produces and consumes the same
`$2a$` hashes the gem does, so a hash created here verifies under the gem's
`Password#==` and a gem-created hash verifies here — **without any Ruby runtime**.

It is the password-hashing backend for
[go-embedded-ruby](https://github.com/go-embedded-ruby/ruby), but is a
**standalone, reusable** module — a sibling of
[go-ruby-yaml](https://github.com/go-ruby-yaml/yaml) (the Psych port),
[go-ruby-regexp](https://github.com/go-ruby-regexp/regexp) (the Onigmo engine)
and [go-ruby-erb](https://github.com/go-ruby-erb/erb) (the ERB compiler).

## Cross-compatible with the gem, both directions

The crypto core is the OpenBSD bcrypt key schedule over
[`golang.org/x/crypto/blowfish`](https://pkg.go.dev/golang.org/x/crypto/blowfish);
there is no cgo and no C bcrypt.

- **Our hash → gem.** `Create` emits a `$2a$NN$…` hash the gem's
  `BCrypt::Password.new(hash) == secret` accepts.
- **Gem hash → us.** `NewPassword(gemHash).EqualString(secret)` accepts a hash the
  gem produced.
- **72-byte truncation.** The gem truncates secrets to 72 bytes before hashing
  (staying compatible with the older C library). This port truncates identically,
  so a secret longer than 72 bytes hashes to the same value here and in the gem
  and cross-verifies at the edge in both directions.

## Features

Faithful port of the gem's public surface, validated against the `bcrypt` gem on
every platform that has it:

- **`Password`** — `Create` / `CreateString` (default cost 12, `$2a$`),
  `NewPassword`, constant-time `Equal` / `EqualString`, and `Cost` / `Salt` /
  `Version` / `Checksum` / `String` accessors, matching `BCrypt::Password`.
- **`Engine`** — `HashSecret`, `GenerateSalt(cost)`, `ValidSecret`, `ValidSalt`,
  `ValidHash`, `AutodetectCost`, and the `MinCost` / `MaxCost` / `DefaultCost` /
  `MaxSecretBytesize` / `MaxSaltLength` bounds, matching `BCrypt::Engine`.
- **Gem-faithful cost handling** — a cost below `MinCost` (4) is raised to 4, a
  cost of 0 or below is rejected (`ErrInvalidCost`), and a cost above `MaxCost`
  (31) is rejected (`ErrCostTooHigh`, the gem's `ArgumentError`).
- **`Errors`** — sentinel errors mirroring `BCrypt::Errors` (`ErrInvalidSecret`,
  `ErrInvalidCost`, `ErrInvalidSalt`, `ErrInvalidHash`), matchable with
  `errors.Is`.

CGO-free, **100% test coverage**, `gofmt` + `go vet` clean, and green across the
six 64-bit Go targets (amd64, arm64, riscv64, loong64, ppc64le, s390x).

## Install

```sh
go get github.com/go-ruby-bcrypt/bcrypt
```

## Usage

```go
package main

import (
	"fmt"

	"github.com/go-ruby-bcrypt/bcrypt"
)

func main() {
	// Hash a secret (default cost 12; WithCost overrides).
	pw, _ := bcrypt.CreateString("my grand secret", bcrypt.WithCost(12))
	fmt.Println(pw.String()) // $2a$12$C5.FIvVDS9W4AYZ/Ib37Yu…

	// Verify, in constant time.
	fmt.Println(pw.EqualString("my grand secret")) // true
	fmt.Println(pw.EqualString("a paltry guess"))  // false

	// Parse a stored hash back.
	stored, _ := bcrypt.NewPassword(pw.String())
	fmt.Println(stored.Cost(), stored.Version()) // 12 2a
	fmt.Println(stored.Salt())                   // $2a$12$C5.FIvVDS9W4AYZ/Ib37Yu

	// Low-level engine: hash a secret against a specific salt.
	salt, _ := bcrypt.GenerateSalt(10)
	h, _ := bcrypt.HashSecret([]byte("secret"), salt)
	fmt.Println(h)
}
```

## API

```go
// Password (BCrypt::Password)
func Create(secret []byte, opts ...CreateOption) (*Password, error)
func CreateString(secret string, opts ...CreateOption) (*Password, error)
func NewPassword(rawHash string) (*Password, error)
func WithCost(cost int) CreateOption

func (p *Password) Equal(secret []byte) bool
func (p *Password) EqualString(secret string) bool
func (p *Password) String() string   // to_s
func (p *Password) Version() string  // "2a"
func (p *Password) Cost() int
func (p *Password) Salt() string
func (p *Password) Checksum() string

// Engine (BCrypt::Engine)
func HashSecret(secret []byte, salt string) (string, error)
func GenerateSalt(cost int) (string, error)
func ValidSecret(secret []byte) bool
func ValidSalt(salt string) bool
func ValidHash(h string) bool
func AutodetectCost(salt string) int

const (
	DefaultCost       = 12 // DEFAULT_COST
	MinCost           = 4  // MIN_COST
	MaxCost           = 31 // MAX_COST
	MaxSecretBytesize = 72 // MAX_SECRET_BYTESIZE
	MaxSaltLength     = 16 // MAX_SALT_LENGTH
)

// Errors (BCrypt::Errors), matchable with errors.Is.
var ErrInvalidSecret, ErrInvalidCost, ErrInvalidSalt, ErrInvalidHash, ErrCostTooHigh error
```

## Tests & coverage

The suite pairs deterministic, ruby-free **golden vectors** (fixed salt + secret →
hash, captured from the gem; these alone hold coverage at 100%, so the qemu
cross-arch and Windows lanes pass the gate) with a **differential gem oracle**
gated on `RUBY_VERSION >= "4.0"`: hashes made here are verified by the gem's
`Password#==`, gem-made hashes are verified here, `.cost` / `.salt` / `.version` /
`.checksum` parsing is compared against the gem, and the 72-byte truncation edge
is crossed in both directions. The oracle scripts `$stdout.binmode` so Windows
text-mode never pollutes the bytes, and skip themselves where `ruby` or the gem is
absent.

```sh
COVERPKG=$(go list ./... | paste -sd, -)
go test -race -coverpkg="$COVERPKG" -coverprofile=cover.out ./...
go tool cover -func=cover.out | tail -1   # 100.0%
```

## License

BSD-3-Clause — see [LICENSE](LICENSE). Copyright the go-ruby-bcrypt/bcrypt authors.

## WebAssembly

Being pure Go (CGO=0), this library also compiles to **WebAssembly** — both
`GOOS=js GOARCH=wasm` (browser / Node.js) and `GOOS=wasip1 GOARCH=wasm` (WASI).
CI builds both targets on every push, alongside the six 64-bit native/qemu arches.

```sh
GOOS=js     GOARCH=wasm go build ./...   # browser / Node
GOOS=wasip1 GOARCH=wasm go build ./...   # WASI (wasmtime, wasmer, wasmedge, …)
```
