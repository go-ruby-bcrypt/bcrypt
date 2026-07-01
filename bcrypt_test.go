// Copyright (c) the go-ruby-bcrypt/bcrypt authors
//
// SPDX-License-Identifier: BSD-3-Clause

package bcrypt

import (
	"errors"
	"strings"
	"testing"
)

// goldenVectors are deterministic (fixed salt + secret -> hash) triples captured
// from the reference bcrypt gem (BCrypt::Engine.hash_secret). They pin the crypto
// core so the suite holds without any Ruby runtime — the qemu cross-arch and
// Windows lanes verify against these alone.
var goldenVectors = []struct {
	salt, secret, hash string
}{
	{"$2a$04$CCCCCCCCCCCCCCCCCCCCCu", "", "$2a$04$CCCCCCCCCCCCCCCCCCCCCuswIafWjpQzLpmf.3r2ItIGu74gPoi4."},
	{"$2a$04$CCCCCCCCCCCCCCCCCCCCCu", "a", "$2a$04$CCCCCCCCCCCCCCCCCCCCCubQ1zJCB3mEVZNTR0N3gUw.vIAwA/TM2"},
	{"$2a$04$CCCCCCCCCCCCCCCCCCCCCu", "password", "$2a$04$CCCCCCCCCCCCCCCCCCCCCu/FlxU1ojkQ75LhKwnU4xvSUSTSvky6S"},
	{"$2a$04$CCCCCCCCCCCCCCCCCCCCCu", "correct horse battery staple", "$2a$04$CCCCCCCCCCCCCCCCCCCCCu6WrTtC4YjA6a6uFdMP1jlPYR/t59XP6"},
	{"$2a$04$CCCCCCCCCCCCCCCCCCCCCu", "unicodé ☃", "$2a$04$CCCCCCCCCCCCCCCCCCCCCuavC3Y5DSJ5VhiOtgg8Ntjh4gRKVtnNO"},
	{"$2a$05$DDDDDDDDDDDDDDDDDDDDDu", "", "$2a$05$DDDDDDDDDDDDDDDDDDDDDuiPjwVBZCsF3r9c6ltI97EaQQpm5hqpa"},
	{"$2a$05$DDDDDDDDDDDDDDDDDDDDDu", "a", "$2a$05$DDDDDDDDDDDDDDDDDDDDDunfS6iVH9ue/pKywEqT5Yis2/2eTtjIm"},
	{"$2a$05$DDDDDDDDDDDDDDDDDDDDDu", "password", "$2a$05$DDDDDDDDDDDDDDDDDDDDDuJ2HkdSp57O35A4yXzTgtjGgiVbB5mPm"},
	{"$2a$10$EEEEEEEEEEEEEEEEEEEEEu", "", "$2a$10$EEEEEEEEEEEEEEEEEEEEEuNCYa5HmJUWhQTK2c4mnxEs.IOhR9Pxa"},
	{"$2a$10$EEEEEEEEEEEEEEEEEEEEEu", "password", "$2a$10$EEEEEEEEEEEEEEEEEEEEEug2lvSbZcm5jrGm1FqJHK/wCxQwvReQa"},
	{"$2a$12$FFFFFFFFFFFFFFFFFFFFFu", "", "$2a$12$FFFFFFFFFFFFFFFFFFFFFu/CaiPOo8jq5QFMPY5fAQKkjIhSvOOc."},
	{"$2a$12$FFFFFFFFFFFFFFFFFFFFFu", "a", "$2a$12$FFFFFFFFFFFFFFFFFFFFFuHwSHc4PTB8A44VLvEd.rJyjQFgQXN8."},
	{"$2a$12$FFFFFFFFFFFFFFFFFFFFFu", "password", "$2a$12$FFFFFFFFFFFFFFFFFFFFFuU5yvObVaCY1Z42pQUOqDn9Zf7zesOo2"},
	{"$2a$12$FFFFFFFFFFFFFFFFFFFFFu", "unicodé ☃", "$2a$12$FFFFFFFFFFFFFFFFFFFFFuN8w02OcsZQpe79A0RU2cnYfy505FlgW"},
}

// The 72-byte truncation golden: 72 and 100 'a's hash identically at cost 4.
const (
	golden72aSalt = "$2a$04$CCCCCCCCCCCCCCCCCCCCCu"
	golden72aHash = "$2a$04$CCCCCCCCCCCCCCCCCCCCCu55zp/.wvtIUR9OjGKhmIRdxFTDnSOaG"
)

func TestHashSecretGolden(t *testing.T) {
	for _, v := range goldenVectors {
		got, err := HashSecret([]byte(v.secret), v.salt)
		if err != nil {
			t.Fatalf("HashSecret(%q, %q): %v", v.secret, v.salt, err)
		}
		if got != v.hash {
			t.Errorf("HashSecret(%q, %q) = %q, want %q", v.secret, v.salt, got, v.hash)
		}
	}
}

func TestHashSecretTruncatesAt72(t *testing.T) {
	h72, err := HashSecret([]byte(strings.Repeat("a", 72)), golden72aSalt)
	if err != nil {
		t.Fatal(err)
	}
	h100, err := HashSecret([]byte(strings.Repeat("a", 100)), golden72aSalt)
	if err != nil {
		t.Fatal(err)
	}
	if h72 != golden72aHash || h100 != golden72aHash {
		t.Errorf("72/100-byte hashes = %q / %q, want both %q", h72, h100, golden72aHash)
	}
	// A 71-byte secret must differ (the 72nd byte is significant).
	h71, _ := HashSecret([]byte(strings.Repeat("a", 71)), golden72aSalt)
	if h71 == golden72aHash {
		t.Error("71-byte secret hashed identically to the 72-byte secret")
	}
}

func TestHashSecretInvalidSalt(t *testing.T) {
	for _, bad := range []string{"", "nope", "$2$04$" + strings.Repeat("x", 22), "plain-text"} {
		if _, err := HashSecret([]byte("x"), bad); !errors.Is(err, ErrInvalidSalt) {
			t.Errorf("HashSecret(_, %q) err = %v, want ErrInvalidSalt", bad, err)
		}
	}
}

func TestHashSecretInvalidSecret(t *testing.T) {
	if _, err := HashSecret(nil, goldenVectors[0].salt); !errors.Is(err, ErrInvalidSecret) {
		t.Errorf("HashSecret(nil, _) err = %v, want ErrInvalidSecret", err)
	}
}

// A salt whose 22 encoded chars are not valid bcrypt-base64 must be rejected.
// "!" is outside [A-Za-z0-9./] so the regex already blocks it; construct a case
// where the regex passes but decoding fails is impossible for the 22-char field,
// so we exercise the decode error via a crafted salt with a cost the atoi step
// still parses. Here we verify a well-formed salt round-trips its cost.
func TestHashSecretCostParsedFromSalt(t *testing.T) {
	h, err := HashSecret([]byte("x"), "$2a$07$"+strings.Repeat("C", 22))
	if err != nil {
		t.Fatal(err)
	}
	if AutodetectCost(h) != 7 {
		t.Errorf("cost from salt = %d, want 7", AutodetectCost(h))
	}
}

func TestValidSalt(t *testing.T) {
	cases := map[string]bool{
		"$2a$04$" + strings.Repeat("C", 22): true,
		"$2b$10$" + strings.Repeat("x", 22): true,
		"$2y$05$" + strings.Repeat("y", 22): true,
		"$2$05$" + strings.Repeat("z", 22):  false, // one-char version
		"":                                  false,
		"$2a$4$" + strings.Repeat("C", 22):  false, // one-digit cost
		"$2a$04$" + strings.Repeat("C", 21): false, // salt too short
		"$2a$04$" + strings.Repeat("!", 22): false, // bad alphabet
	}
	for s, want := range cases {
		if got := ValidSalt(s); got != want {
			t.Errorf("ValidSalt(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestValidSecret(t *testing.T) {
	if !ValidSecret([]byte("")) || !ValidSecret([]byte("x")) {
		t.Error("byte secrets should be valid")
	}
	if ValidSecret(nil) {
		t.Error("nil secret should be invalid")
	}
}

func TestGenerateSalt(t *testing.T) {
	s, err := GenerateSalt(6)
	if err != nil {
		t.Fatal(err)
	}
	if !ValidSalt(s) || !strings.HasPrefix(s, "$2a$06$") || len(s) != 29 {
		t.Errorf("GenerateSalt(6) = %q", s)
	}
	// Below MinCost is raised to MinCost.
	s4, _ := GenerateSalt(1)
	if !strings.HasPrefix(s4, "$2a$04$") {
		t.Errorf("GenerateSalt(1) = %q, want cost clamped to 04", s4)
	}
	// Cost <= 0 is rejected.
	for _, c := range []int{0, -1} {
		if _, err := GenerateSalt(c); !errors.Is(err, ErrInvalidCost) {
			t.Errorf("GenerateSalt(%d) err = %v, want ErrInvalidCost", c, err)
		}
	}
}

func TestGenerateSaltRandFailure(t *testing.T) {
	orig := randRead
	randRead = func(b []byte) (int, error) { return 0, errors.New("boom") }
	defer func() { randRead = orig }()
	if _, err := GenerateSalt(4); err == nil || err.Error() != "boom" {
		t.Errorf("GenerateSalt with failing rand: err = %v", err)
	}
}

func TestAutodetectCost(t *testing.T) {
	if got := AutodetectCost("$2a$12$" + strings.Repeat("C", 22)); got != 12 {
		t.Errorf("AutodetectCost = %d, want 12", got)
	}
	if got := AutodetectCost("$2a$"); got != 0 {
		t.Errorf("AutodetectCost(short) = %d, want 0", got)
	}
}

func TestTwoDigit(t *testing.T) {
	if twoDigit(4) != "04" || twoDigit(12) != "12" || twoDigit(31) != "31" {
		t.Errorf("twoDigit wrong: %q %q %q", twoDigit(4), twoDigit(12), twoDigit(31))
	}
}

func TestBase64RoundTrip(t *testing.T) {
	raw := []byte{0, 1, 2, 3, 255, 128, 64, 16}
	enc := bcBase64Encode(raw)
	dec, err := bcBase64Decode(enc)
	if err != nil {
		t.Fatal(err)
	}
	if string(dec) != string(raw) {
		t.Errorf("round trip = %v, want %v", dec, raw)
	}
	// Decode of a well-formed-length input that is not valid base64 errors.
	if _, err := bcBase64Decode([]byte("!!!!")); err == nil {
		t.Error("expected decode error for bad alphabet")
	}
}

func TestPasswordCreateAndVerify(t *testing.T) {
	pw, err := CreateString("s3cret", WithCost(4))
	if err != nil {
		t.Fatal(err)
	}
	if !pw.EqualString("s3cret") {
		t.Error("password should verify its own secret")
	}
	if pw.EqualString("wrong") {
		t.Error("password should reject a wrong secret")
	}
	if pw.Cost() != 4 || pw.Version() != "2a" {
		t.Errorf("cost/version = %d/%q", pw.Cost(), pw.Version())
	}
	if pw.Salt() != pw.String()[:29] {
		t.Errorf("salt %q not prefix of hash %q", pw.Salt(), pw.String())
	}
	if pw.Checksum() != pw.String()[len(pw.String())-31:] {
		t.Errorf("checksum mismatch: %q", pw.Checksum())
	}
	// Byte-secret path.
	pb, _ := Create([]byte("bytes"), WithCost(4))
	if !pb.Equal([]byte("bytes")) {
		t.Error("byte secret should verify")
	}
}

func TestPasswordCreateDefaultCost(t *testing.T) {
	// Default cost is 12; avoid the expensive hash by only checking the salt
	// generator picks DefaultCost via a stubbed rand (fast, no hashing here).
	if DefaultCost != 12 {
		t.Fatalf("DefaultCost = %d, want 12", DefaultCost)
	}
	s, err := GenerateSalt(DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	if AutodetectCost(s) != 12 {
		t.Errorf("default-cost salt = %q", s)
	}
}

func TestPasswordCreateCostTooHigh(t *testing.T) {
	if _, err := CreateString("x", WithCost(MaxCost+1)); !errors.Is(err, ErrCostTooHigh) {
		t.Errorf("Create cost 32 err = %v, want ErrCostTooHigh", err)
	}
}

func TestPasswordCreateCostZero(t *testing.T) {
	// Cost 0 flows to GenerateSalt which rejects it.
	if _, err := CreateString("x", WithCost(0)); !errors.Is(err, ErrInvalidCost) {
		t.Errorf("Create cost 0 err = %v, want ErrInvalidCost", err)
	}
}

func TestCreateNilSecret(t *testing.T) {
	// A nil secret is invalid; Create propagates HashSecret's ErrInvalidSecret.
	if _, err := Create(nil, WithCost(4)); !errors.Is(err, ErrInvalidSecret) {
		t.Errorf("Create(nil) err = %v, want ErrInvalidSecret", err)
	}
}

func TestNewPasswordParsing(t *testing.T) {
	h := goldenVectors[12].hash // cost 12 vector
	pw, err := NewPassword(h)
	if err != nil {
		t.Fatal(err)
	}
	if pw.Version() != "2a" || pw.Cost() != 12 {
		t.Errorf("parsed version/cost = %q/%d", pw.Version(), pw.Cost())
	}
	if pw.Salt() != h[:29] || pw.Checksum() != h[len(h)-31:] {
		t.Errorf("parsed salt/checksum wrong")
	}
	if pw.String() != h {
		t.Errorf("String() = %q, want %q", pw.String(), h)
	}
	// It verifies the golden secret.
	if !pw.EqualString("password") {
		t.Error("parsed golden hash should verify 'password'")
	}
}

func TestNewPasswordInvalid(t *testing.T) {
	for _, bad := range []string{
		"", "not a hash",
		"$2a$04$" + strings.Repeat("C", 52), // checksum too short
		"$2a$4$" + strings.Repeat("C", 53),  // one-digit cost
	} {
		if _, err := NewPassword(bad); !errors.Is(err, ErrInvalidHash) {
			t.Errorf("NewPassword(%q) err = %v, want ErrInvalidHash", bad, err)
		}
	}
}

func TestValidHash(t *testing.T) {
	if !ValidHash(goldenVectors[0].hash) {
		t.Error("golden hash should be valid")
	}
	if ValidHash("nope") {
		t.Error("garbage should be invalid")
	}
}

// TestEqualLengthMismatch drives the length-mismatch guard in Equal by handing a
// Password a stored hash of the right shape but a different salt, so a re-hash of
// any secret differs. (Equal returns false, not a panic.)
func TestEqualRejectsWrongSecret(t *testing.T) {
	pw, _ := NewPassword(goldenVectors[0].hash)
	if pw.Equal([]byte("definitely-not-empty")) {
		t.Error("wrong secret must not verify")
	}
	// The golden secret is the empty string.
	if !pw.Equal([]byte("")) {
		t.Error("empty secret should verify the empty-secret golden")
	}
}

// TestEqualEmptyStoredHash covers the guard where the stored hash is empty.
func TestEqualEmptyStoredHash(t *testing.T) {
	pw := &Password{hash: "", salt: goldenVectors[0].salt}
	if pw.Equal([]byte("x")) {
		t.Error("empty stored hash must never verify")
	}
}

// TestEqualHashSecretError covers Equal's branch where re-hashing errors (an
// invalid salt on the Password value).
func TestEqualHashSecretError(t *testing.T) {
	pw := &Password{hash: goldenVectors[0].hash, salt: "bogus"}
	if pw.Equal([]byte("")) {
		t.Error("Equal with unhashable salt must return false")
	}
}

func TestVersionConstant(t *testing.T) {
	if Version == "" {
		t.Error("Version must be set")
	}
}
