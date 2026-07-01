// Copyright (c) the go-ruby-bcrypt/bcrypt authors
//
// SPDX-License-Identifier: BSD-3-Clause

package bcrypt

import (
	"os/exec"
	"strings"
	"testing"
)

// rubyBcrypt locates a `ruby` whose bcrypt gem loads and whose RUBY_VERSION is
// at least 4.0, returning the binary path. The oracle tests skip themselves when
// ruby, the gem, or a recent-enough version is absent (the qemu cross-arch and
// Windows lanes, and any host without the gem installed), so the deterministic
// golden suite alone drives the 100% gate there.
func rubyBcrypt(t *testing.T) string {
	t.Helper()
	bin, err := exec.LookPath("ruby")
	if err != nil {
		t.Skip("ruby not on PATH; skipping bcrypt gem oracle")
	}
	// Version-gate on RUBY_VERSION >= "4.0" and confirm the gem loads.
	out, err := exec.Command(bin, "-rbcrypt", "-e",
		`exit(RUBY_VERSION >= "4.0" ? 0 : 3)`).CombinedOutput()
	if err != nil {
		t.Skipf("ruby<4.0 or bcrypt gem unavailable; skipping oracle (%v: %s)", err, out)
	}
	return bin
}

// ruby runs a bcrypt script and returns trimmed stdout. The script $stdout.binmode's
// itself so Windows text-mode never pollutes the bytes.
func ruby(t *testing.T, bin, script string) string {
	t.Helper()
	cmd := exec.Command(bin, "-rbcrypt", "-e", "$stdout.binmode\n"+script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ruby error: %v\nscript:\n%s\noutput:\n%s", err, script, out)
	}
	return strings.TrimRight(string(out), "\n")
}

// TestOracleGemVerifiesOurHash: hashes here, and the gem's Password#== accepts our
// hash for the right secret and rejects a wrong one — the "our -> gem" direction,
// across several costs and secrets.
func TestOracleGemVerifiesOurHash(t *testing.T) {
	bin := rubyBcrypt(t)
	cases := []struct {
		secret string
		cost   int
	}{
		{"", 4},
		{"a", 4},
		{"password", 5},
		{"correct horse battery staple", 4},
		{"unicodé ☃", 6},
		{strings.Repeat("x", 40), 4},
	}
	for _, c := range cases {
		pw, err := CreateString(c.secret, WithCost(c.cost))
		if err != nil {
			t.Fatalf("CreateString(%q, cost %d): %v", c.secret, c.cost, err)
		}
		script := "p BCrypt::Password.new(" + rubyStr(pw.String()) + ") == " + rubyStr(c.secret) + "\n" +
			"p BCrypt::Password.new(" + rubyStr(pw.String()) + ") == " + rubyStr(c.secret+"X") + "\n" +
			"p BCrypt::Password.new(" + rubyStr(pw.String()) + ").cost\n"
		got := ruby(t, bin, script)
		want := "true\nfalse\n" + itoa(c.cost)
		if got != want {
			t.Errorf("gem verify of our %q hash =\n%s\nwant\n%s", c.secret, got, want)
		}
	}
}

// TestOracleWeVerifyGemHash: the gem hashes, and our Password.Equal accepts its
// hash for the right secret and rejects a wrong one — the "gem -> our" direction.
func TestOracleWeVerifyGemHash(t *testing.T) {
	bin := rubyBcrypt(t)
	for _, secret := range []string{"", "a", "password", "üî∂ secret", strings.Repeat("z", 50)} {
		gemHash := ruby(t, bin,
			"print BCrypt::Password.create("+rubyStr(secret)+", cost: 4)\n")
		pw, err := NewPassword(gemHash)
		if err != nil {
			t.Fatalf("NewPassword(gem %q): %v\nhash: %q", secret, err, gemHash)
		}
		if !pw.EqualString(secret) {
			t.Errorf("we reject the gem's hash of %q (%q)", secret, gemHash)
		}
		if pw.EqualString(secret + "!") {
			t.Errorf("we accept a wrong secret for the gem's hash of %q", secret)
		}
	}
}

// TestOracleParsingMatchesGem: our .cost/.salt/.version/.checksum parsing agrees
// with the gem's for a gem-produced hash.
func TestOracleParsingMatchesGem(t *testing.T) {
	bin := rubyBcrypt(t)
	fields := ruby(t, bin,
		"pw = BCrypt::Password.create(\"parse-me\", cost: 5)\n"+
			"puts pw.to_s\nputs pw.version\nputs pw.cost\nputs pw.salt\nputs pw.checksum\n")
	lines := strings.Split(fields, "\n")
	if len(lines) != 5 {
		t.Fatalf("expected 5 gem fields, got %d: %q", len(lines), fields)
	}
	pw, err := NewPassword(lines[0])
	if err != nil {
		t.Fatal(err)
	}
	if pw.Version() != lines[1] {
		t.Errorf("version = %q, gem %q", pw.Version(), lines[1])
	}
	if itoa(pw.Cost()) != lines[2] {
		t.Errorf("cost = %d, gem %q", pw.Cost(), lines[2])
	}
	if pw.Salt() != lines[3] {
		t.Errorf("salt = %q, gem %q", pw.Salt(), lines[3])
	}
	if pw.Checksum() != lines[4] {
		t.Errorf("checksum = %q, gem %q", pw.Checksum(), lines[4])
	}
}

// TestOracle72ByteEdge: the gem truncates a >72-byte secret at 72 bytes. Our hash
// of the first 72 bytes must be accepted by the gem for the full secret, and the
// gem's hash of the full secret must be accepted by us for the 72-byte prefix —
// the NUL/truncation edge crossing both directions.
func TestOracle72ByteEdge(t *testing.T) {
	bin := rubyBcrypt(t)
	full := strings.Repeat("a", 100)
	trunc := full[:72]

	// our (72-byte) hash, verified by the gem against the full 100-byte secret.
	pw, err := CreateString(trunc, WithCost(4))
	if err != nil {
		t.Fatal(err)
	}
	got := ruby(t, bin,
		"p BCrypt::Password.new("+rubyStr(pw.String())+") == "+rubyStr(full)+"\n"+
			"p BCrypt::Password.new("+rubyStr(pw.String())+") == "+rubyStr(full[:71])+"\n")
	if got != "true\nfalse" {
		t.Errorf("gem verify of our truncated hash = %q, want \"true\\nfalse\"", got)
	}

	// gem's hash of the full 100-byte secret, verified by us against the 72-byte
	// prefix (and the full secret, which we also truncate to 72).
	gemHash := ruby(t, bin, "print BCrypt::Password.create("+rubyStr(full)+", cost: 4)\n")
	gpw, err := NewPassword(gemHash)
	if err != nil {
		t.Fatal(err)
	}
	if !gpw.EqualString(trunc) || !gpw.EqualString(full) {
		t.Errorf("we fail to verify the gem's truncated hash (72-prefix or full)")
	}
	if gpw.EqualString(full[:71]) {
		t.Error("a 71-byte secret must not verify the 72-byte-truncated gem hash")
	}
}

// TestOracleGenerateSaltAcceptedByGem: a salt we generate is accepted by the gem's
// valid_salt?, and hashing a secret against it agrees in both engines.
func TestOracleGenerateSaltAcceptedByGem(t *testing.T) {
	bin := rubyBcrypt(t)
	salt, err := GenerateSalt(4)
	if err != nil {
		t.Fatal(err)
	}
	ourHash, err := HashSecret([]byte("shared"), salt)
	if err != nil {
		t.Fatal(err)
	}
	got := ruby(t, bin,
		"p BCrypt::Engine.valid_salt?("+rubyStr(salt)+")\n"+
			"print BCrypt::Engine.hash_secret("+rubyStr("shared")+", "+rubyStr(salt)+")\n")
	want := "true\n" + ourHash
	if got != want {
		t.Errorf("gem salt/hash agreement =\n%q\nwant\n%q", got, want)
	}
}

// rubyStr renders s as a Ruby double-quoted byte string literal using \xNN escapes,
// so arbitrary bytes (including UTF-8 and control chars) survive intact.
func rubyStr(s string) string {
	var b strings.Builder
	b.WriteString(`"`)
	for i := 0; i < len(s); i++ {
		b.WriteString("\\x")
		const hex = "0123456789ABCDEF"
		b.WriteByte(hex[s[i]>>4])
		b.WriteByte(hex[s[i]&0xf])
	}
	b.WriteString(`"`)
	return b.String()
}

// itoa is strconv.Itoa without the import churn in this test file.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
