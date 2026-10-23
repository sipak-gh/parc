package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func writeKey(t testing.TB, dir, name string, priv any, pass string) string {
	t.Helper()
	var blk *pem.Block
	var err error
	if pass != "" {
		blk, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(pass))
	} else {
		blk, err = ssh.MarshalPrivateKey(priv, "")
	}
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, pem.EncodeToMemory(blk), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func edKey(t testing.TB, dir, name string) string {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return writeKey(t, dir, name, priv, "")
}

func mustKM(t testing.TB, path string) *keyMaterial {
	t.Helper()
	km, err := loadKey(path)
	if err != nil {
		t.Fatal(err)
	}
	return km
}

func write(t testing.TB, p string, b []byte) {
	t.Helper()
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func read(t testing.TB, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func exists(p string) bool { _, err := os.Lstat(p); return err == nil }

// ---- name encryption ----

func TestNameRoundTrip(t *testing.T) {
	km := mustKM(t, edKey(t, t.TempDir(), "k"))
	names := []string{
		"a", "file.txt", "with space.txt", "ünïcødé-日本語.md", ".hidden", "-dash", "a.b.c.tar.gz",
		strings.Repeat("x", maxNameLen), "emoji-😀.png", "UPPER.TXT", "weird'\"<>|*?.txt",
	}
	for _, n := range names {
		e, err := encryptName(km, n)
		if err != nil {
			t.Fatalf("%q: %v", n, err)
		}
		got, err := decryptName(km, e)
		if err != nil || got != n {
			t.Fatalf("%q: got %q, %v", n, got, err)
		}
	}
}

func TestNameFixedLengthAndSalted(t *testing.T) {
	km := mustKM(t, edKey(t, t.TempDir(), "k"))
	want := -1
	seen := map[string]bool{}
	for _, n := range []string{"a", "short", strings.Repeat("y", maxNameLen), "日本語"} {
		e, err := encryptName(km, n)
		if err != nil {
			t.Fatal(err)
		}
		if want == -1 {
			want = len(e)
		}
		if len(e) != want {
			t.Fatalf("length varies: %d vs %d", len(e), want)
		}
		if len(e) > 255 {
			t.Fatalf("name too long for filesystems: %d", len(e))
		}
		if e != strings.ToLower(e) {
			t.Fatal("encrypted name must be lowercase")
		}
		for _, r := range e {
			if !(r >= 'a' && r <= 'z' || r >= '2' && r <= '7' || r == '.') {
				t.Fatalf("unexpected char %q", r)
			}
		}
	}
	for i := 0; i < 50; i++ {
		e, _ := encryptName(km, "same.txt")
		if seen[e] {
			t.Fatal("same name produced identical ciphertext: not salted")
		}
		seen[e] = true
	}
}

func TestNameLimits(t *testing.T) {
	km := mustKM(t, edKey(t, t.TempDir(), "k"))
	if _, err := encryptName(km, ""); err == nil {
		t.Error("empty name accepted")
	}
	if _, err := encryptName(km, strings.Repeat("a", maxNameLen+1)); err == nil {
		t.Error("overlong name accepted")
	}
}

func TestNameWrongKeyAndTamper(t *testing.T) {
	d := t.TempDir()
	k1, k2 := mustKM(t, edKey(t, d, "a")), mustKM(t, edKey(t, d, "b"))
	e, _ := encryptName(k1, "secret.txt")
	if _, err := decryptName(k2, e); err == nil {
		t.Error("wrong key decrypted name")
	}
	// flip every character in turn; none may decrypt to the original or panic
	body := []byte(strings.TrimSuffix(e, encExt))
	for i := range body {
		m := append([]byte{}, body...)
		if m[i] == 'a' {
			m[i] = 'b'
		} else {
			m[i] = 'a'
		}
		if got, err := decryptName(k1, string(m)+encExt); err == nil && got == "secret.txt" {
			// the last base32 char may carry unused bits; accept only that case
			if i != len(body)-1 {
				t.Errorf("tampered char %d still decrypts", i)
			}
		}
	}
}

func TestDecryptNameMalformed(t *testing.T) {
	km := mustKM(t, edKey(t, t.TempDir(), "k"))
	e, _ := encryptName(km, "x")
	cases := []string{
		"", ".parc", "plain.txt", "!!!!.parc", strings.TrimSuffix(e, encExt), e + "a",
		e[:len(e)-len(encExt)-1] + encExt, strings.Repeat("a", 231) + ".txt", "12345678.parc",
	}
	for _, c := range cases {
		if _, err := decryptName(km, c); err == nil {
			t.Errorf("%q: expected error", c)
		}
	}
}

func TestDecryptNameCaseInsensitive(t *testing.T) {
	km := mustKM(t, edKey(t, t.TempDir(), "k"))
	e, _ := encryptName(km, "Case.txt")
	got, err := decryptName(km, strings.ToUpper(e))
	if err != nil || got != "Case.txt" {
		t.Fatalf("%q %v", got, err)
	}
}

func TestRemoteBaseName(t *testing.T) {
	ok := map[string]string{
		"https://h/a/b/c.parc":          "c.parc",
		"https://h/a/b/c.parc?x=1#frag": "c.parc",
		"http://h:8080/c.parc":          "c.parc",
		"https://h/a%20b.parc":          "a b.parc",
		"https://user:pw@h/dir/x.parc":  "x.parc",
	}
	for in, want := range ok {
		got, err := remoteBaseName(in)
		if err != nil || got != want {
			t.Errorf("%s: got %q %v want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"https://h", "https://h/", "https://h/dir/", "http://[::1", "https://h/%zz"} {
		if _, err := remoteBaseName(in); err == nil {
			t.Errorf("%s: expected error", in)
		}
	}
}

// ---- key loading ----

func TestRSAAndOtherKeysRejected(t *testing.T) {
	d := t.TempDir()
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	p := writeKey(t, d, "rsa", rk, "")
	if _, err := loadKey(p); err == nil {
		t.Error("rsa private key accepted")
	}
	if _, err := loadPublic("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC7"); err == nil {
		t.Error("rsa public key accepted")
	}
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := loadKey(writeKey(t, d, "ec", ek, "")); err == nil {
		t.Error("ecdsa private key accepted")
	}
}

func pubLine(t testing.TB, keyPath string) string {
	t.Helper()
	raw, err := ssh.ParseRawPrivateKey(read(t, keyPath))
	if err != nil {
		t.Fatal(err)
	}
	pk := raw.(*ed25519.PrivateKey)
	sp, _ := ssh.NewPublicKey(pk.Public())
	return string(ssh.MarshalAuthorizedKey(sp))
}

func TestPublicOnlyEncrypt(t *testing.T) {
	d := t.TempDir()
	kp := edKey(t, d, "k")
	priv := mustKM(t, kp)
	line := pubLine(t, kp)
	write(t, kp+".pub", []byte(line))

	for name, spec := range map[string]string{"literal": strings.TrimSpace(line), "file": kp + ".pub"} {
		pub, err := loadPublic(spec)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if pub.nameSecret != nil || pub.identity != nil {
			t.Fatal("public material holds secrets")
		}
		if _, err := decryptName(pub, mustEncName(t, pub, "x")); err == nil {
			t.Error("public-only material decrypted a name")
		}
		src := filepath.Join(d, "pub-"+name+".txt")
		write(t, src, []byte("for you"))
		enc, err := encryptFile(pub, src, filepath.Join(d, "o"), false)
		if err != nil {
			t.Fatal(err)
		}
		dec, err := decryptFile(priv, enc, filepath.Join(d, "dd"), false)
		if err != nil || filepath.Base(dec) != "pub-"+name+".txt" || string(read(t, dec)) != "for you" {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := loadPublic(filepath.Join(d, "nonexistent")); err == nil {
		t.Error("missing public key accepted")
	}
	if _, err := loadPublic("ssh-ed25519 notbase64!!"); err == nil {
		t.Error("garbage public key accepted")
	}
}

func TestEncryptDoesNotNeedPassphraseWithPubFile(t *testing.T) {
	d := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	p := writeKey(t, d, "enc", priv, "pw")
	sp, _ := ssh.NewPublicKey(priv.Public())
	write(t, p+".pub", ssh.MarshalAuthorizedKey(sp))
	orig := readPassphrase
	defer func() { readPassphrase = orig }()
	readPassphrase = func(string) ([]byte, error) { t.Fatal("prompted"); return nil, nil }
	if _, err := loadForEncrypt("", p); err != nil {
		t.Fatal(err)
	}
}

func TestXNameKeyMatchesAcrossLoads(t *testing.T) {
	kp := edKey(t, t.TempDir(), "k")
	a, b := mustKM(t, kp), mustKM(t, kp)
	e := mustEncName(t, a, "n.txt")
	if got, err := decryptName(b, e); err != nil || got != "n.txt" {
		t.Fatal(got, err)
	}
}

func TestUnsupportedAndBadKeys(t *testing.T) {
	d := t.TempDir()
	if _, err := loadKey(filepath.Join(d, "missing")); err == nil {
		t.Error("missing key accepted")
	}
	write(t, filepath.Join(d, "junk"), []byte("not a key"))
	if _, err := loadKey(filepath.Join(d, "junk")); err == nil {
		t.Error("junk key accepted")
	}
	write(t, filepath.Join(d, "empty"), nil)
	if _, err := loadKey(filepath.Join(d, "empty")); err == nil {
		t.Error("empty key accepted")
	}
}

func TestPassphraseKey(t *testing.T) {
	d := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	p := writeKey(t, d, "enc", priv, "hunter2")
	orig := readPassphrase
	defer func() { readPassphrase = orig }()

	readPassphrase = func(string) ([]byte, error) { return []byte("hunter2"), nil }
	if _, err := loadKey(p); err != nil {
		t.Fatalf("right passphrase: %v", err)
	}
	readPassphrase = func(string) ([]byte, error) { return []byte("wrong"), nil }
	if _, err := loadKey(p); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	readPassphrase = func(string) ([]byte, error) { return nil, errors.New("no tty") }
	if _, err := loadKey(p); err == nil {
		t.Fatal("expected tty error")
	}
}

// ---- file encryption ----

func TestFileRoundTripKeyTypes(t *testing.T) {
	d := t.TempDir()
	keys := map[string]string{"ed": edKey(t, d, "ed")}
	big := make([]byte, 3<<20+17) // spans multiple age chunks
	rand.Read(big)
	payloads := map[string][]byte{"empty": {}, "small": []byte("hello"), "big": big}

	for kn, kp := range keys {
		km := mustKM(t, kp)
		for pn, data := range payloads {
			w := t.TempDir()
			src := filepath.Join(w, "orig-"+pn+".bin")
			write(t, src, data)
			encPath, err := encryptFile(km, src, filepath.Join(w, "enc"), false)
			if err != nil {
				t.Fatalf("%s/%s enc: %v", kn, pn, err)
			}
			if strings.Contains(filepath.Base(encPath), "orig") {
				t.Error("name leaked")
			}
			if bytes.Contains(read(t, encPath), []byte("hello")) && pn == "small" {
				t.Error("plaintext leaked")
			}
			decPath, err := decryptFile(km, encPath, filepath.Join(w, "dec"), false)
			if err != nil {
				t.Fatalf("%s/%s dec: %v", kn, pn, err)
			}
			if filepath.Base(decPath) != "orig-"+pn+".bin" || !bytes.Equal(read(t, decPath), data) {
				t.Fatalf("%s/%s mismatch", kn, pn)
			}
			if !exists(src) || !exists(encPath) {
				t.Error("sources must be kept without --replace")
			}
		}
	}
}

func TestWrongKeyDecryptFails(t *testing.T) {
	d := t.TempDir()
	k1, k2 := mustKM(t, edKey(t, d, "a")), mustKM(t, edKey(t, d, "b"))
	write(t, filepath.Join(d, "f.txt"), []byte("x"))
	e, err := encryptFile(k1, filepath.Join(d, "f.txt"), filepath.Join(d, "o"), false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decryptFile(k2, e, filepath.Join(d, "o2"), true); err == nil {
		t.Fatal("wrong key decrypted")
	}
	if !exists(e) {
		t.Error("source removed on failure")
	}
}

func TestContentWithRightNameKeyButWrongIdentity(t *testing.T) {
	// name decrypts (same name key) but content was encrypted for someone else
	d := t.TempDir()
	k1, k2 := mustKM(t, edKey(t, d, "a")), mustKM(t, edKey(t, d, "b"))
	write(t, filepath.Join(d, "f.txt"), []byte("x"))
	e, _ := encryptFile(k2, filepath.Join(d, "f.txt"), filepath.Join(d, "o"), false)
	// rename to a name k1 can decrypt
	n, _ := encryptName(k1, "f.txt")
	moved := filepath.Join(d, n)
	if err := os.Rename(e, moved); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(d, "dec")
	if _, err := decryptFile(k1, moved, out, false); err == nil {
		t.Fatal("expected failure")
	}
	if entries, _ := os.ReadDir(out); len(entries) != 0 {
		t.Errorf("leftover files after failed decrypt: %v", entries)
	}
}

func TestReplace(t *testing.T) {
	d := t.TempDir()
	km := mustKM(t, edKey(t, d, "k"))
	src := filepath.Join(d, "doc.txt")
	write(t, src, []byte("data"))
	enc, err := encryptFile(km, src, d, true)
	if err != nil {
		t.Fatal(err)
	}
	if exists(src) {
		t.Error("enc --replace kept source")
	}
	dec, err := decryptFile(km, enc, d, true)
	if err != nil {
		t.Fatal(err)
	}
	if exists(enc) || string(read(t, dec)) != "data" {
		t.Error("dec --replace wrong")
	}
}

func TestTruncatedAndCorruptedCiphertext(t *testing.T) {
	d := t.TempDir()
	km := mustKM(t, edKey(t, d, "k"))
	src := filepath.Join(d, "f.bin")
	data := bytes.Repeat([]byte("A"), 200000)
	write(t, src, data)
	enc, _ := encryptFile(km, src, filepath.Join(d, "e"), false)
	ct := read(t, enc)
	for name, mod := range map[string][]byte{
		"truncated": ct[:len(ct)-10],
		"header":    ct[:30],
		"empty":     {},
		"flipped":   append(append([]byte{}, ct[:len(ct)-5]...), ct[len(ct)-5]^1, 0, 0, 0, 0),
	} {
		bad := filepath.Join(d, "bad-"+name)
		write(t, bad, mod)
		if err := os.Rename(bad, filepath.Join(d, mustEncName(t, km, "f.bin"))); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(d, mustEncName(t, km, "f.bin"))
		// use a fresh name each time
		out := filepath.Join(d, "o-"+name)
		if _, err := decryptFile(km, p, out, false); err == nil {
			t.Errorf("%s: corrupted file decrypted", name)
		}
		if entries, _ := os.ReadDir(out); len(entries) != 0 {
			t.Errorf("%s: leftover output %v", name, entries)
		}
		os.Remove(p)
	}
}

func mustEncName(t testing.TB, km *keyMaterial, n string) string {
	e, err := encryptName(km, n)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestRefuseOverwriteWithoutReplace(t *testing.T) {
	d := t.TempDir()
	km := mustKM(t, edKey(t, d, "k"))
	src := filepath.Join(d, "a.txt")
	write(t, src, []byte("new"))
	enc, _ := encryptFile(km, src, filepath.Join(d, "e"), false)
	out := filepath.Join(d, "o")
	os.MkdirAll(out, 0o755)
	write(t, filepath.Join(out, "a.txt"), []byte("precious"))
	if _, err := decryptFile(km, enc, out, false); err == nil {
		t.Fatal("overwrote existing file")
	}
	if string(read(t, filepath.Join(out, "a.txt"))) != "precious" {
		t.Fatal("existing file modified")
	}
	if _, err := decryptFile(km, enc, out, false); err == nil {
		t.Fatal("still must refuse")
	}
	if _, err := decryptFile(km, enc, out, true); err != nil {
		t.Fatalf("--replace should overwrite: %v", err)
	}
	if string(read(t, filepath.Join(out, "a.txt"))) != "new" {
		t.Fatal("not overwritten")
	}
}

func TestInvalidSources(t *testing.T) {
	d := t.TempDir()
	km := mustKM(t, edKey(t, d, "k"))
	if _, err := encryptFile(km, filepath.Join(d, "nope"), d, false); err == nil {
		t.Error("missing file")
	}
	if _, err := encryptFile(km, d, d, false); err == nil {
		t.Error("directory accepted")
	}
	if _, err := decryptFile(km, d, d, false); err == nil {
		t.Error("directory accepted for dec")
	}
	write(t, filepath.Join(d, "plain.txt"), []byte("x"))
	if _, err := decryptFile(km, filepath.Join(d, "plain.txt"), d, false); err == nil {
		t.Error("non-parc file accepted")
	}
	long := filepath.Join(d, strings.Repeat("n", maxNameLen+1))
	write(t, long, []byte("x"))
	if _, err := encryptFile(km, long, d, false); err == nil {
		t.Error("overlong name accepted")
	}
}

func TestDecryptedNameTraversalRefused(t *testing.T) {
	d := t.TempDir()
	km := mustKM(t, edKey(t, d, "k"))
	for _, evil := range []string{"../evil", "a/b", "..", ".", `a\b`, "a\x00b"} {
		enc := mustEncName(t, km, evil)
		write(t, filepath.Join(d, enc), []byte("x"))
		out := filepath.Join(d, "out")
		if _, err := decryptFile(km, filepath.Join(d, enc), out, false); err == nil {
			t.Errorf("%q accepted", evil)
		}
		os.Remove(filepath.Join(d, enc))
	}
	if exists(filepath.Join(d, "evil")) {
		t.Error("escaped out dir")
	}
}

func TestSourceNotRemovedOnFailure(t *testing.T) {
	d := t.TempDir()
	km := mustKM(t, edKey(t, d, "k"))
	src := filepath.Join(d, "a.txt")
	write(t, src, []byte("x"))
	blocker := filepath.Join(d, "blocker")
	write(t, blocker, []byte("file where dir expected"))
	if _, err := encryptFile(km, src, blocker, true); err == nil {
		t.Fatal("expected error")
	}
	if !exists(src) {
		t.Fatal("source removed despite failed enc")
	}
}

// ---- CLI ----

func TestCLI(t *testing.T) {
	d := t.TempDir()
	key := edKey(t, d, "k")
	src := filepath.Join(d, "my doc.txt")
	write(t, src, []byte("cli"))
	var out bytes.Buffer
	run0 := func(args ...string) (string, error) {
		out.Reset()
		err := run(args, &out)
		return strings.TrimSpace(out.String()), err
	}

	// flags after, before, and with `--`
	enc, err := run0("enc", src, "--key", key, "-o", filepath.Join(d, "o"))
	if err != nil || !exists(enc) {
		t.Fatalf("enc: %q %v", enc, err)
	}
	if n, err := run0("inspect", "--key", key, enc); err != nil || n != "my doc.txt" {
		t.Fatalf("inspect: %q %v", n, err)
	}
	if n, err := run0("inspect", "--key", key, "https://x.test/p/"+filepath.Base(enc)+"?q=1"); err != nil || n != "my doc.txt" {
		t.Fatalf("inspect url: %q %v", n, err)
	}
	dec, err := run0("dec", "--key="+key, "--out-dir="+filepath.Join(d, "dd"), "-R", "--", enc)
	if err != nil || string(read(t, dec)) != "cli" || exists(enc) {
		t.Fatalf("dec: %q %v", dec, err)
	}
	// dash-leading filenames via `--`
	dash := filepath.Join(d, "-weird")
	write(t, dash, []byte("d"))
	t.Chdir(d)
	if _, err := run0("enc", "--key", key, "-o", "dashout", "--", "-weird"); err != nil {
		t.Fatalf("dash file: %v", err)
	}

	// enc with only a recipient (no private key involved), dec with the private key
	rec, err := run0("enc", "-r", strings.TrimSpace(pubLine(t, key)), "-o", filepath.Join(d, "r"), src)
	if err != nil {
		t.Fatalf("recipient enc: %v", err)
	}
	if n, err := run0("inspect", "--key", key, rec); err != nil || n != "my doc.txt" {
		t.Fatalf("recipient inspect: %q %v", n, err)
	}

	for _, bad := range [][]string{
		{"dec", "-r", "x", "y"}, {"enc", "-r", "ssh-rsa AAAA", src},
		{}, {"bogus"}, {"enc"}, {"enc", "a", "b"}, {"enc", "--nope", "x"}, {"inspect", "--key", key, "plain.txt"},
		{"enc", "--key", key, "does-not-exist"}, {"enc", "--key", filepath.Join(d, "nokey"), src},
	} {
		if _, err := run0(bad...); err == nil {
			t.Errorf("%v: expected error", bad)
		}
	}
	if _, err := run0("--help"); err != nil {
		t.Error("help should succeed")
	}
}

// ---- fuzzing ----

func FuzzDecryptName(f *testing.F) {
	km := mustKM(f, edKey(f, f.TempDir(), "k"))
	e, _ := encryptName(km, "seed.txt")
	f.Add(e)
	f.Add("")
	f.Add(".parc")
	f.Add(strings.ToUpper(e))
	f.Fuzz(func(t *testing.T, s string) {
		name, err := decryptName(km, s)
		if err == nil && (len(name) == 0 || len(name) > maxNameLen) {
			t.Fatalf("invalid name accepted: %q", name)
		}
	})
}

func FuzzNameRoundTrip(f *testing.F) {
	km := mustKM(f, edKey(f, f.TempDir(), "k"))
	f.Add("file.txt")
	f.Add("日本語")
	f.Add("a\x00b")
	f.Fuzz(func(t *testing.T, name string) {
		e, err := encryptName(km, name)
		if err != nil {
			if len(name) != 0 && len(name) <= maxNameLen {
				t.Fatalf("valid name rejected: %v", err)
			}
			return
		}
		if len(e) != 231+len(encExt) {
			t.Fatalf("length %d", len(e))
		}
		got, err := decryptName(km, e)
		if err != nil || got != name {
			t.Fatalf("round trip: %q -> %q (%v)", name, got, err)
		}
	})
}

func FuzzRemoteBaseName(f *testing.F) {
	f.Add("https://h/a/b.parc")
	f.Add("%%%")
	f.Add("http://[::1")
	f.Fuzz(func(t *testing.T, s string) {
		b, err := remoteBaseName(s)
		if err == nil && (b == "" || b == "." || b == "/" || strings.HasSuffix(b, "/")) {
			t.Fatalf("bad base %q from %q", b, s)
		}
	})
}

func FuzzFileRoundTrip(f *testing.F) {
	d := f.TempDir()
	km := mustKM(f, edKey(f, d, "k"))
	f.Add([]byte("hello"), "a.txt")
	f.Add([]byte{}, "b")
	f.Fuzz(func(t *testing.T, data []byte, name string) {
		if name == "" || len(name) > maxNameLen || name == "." || name == ".." ||
			strings.ContainsAny(name, "/\\\x00") || strings.HasPrefix(name, ".parc-") {
			t.Skip()
		}
		w := t.TempDir()
		os.MkdirAll(filepath.Join(w, "in"), 0o755)
		src := filepath.Join(w, "in", name)
		if err := os.WriteFile(src, data, 0o644); err != nil {
			t.Skip() // name not valid for this filesystem
		}
		enc, err := encryptFile(km, src, filepath.Join(w, "e"), false)
		if err != nil {
			t.Fatal(err)
		}
		dec, err := decryptFile(km, enc, filepath.Join(w, "d"), false)
		if err != nil {
			t.Fatal(err)
		}
		if filepath.Base(dec) != name || !bytes.Equal(read(t, dec), data) {
			t.Fatal("mismatch")
		}
	})
}

func TestInspectFollow(t *testing.T) {
	d := t.TempDir()
	key := edKey(t, d, "k")
	km := mustKM(t, key)
	enc := mustEncName(t, km, "remote file.txt")
	var methods []string
	mux := http.NewServeMux()
	mux.HandleFunc("/files/", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	mux.HandleFunc("/redir", func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		http.Redirect(w, r, "/files/"+enc, http.StatusFound)
	})
	mux.HandleFunc("/dl", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Disposition", `attachment; filename="`+enc+`"`)
	})
	mux.HandleFunc("/noheadmethod", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		http.Redirect(w, r, "/files/"+enc, http.StatusFound)
	})
	mux.HandleFunc("/plain", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc("/loop", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/loop", 302) })
	mux.HandleFunc("/gone", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	var out bytes.Buffer
	for _, p := range []string{"/redir", "/dl", "/noheadmethod", "/files/" + enc} {
		out.Reset()
		if err := run([]string{"inspect", "--key", key, "--follow", srv.URL + p}, &out); err != nil || strings.TrimSpace(out.String()) != "remote file.txt" {
			t.Errorf("%s: %q %v", p, out.String(), err)
		}
	}
	// without --follow, redirecting URLs are not resolved
	if err := run([]string{"inspect", "--key", key, srv.URL + "/redir"}, &out); err == nil {
		t.Error("redirect followed without --follow")
	}
	for _, p := range []string{"/plain", "/loop", "/gone"} {
		if err := run([]string{"inspect", "--key", key, "--follow", srv.URL + p}, &out); err == nil {
			t.Errorf("%s: expected error", p)
		}
	}
	// a name already in the URL must not touch the network
	srv.Close()
	out.Reset()
	if err := run([]string{"inspect", "--key", key, "--follow", srv.URL + "/files/" + enc}, &out); err != nil {
		t.Errorf("offline decrypt failed: %v", err)
	}
	for _, m := range methods {
		if m != "HEAD" {
			t.Errorf("expected HEAD, got %s", m)
		}
	}
}

func FuzzLoadKeyFile(f *testing.F) {
	d := f.TempDir()
	f.Add(read(f, edKey(f, d, "k")))
	f.Add([]byte("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n"))
	f.Add([]byte{})
	orig := readPassphrase
	readPassphrase = func(string) ([]byte, error) { return []byte("x"), nil }
	f.Cleanup(func() { readPassphrase = orig })
	f.Fuzz(func(t *testing.T, b []byte) {
		p := filepath.Join(t.TempDir(), "k")
		write(t, p, b)
		loadKey(p) // must not panic
	})
}

func FuzzLoadPublic(f *testing.F) {
	f.Add(strings.TrimSpace(pubLine(f, edKey(f, f.TempDir(), "k"))))
	f.Add("ssh-ed25519 AAAA")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		if km, err := loadPublic(s); err == nil && (km.recipient == nil || km.nameSecret != nil) {
			t.Fatal("inconsistent key material")
		}
	})
}

func TestOutputPermissions(t *testing.T) {
	d := t.TempDir()
	km := mustKM(t, edKey(t, d, "k"))
	src := filepath.Join(d, "p.txt")
	write(t, src, []byte("x"))
	enc, _ := encryptFile(km, src, filepath.Join(d, "e"), false)
	dec, err := decryptFile(km, enc, filepath.Join(d, "d"), false)
	if err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]os.FileMode{enc: 0o644, dec: 0o600} {
		if fi, _ := os.Stat(p); fi.Mode().Perm() != want {
			t.Errorf("%s: mode %v, want %v", filepath.Base(p), fi.Mode().Perm(), want)
		}
	}
}

func TestDecryptNonAgeFileHint(t *testing.T) {
	d := t.TempDir()
	km := mustKM(t, edKey(t, d, "k"))
	p := filepath.Join(d, mustEncName(t, km, "page.html"))
	write(t, p, []byte("\n<!DOCTYPE html><html>github page</html>"))
	_, err := decryptFile(km, p, filepath.Join(d, "o"), false)
	if err == nil || !strings.Contains(err.Error(), "/raw/") {
		t.Fatalf("want raw-URL hint, got %v", err)
	}
}
