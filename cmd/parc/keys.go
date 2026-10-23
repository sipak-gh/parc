// Key loading: turns an ed25519 SSH key into the age recipient/identity used
// for file contents and the X25519 key pair used for file names.
package main

import (
	"crypto/ed25519"
	"crypto/sha512"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/edwards25519"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// keyMaterial holds what is derived from an ed25519 SSH key. Encrypting needs
// only the public half; identity and nameSecret are set when the private key
// was loaded.
type keyMaterial struct {
	recipient     age.Recipient
	nameRecipient [32]byte // X25519 form of the public key, used for names
	identity      age.Identity
	nameSecret    []byte // X25519 scalar, nil for public-only material
}

// keyPathOrDefault returns path, or ~/.ssh/id_ed25519 when path is empty.
func keyPathOrDefault(path string) (string, error) {
	if path != "" {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	p := filepath.Join(home, ".ssh", "id_ed25519")
	if _, err := os.Stat(p); err != nil {
		return "", errors.New("no default SSH key found at ~/.ssh/id_ed25519; use --key")
	}
	return p, nil
}

var errNotEd25519 = errors.New("only ed25519 SSH keys are supported (encrypted names must fit in a filename)")

// loadPublic builds key material from an "ssh-ed25519 AAAA..." line or the path
// of a .pub / authorized_keys-style file.
func loadPublic(spec string) (*keyMaterial, error) {
	line := spec
	if b, err := os.ReadFile(spec); err == nil {
		line = string(b)
	} else if !strings.HasPrefix(strings.TrimSpace(spec), "ssh-") {
		return nil, fmt.Errorf("reading public key: %w", err)
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}
	return fromPublic(pk)
}

// fromPublic derives the age recipient and X25519 name recipient from a public key.
func fromPublic(pk ssh.PublicKey) (*keyMaterial, error) {
	if pk.Type() != ssh.KeyAlgoED25519 {
		return nil, errNotEd25519
	}
	km := &keyMaterial{}
	var err error
	if km.recipient, err = agessh.NewEd25519Recipient(pk); err != nil {
		return nil, err
	}
	edPub := pk.(ssh.CryptoPublicKey).CryptoPublicKey().(ed25519.PublicKey)
	mont, err := edToMontgomery(edPub)
	if err != nil {
		return nil, err
	}
	copy(km.nameRecipient[:], mont)
	return km, nil
}

// loadForEncrypt prefers an explicit recipient, then KEY.pub next to the key
// (so no passphrase is needed), then the private key itself.
func loadForEncrypt(recipient, keyPath string) (*keyMaterial, error) {
	if recipient != "" {
		return loadPublic(recipient)
	}
	keyPath, err := keyPathOrDefault(keyPath)
	if err != nil {
		return nil, err
	}
	if km, err := loadPublic(keyPath + ".pub"); err == nil {
		return km, nil
	}
	return loadKey(keyPath)
}

// loadKey loads the full private key (prompting for a passphrase if needed),
// giving access to decryption as well as encryption.
func loadKey(path string) (*keyMaterial, error) {
	path, err := keyPathOrDefault(path)
	if err != nil {
		return nil, err
	}
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading key: %w", err)
	}
	raw, err := ssh.ParseRawPrivateKey(pemBytes)
	var pme *ssh.PassphraseMissingError
	if errors.As(err, &pme) {
		pass, perr := readPassphrase(path)
		if perr != nil {
			return nil, perr
		}
		raw, err = ssh.ParseRawPrivateKeyWithPassphrase(pemBytes, pass)
	}
	if err != nil {
		return nil, fmt.Errorf("parsing key %s: %w", path, err)
	}

	var priv ed25519.PrivateKey
	switch k := raw.(type) {
	case *ed25519.PrivateKey:
		priv = *k
	case ed25519.PrivateKey:
		priv = k
	default:
		return nil, errNotEd25519
	}
	sshPub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		return nil, err
	}
	km, err := fromPublic(sshPub)
	if err != nil {
		return nil, err
	}
	if km.identity, err = agessh.NewEd25519Identity(priv); err != nil {
		return nil, err
	}
	h := sha512.Sum512(priv.Seed())
	km.nameSecret = h[:32] // X25519 clamps the scalar itself
	return km, nil
}

// edToMontgomery converts an Ed25519 public key to its X25519 form.
func edToMontgomery(pub ed25519.PublicKey) ([]byte, error) {
	p, err := new(edwards25519.Point).SetBytes(pub)
	if err != nil {
		return nil, err
	}
	return p.BytesMontgomery(), nil
}

// readPassphrase prompts on the controlling terminal; a variable so tests can stub it.
var readPassphrase = func(path string) ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, errors.New("key is passphrase-protected and no terminal is available")
	}
	defer tty.Close()
	fmt.Fprintf(tty, "Passphrase for %s: ", path)
	p, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	return p, err
}
