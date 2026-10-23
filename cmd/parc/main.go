// Command parc encrypts files and their names with an ed25519 SSH key so they
// can be stored publicly. See README.md for the design.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
)

// ageMagic begins every age-encrypted file.
const ageMagic = "age-encryption.org/v1"

const usage = `parc - encrypt files and their names using your SSH key

Usage:
  parc enc     [flags] <PATH>   encrypt a file and its name
  parc dec     [flags] <PATH>   decrypt a file and restore its name
  parc inspect [flags] <PATH|URL>   show the decrypted name of a file

Flags:
  -o, --out-dir DIR   write output into DIR (default: current directory)
      --key PATH      ed25519 SSH key (default: ~/.ssh/id_ed25519); enc uses PATH.pub if present
  -r, --recipient K   enc only: encrypt to this public key ("ssh-ed25519 ..." or a .pub file);
                      only the matching private key can dec/inspect
      --follow        with a URL, follow redirects and Content-Disposition to find the name
  -R, --replace       remove the source file after enc/dec (and overwrite existing output)
`

// main reports errors on stderr; asking for --help is not an error.
func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "parc:", err)
		os.Exit(1)
	}
}

// run executes one parc invocation, writing results to stdout. It is separate
// from main so tests can drive the CLI directly.
func run(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return errors.New("missing command")
	}
	cmd := args[0]
	if cmd == "-h" || cmd == "--help" || cmd == "help" {
		fmt.Fprint(stdout, usage)
		return nil
	}
	if cmd != "enc" && cmd != "dec" && cmd != "inspect" {
		return fmt.Errorf("unknown command %q", cmd)
	}

	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	var outDir, keyPath, recipient string
	var replace, follow bool
	fs.StringVar(&outDir, "out-dir", "", "")
	fs.StringVar(&outDir, "o", "", "")
	fs.StringVar(&keyPath, "key", "", "")
	fs.StringVar(&recipient, "recipient", "", "")
	fs.StringVar(&recipient, "r", "", "")
	fs.BoolVar(&replace, "replace", false, "")
	fs.BoolVar(&replace, "R", false, "")
	fs.BoolVar(&follow, "follow", false, "")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }

	// Allow flags before or after the positional argument.
	var pos []string
	rest := args[1:]
	for len(rest) > 0 {
		if err := fs.Parse(rest); err != nil {
			return err
		}
		rest = fs.Args()
		if len(rest) == 0 {
			break
		}
		if rest[0] == "--" {
			pos = append(pos, rest[1:]...)
			break
		}
		pos = append(pos, rest[0])
		rest = rest[1:]
	}
	if len(pos) != 1 {
		return fmt.Errorf("%s requires exactly one <PATH>", cmd)
	}
	target := pos[0]

	if recipient != "" && cmd != "enc" {
		return errors.New("--recipient only applies to enc")
	}
	var km *keyMaterial
	var err error
	if cmd == "enc" {
		km, err = loadForEncrypt(recipient, keyPath)
	} else {
		km, err = loadKey(keyPath)
	}
	if err != nil {
		return err
	}

	var out string
	switch cmd {
	case "inspect":
		out, err = inspect(km, target, follow)
	case "enc":
		out, err = encryptFile(km, target, outDir, replace)
	case "dec":
		out, err = decryptFile(km, target, outDir, replace)
	}
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, out)
	return nil
}

// inspect returns the original name for a local path or http(s) URL.
func inspect(km *keyMaterial, target string, follow bool) (string, error) {
	if isURL(target) {
		return inspectURL(km, target, follow)
	}
	return decryptName(km, filepath.Base(target))
}

// checkRegular rejects directories, devices, and other non-regular files.
func checkRegular(p string) error {
	info, err := os.Stat(p)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", p)
	}
	return nil
}

// encryptFile writes src, age-encrypted, to outDir under an encrypted name and
// returns the new path. With replace, src is removed afterwards.
func encryptFile(km *keyMaterial, src, outDir string, replace bool) (string, error) {
	if err := checkRegular(src); err != nil {
		return "", err
	}
	encName, err := encryptName(km, filepath.Base(src))
	if err != nil {
		return "", err
	}
	dst, err := outPath(outDir, encName)
	if err != nil {
		return "", err
	}
	if err := writeAtomic(src, dst, 0o644, replace, func(w io.Writer, r io.Reader) error {
		aw, err := age.Encrypt(w, km.recipient)
		if err != nil {
			return err
		}
		if _, err := io.Copy(aw, r); err != nil {
			return err
		}
		return aw.Close()
	}); err != nil {
		return "", err
	}
	return dst, finishReplace(src, dst, replace)
}

// decryptFile restores src's original name and contents into outDir and returns
// the new path. With replace, src is removed afterwards.
func decryptFile(km *keyMaterial, src, outDir string, replace bool) (string, error) {
	if err := checkRegular(src); err != nil {
		return "", err
	}
	name, err := decryptName(km, filepath.Base(src))
	if err != nil {
		return "", err
	}
	// The name is attacker-controlled once decrypted; never let it leave outDir.
	if name != filepath.Base(name) || name == "." || name == ".." || strings.ContainsAny(name, "/\\\x00") {
		return "", errors.New("decrypted name is not a plain file name; refusing")
	}
	dst, err := outPath(outDir, name)
	if err != nil {
		return "", err
	}
	// Plaintext output is private to the user.
	if err := writeAtomic(src, dst, 0o600, replace, func(w io.Writer, r io.Reader) error {
		br := bufio.NewReader(r)
		if magic, _ := br.Peek(len(ageMagic)); string(magic) != ageMagic {
			return errors.New("not an age-encrypted file (if downloaded from GitHub, use the /raw/ URL, not /blob/)")
		}
		ar, err := age.Decrypt(br, km.identity)
		if err != nil {
			return err
		}
		_, err = io.Copy(w, ar)
		return err
	}); err != nil {
		return "", err
	}
	return dst, finishReplace(src, dst, replace)
}

// outPath creates outDir (default: current directory) and returns name inside it.
func outPath(outDir, name string) (string, error) {
	if outDir == "" {
		outDir = "."
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", err
	}
	return filepath.Join(outDir, name), nil
}

// writeAtomic streams src through fn into a temp file in dst's directory, then
// renames it to dst, so a failure never leaves a partial or clobbered output.
// An existing dst is only overwritten when replace is set.
func writeAtomic(src, dst string, mode os.FileMode, replace bool, fn func(w io.Writer, r io.Reader) error) error {
	if _, err := os.Lstat(dst); err == nil && !replace {
		return fmt.Errorf("%s already exists (use --replace to overwrite)", dst)
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".parc-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if err := fn(tmp, in); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), mode); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dst)
}

// finishReplace removes src after a successful run when --replace is set,
// unless the output already overwrote it (src and dst are the same file).
func finishReplace(src, dst string, replace bool) error {
	if !replace {
		return nil
	}
	if si, err := os.Stat(src); err == nil {
		if di, err := os.Stat(dst); err == nil && os.SameFile(si, di) {
			return nil
		}
	}
	return os.Remove(src)
}
