// Command gossh-keygen generates SSH key pairs.
//
// Usage: gossh-keygen [-t ed25519|rsa] [-b bits] [-C comment] -f path
//
// For RSA, bits defaults to 3072 and the minimum is 3072. Ed25519 has
// no configurable size. The private key is written mode 0600, the
// .pub file mode 0644.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"

	"github.com/oscar/gossh/internal/hostkey"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gossh-keygen:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		algName = flag.String("t", "ed25519", "key algorithm: ed25519 or rsa")
		bits    = flag.Int("b", 3072, "RSA key size in bits (ignored for ed25519; minimum 3072)")
		comment = flag.String("C", "", "key comment (goes into .pub)")
		path    = flag.String("f", "", "output path for the private key (required)")
		fprint  = flag.Bool("l", false, "print fingerprint of an existing key at -f and exit")
	)
	flag.Parse()
	if *path == "" {
		return errors.New("-f is required")
	}

	if *fprint {
		kp, err := hostkey.Load(*path)
		if err != nil {
			return err
		}
		fmt.Printf("%s %s\n", kp.Signer.PublicKey().Type(), ssh.FingerprintSHA256(kp.Signer.PublicKey()))
		return nil
	}

	var alg hostkey.Algorithm
	switch *algName {
	case "ed25519":
		alg = hostkey.Ed25519
	case "rsa":
		alg = hostkey.RSA
	default:
		return fmt.Errorf("unknown algorithm %q (expected ed25519 or rsa)", *algName)
	}
	kp, err := hostkey.Generate(alg, *bits, *comment)
	if err != nil {
		return err
	}
	if err := kp.Save(*path); err != nil {
		return err
	}
	fmt.Printf("Wrote %s (%s)\n", *path, kp.Signer.PublicKey().Type())
	fmt.Printf("Fingerprint: %s\n", ssh.FingerprintSHA256(kp.Signer.PublicKey()))
	return nil
}
