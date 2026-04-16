package hostkey

import (
	"crypto/rsa"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestGenerateEd25519(t *testing.T) {
	kp, err := GenerateEd25519("test@host")
	if err != nil {
		t.Fatal(err)
	}
	if kp.Signer == nil {
		t.Fatal("no signer")
	}
	if got := kp.Signer.PublicKey().Type(); got != ssh.KeyAlgoED25519 {
		t.Fatalf("public key type = %q, want %q", got, ssh.KeyAlgoED25519)
	}
}

func TestGenerateRSARefusesSmall(t *testing.T) {
	if _, err := GenerateRSA(1024, ""); err == nil {
		t.Fatal("expected refusal of 1024-bit key")
	}
	if _, err := GenerateRSA(2048, ""); err == nil {
		t.Fatal("expected refusal of 2048-bit key (below our floor)")
	}
}

func TestGenerateRSA(t *testing.T) {
	if testing.Short() {
		t.Skip("slow: generates 3072-bit RSA key")
	}
	kp, err := GenerateRSA(3072, "test")
	if err != nil {
		t.Fatal(err)
	}
	rk := kp.Private.(*rsa.PrivateKey)
	if rk.N.BitLen() != 3072 {
		t.Fatalf("bits = %d", rk.N.BitLen())
	}
}

func TestRoundTripEd25519(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "id_ed25519")

	orig, err := GenerateEd25519("comment@host")
	if err != nil {
		t.Fatal(err)
	}
	if err := orig.Save(path); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("private key mode = %#o, want 0600", mode)
	}
	pubInfo, err := os.Stat(path + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	if mode := pubInfo.Mode().Perm(); mode != 0o644 {
		t.Fatalf("public key mode = %#o, want 0644", mode)
	}

	// .pub contains the comment we set
	pubBytes, err := os.ReadFile(path + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(pubBytes), "comment@host") {
		t.Fatalf("public key missing comment: %s", pubBytes)
	}

	reloaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Signer.PublicKey().Type() != orig.Signer.PublicKey().Type() {
		t.Fatal("reloaded key type differs")
	}
	if string(reloaded.Signer.PublicKey().Marshal()) != string(orig.Signer.PublicKey().Marshal()) {
		t.Fatal("reloaded public key differs from original")
	}
}

func TestSaveRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "id_ed25519")
	kp, _ := GenerateEd25519("a")
	if err := kp.Save(path); err != nil {
		t.Fatal(err)
	}
	kp2, _ := GenerateEd25519("b")
	if err := kp2.Save(path); err == nil {
		t.Fatal("expected refusal to overwrite existing key")
	}
}

func TestLoadRejectsLoosePerms(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "id_ed25519")
	kp, _ := GenerateEd25519("a")
	if err := kp.Save(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected error loading world-readable private key")
	}
}

func TestLoadOrGenerate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "id_ed25519")

	kp1, err := LoadOrGenerate(path, Ed25519, 0, "first")
	if err != nil {
		t.Fatal(err)
	}
	kp2, err := LoadOrGenerate(path, Ed25519, 0, "second")
	if err != nil {
		t.Fatal(err)
	}
	if string(kp1.Signer.PublicKey().Marshal()) != string(kp2.Signer.PublicKey().Marshal()) {
		t.Fatal("second call should have loaded the same key")
	}
}

// TestInteropWithSSHKeygen parses the public key we emitted using the
// system ssh-keygen, ensuring our on-disk format matches what OpenSSH
// can read.
func TestInteropWithSSHKeygen(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not available")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "id_ed25519")
	kp, err := GenerateEd25519("interop@test")
	if err != nil {
		t.Fatal(err)
	}
	if err := kp.Save(path); err != nil {
		t.Fatal(err)
	}
	// -l prints the fingerprint — if parsing fails, exits nonzero.
	out, err := exec.Command("ssh-keygen", "-l", "-f", path).CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-keygen -l failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "ED25519") {
		t.Fatalf("ssh-keygen did not recognize ed25519 key: %s", out)
	}
	// Public key file parseable too.
	out, err = exec.Command("ssh-keygen", "-l", "-f", path+".pub").CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-keygen -l .pub failed: %v\n%s", err, out)
	}
}
