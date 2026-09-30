package app

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"golang.org/x/crypto/argon2"
	"os"
	"path/filepath"
)

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}
func token() string { return base64.RawURLEncoding.EncodeToString(randomBytes(32)) }
func digest(s string) string {
	b := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(b[:])
}
func passwordHash(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 2, 64*1024, 2, 32)
}
func equal(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }
func privateKey() (string, string, error) {
	p, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(p.Bytes()), base64.StdEncoding.EncodeToString(p.PublicKey().Bytes()), nil
}
func publicKey(key string) (string, error) {
	b, e := base64.StdEncoding.DecodeString(key)
	if e != nil {
		return "", e
	}
	p, e := ecdh.X25519().NewPrivateKey(b)
	if e != nil {
		return "", e
	}
	return base64.StdEncoding.EncodeToString(p.PublicKey().Bytes()), nil
}
func masterKey(dir string) ([]byte, error) {
	path := filepath.Join(dir, "master.key")
	b, e := os.ReadFile(path)
	if e == nil {
		if len(b) != 32 {
			return nil, errors.New("invalid master key")
		}
		if e = os.Chmod(path, 0600); e != nil {
			return nil, e
		}
		return b, nil
	}
	if !os.IsNotExist(e) {
		return nil, e
	}
	if _, dbErr := os.Stat(filepath.Join(dir, "state.db")); dbErr == nil {
		return nil, errors.New("master.key missing for existing database; restore it from backup")
	}
	b = randomBytes(32)
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return nil, e
	}
	_, e = f.Write(b)
	ce := f.Close()
	if e != nil {
		return nil, e
	}
	return b, ce
}
func encrypt(key []byte, value, scope string) ([]byte, error) {
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(b)
	if e != nil {
		return nil, e
	}
	n := randomBytes(g.NonceSize())
	return g.Seal(n, n, []byte(value), []byte(scope)), nil
}
func decrypt(key, b []byte, scope string) (string, error) {
	c, e := aes.NewCipher(key)
	if e != nil {
		return "", e
	}
	g, e := cipher.NewGCM(c)
	if e != nil {
		return "", e
	}
	if len(b) < g.NonceSize() {
		return "", errors.New("invalid encrypted secret")
	}
	p, e := g.Open(nil, b[:g.NonceSize()], b[g.NonceSize():], []byte(scope))
	return string(p), e
}
