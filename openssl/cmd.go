package openssl

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/makeworld-the-better-one/amfora/logger"
)

func GetCertsDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(home, ".local", "share", "amfora"), nil
}

func GetPageDir(dir string, url string) (string, error) {
	sp := strings.Split(url, "//")
	if len(sp) <= 1 || sp[1] == "" {
		return "", errors.New("not a proper url")
	}
	pageDir := filepath.Join(dir, sp[1])

	return pageDir, nil
}

func CallOpenSSL(pageName string, userName string, expireDays int) error {
	if expireDays == 0 {
		expireDays = 1825
	}

	dir, err := GetCertsDir()
	if err != nil {
		return err
	}

	pageDir, err := GetPageDir(dir, pageName)
	if err != nil {
		return err
	}

	// Create Priv/Pub Key
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	// Create certificate
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(expireDays*24) * time.Hour)

	template := x509.Certificate{
		SerialNumber:          big.NewInt(0),
		Subject:               pkix.Name{CommonName: pageName},
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	cert, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		return err
	}

	// Save cert
	certPath := filepath.Join(pageDir, "cert.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
	if err = os.WriteFile(certPath, certPEM, 0600); err != nil {
		return err
	}

	// Save key
	// Use PKCS#8 encoding for the private key
	privBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		logger.Logger.Fatalf("Failed to marshal private key: %v", err)
	}

	keyPath := filepath.Join(pageDir, "key.pem")
	encKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	err = os.WriteFile(keyPath, encKey, 0600)
	if err != nil {
		logger.Logger.Fatalf("Failed to save private key: %v", err)
	}

	// Based on:
	// openssl req -new -subj "/CN=username" -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -days 1825 -nodes -out cert.pem -keyout key.pem

	return nil
}
