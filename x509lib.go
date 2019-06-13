package x509lib

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
)

// LoadPEMCertWithPath loads a certificate and
// returns a x509 stucture when path is give as parameter
func LoadPEMCertWithPath(path string) (*x509.Certificate, error) {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	bytesBlock, _ := pem.Decode(bytes)
	if bytesBlock == nil {
		fmt.Println("ERROR: failed to parse certificate PEM")
		return nil, errors.New("ERROR: failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(bytesBlock.Bytes)
	if err != nil {
		fmt.Println("ERROR:", path, "failed to parse certificate: "+err.Error())
		return nil, err
	}
	return cert, nil
}

// LoadDERCertWithPath loads a certificate and
// returns a x509 stucture when path is give as parameter
func LoadDERCertWithPath(path string) (*x509.Certificate, error) {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	cert, err := x509.ParseCertificate(bytes)
	if err != nil {
		fmt.Println("ERROR:", path, "failed to parse certificate: "+err.Error())
		return nil, err
	}
	return cert, nil
}

// LoadCertWithPEMBytes loads a certificate and
// returns a x509 stucture when path is give as parameter
func LoadCertWithPEMBytes(bytes []byte) (*x509.Certificate, error) {
	bytesBlock, _ := pem.Decode(bytes)
	if bytesBlock == nil {
		fmt.Println("ERROR: failed to parse certificate PEM")
		return nil, errors.New("ERROR: failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(bytesBlock.Bytes)
	if err != nil {
		fmt.Println("ERROR: failed to parse certificate: " + err.Error())
		return nil, err
	}
	return cert, nil
}

// LoadCertWithDERBytes loads a certificate and
// returns a x509 stucture when path is give as parameter
func LoadCertWithDERBytes(bytes []byte) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(bytes)
	if err != nil {
		fmt.Println("ERROR: failed to parse certificate: " + err.Error())
		return nil, err
	}
	return cert, nil
}

// IsLeafCert checks if a leaf certificate is
func IsLeafCert(cert *x509.Certificate) bool {
	if cert.BasicConstraintsValid && !cert.IsCA {
		return true
	}
	return false
}

// IsCodeSigningCert checks if code signing cert is
func IsCodeSigningCert(cert *x509.Certificate) bool {
	for _, key := range cert.ExtKeyUsage {
		if key == x509.ExtKeyUsageCodeSigning {
			return true
		}
	}
	return false
}

// IsTimeStampingCert checks if the cert is for timestamp
func IsTimeStampingCert(cert *x509.Certificate) bool {
	for _, key := range cert.ExtKeyUsage {
		if key == x509.ExtKeyUsageTimeStamping {
			return true
		}
	}
	return false
}

// DumpX509InJSON dumps x509 information in
// JSON when path of x509 is given a parameter
// returns error when error occurs.
func DumpX509InJSON(x509Path string, jsonPath string) error {
	cert, err := LoadPEMCertWithPath(x509Path)
	if err != nil {
		return err
	}
	jsonBytes, err := json.Marshal(cert)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(jsonPath, jsonBytes, 0644)
}
