package cryptop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
)

var (
	oidPublicKeyRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidPublicKeyDSA   = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}
	oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
)

// https://golang.org/src/crypto/x509/x509.go
type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// An extension for x509.ParsePKIXPublicKey() that supports more ECDSA curves
func ParsePKIXPublicKey(derBytes []byte) (interface{}, error) {
	var pki publicKeyInfo
	if rest, err := asn1.Unmarshal(derBytes, &pki); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after ASN.1 of public-key")
	}
	if !oidPublicKeyECDSA.Equal(pki.Algorithm.Algorithm) {
		return x509.ParsePKIXPublicKey(derBytes)
	}

	asn1Data := pki.PublicKey.RightAlign()
	paramsData := pki.Algorithm.Parameters.FullBytes
	namedCurveOID := new(asn1.ObjectIdentifier)
	rest, err := asn1.Unmarshal(paramsData, namedCurveOID)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after ECDSA parameters")
	}
	namedCurve := namedCurveFromOID(*namedCurveOID)
	if namedCurve == nil {
		return nil, errors.New("x509: unsupported elliptic curve")
	}
	x, y := elliptic.Unmarshal(namedCurve, asn1Data)
	if x == nil {
		return nil, errors.New("x509: failed to unmarshal elliptic curve point")
	}
	pub := &ecdsa.PublicKey{
		Curve: namedCurve,
		X:     x,
		Y:     y,
	}
	return pub, nil
}
