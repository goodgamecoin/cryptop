package cryptop

import (
	"bytes"
	"compress/zlib"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"
)

type TLSSignature struct {
	AccountType string
	Identifier  string
	AppId3rd    string
	SDKAppId    string
	Version     string
	Expire      int64
	PriKey      string
	PubKey      string
	Time        time.Time
}

func (s *TLSSignature) GetTLSFieldsSerialString() string {
	return fmt.Sprintf(
		"TLS.appid_at_3rd:%s\nTLS.account_type:%s\nTLS.identifier:%s\nTLS.sdk_appid:%s\nTLS.time:%d\nTLS.expire_after:%d\n",
		s.AppId3rd, s.AccountType, s.Identifier, s.SDKAppId, s.Time.Unix(), s.Expire)
}

func (s *TLSSignature) GetTLSFieldsMap() map[string]string {
	return map[string]string{
		"TLS.account_type": s.AccountType,
		"TLS.identifier":   s.Identifier,
		"TLS.appid_at_3rd": s.AppId3rd,
		"TLS.sdk_appid":    s.SDKAppId,
		"TLS.expire_after": fmt.Sprintf("%d", s.Expire),
		"TLS.version":      s.Version,
		"TLS.time":         fmt.Sprintf("%d", s.Time.Unix()),
	}
}

func (s *TLSSignature) GetTLSFieldsSerialStringFromMap(fields map[string]string) string {
	return fmt.Sprintf(
		"TLS.appid_at_3rd:%s\nTLS.account_type:%s\nTLS.identifier:%s\nTLS.sdk_appid:%s\nTLS.time:%s\nTLS.expire_after:%s\n",
		fields["TLS.appid_at_3rd"],
		fields["TLS.account_type"],
		fields["TLS.identifier"],
		fields["TLS.sdk_appid"],
		fields["TLS.time"],
		fields["TLS.expire_after"])

}

func (s *TLSSignature) encodeTLSSignatureFields(fields map[string]string) string {
	var result string
	jsonFields, _ := json.Marshal(fields)
	var b bytes.Buffer
	w, _ := zlib.NewWriterLevel(&b, 6)
	w.Write(jsonFields)
	w.Flush()
	w.Close()
	result = base64.StdEncoding.EncodeToString(b.Bytes())
	result = strings.Replace(result, "+", "*", -1)
	result = strings.Replace(result, "/", "-", -1)
	result = strings.Replace(result, "=", "_", -1)
	return result
}

func (s *TLSSignature) decodeTLSSignature(sig string) (map[string]string, error) {
	fields := make(map[string]string)
	sig = strings.Replace(sig, "*", "+", -1)
	sig = strings.Replace(sig, "-", "/", -1)
	sig = strings.Replace(sig, "_", "=", -1)
	resultCompressedBytes, err := base64.StdEncoding.DecodeString(sig)
	b := bytes.NewReader(resultCompressedBytes)
	var out bytes.Buffer
	r, err := zlib.NewReader(b)
	if err != nil {
		return fields, err
	}
	io.Copy(&out, r)
	r.Close()
	resultBytes := out.Bytes()
	err = json.Unmarshal(resultBytes, &fields)
	return fields, nil
}

func (s *TLSSignature) GenTLSSig() (string, error) {
	var sig string
	pkcs8Block, _ := pem.Decode([]byte(s.PriKey))
	key, err := ParsePKCS8PrivateKey(pkcs8Block.Bytes)
	if err != nil {
		return sig, err
	}
	privateKey := key.(*ecdsa.PrivateKey)
	fields := s.GetTLSFieldsMap()
	serialString := s.GetTLSFieldsSerialString()
	h := sha256.New()
	h.Write([]byte(serialString))
	d := h.Sum(nil)
	rint, sint, err := ecdsa.Sign(rand.Reader, privateKey, d)
	if err != nil {
		return sig, err
	}
	asn1Data := []*big.Int{rint, sint}
	sbytes, err := asn1.Marshal(asn1Data)
	if err != nil {
		return sig, err
	}
	encodedSignature := base64.StdEncoding.EncodeToString(sbytes)
	fields["TLS.sig"] = encodedSignature
	sig = s.encodeTLSSignatureFields(fields)
	return sig, err
}

func (s *TLSSignature) CheckTLSSig(sig string) (bool, error) {
	var (
		result bool
		err    error
	)
	fields, err := s.decodeTLSSignature(sig)
	if err != nil {
		return result, err
	}
	encodedSignature := fields["TLS.sig"]
	sbytes, err := base64.StdEncoding.DecodeString(encodedSignature)
	if err != nil {
		return result, err
	}
	asn1Data := make([]*big.Int, 2)
	_, err = asn1.Unmarshal(sbytes, &asn1Data)
	if err != nil {
		return result, err
	}
	serialString := s.GetTLSFieldsSerialStringFromMap(fields)
	h := sha256.New()
	h.Write([]byte(serialString))
	hash := h.Sum(nil)
	block, _ := pem.Decode([]byte(s.PubKey))
	pubKey, err := ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return result, err
	}
	ecdsaPubKey := pubKey.(*ecdsa.PublicKey)
	result = ecdsa.Verify(ecdsaPubKey, hash, asn1Data[0], asn1Data[1])
	return result, err
}
