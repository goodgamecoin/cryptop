package cryptop

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/pem"
	"testing"
)

//samples generated with ssl:
//openssl ecparam -name secp256k1 -out secp256k1.pem
//openssl ecparam -in secp256k1.pem -genkey -noout -out secp256k1-key.pem
//openssl pkcs8 -topk8 -nocrypt -in secp256k1-key.pem -out p8file.pem
//openssl ec -in secp256k1-key.pem -pubout -out ecpubkey.pem

var secp256k1pem = []byte(`-----BEGIN EC PARAMETERS-----
BgUrgQQACg==
-----END EC PARAMETERS-----`)

var secp256k1keypem = []byte(`-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIDsfNWvgXwdbUKQ9Ip6sq0tvTeXqr2I+BmseaH7N2vdcoAcGBSuBBAAK
oUQDQgAEmJwz7Y/QlnnOaoOKRiJZaudZfuVlz1Q3kkmVYjuXegQ9oE34Fw2T8wH3
TsQptxnbklOlH34nKBs5lZvnj9tR0Q==
-----END EC PRIVATE KEY-----`)

var pkcs8pem = []byte(`-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgOx81a+BfB1tQpD0inqyr
S29N5eqvYj4Gax5ofs3a91yhRANCAASYnDPtj9CWec5qg4pGIllq51l+5WXPVDeS
SZViO5d6BD2gTfgXDZPzAfdOxCm3GduSU6UfficoGzmVm+eP21HR
-----END PRIVATE KEY-----`)

var secp256k1pubkeypem = []byte(`-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEmJwz7Y/QlnnOaoOKRiJZaudZfuVlz1Q3
kkmVYjuXegQ9oE34Fw2T8wH3TsQptxnbklOlH34nKBs5lZvnj9tR0Q==
-----END PUBLIC KEY-----`)

func TestCryptop(t *testing.T) {
	ecpkBlock, _ := pem.Decode(secp256k1keypem)
	key, err := ParseECPrivateKey(ecpkBlock.Bytes)
	if err != nil {
		t.Log("ParseECPrivateKey error: ", err)
		t.Fail()
	}
	t.Log("secp256k1 key:", key)

	pkcs8Block, _ := pem.Decode(pkcs8pem)
	key2, err := ParsePKCS8PrivateKey(pkcs8Block.Bytes)
	if err != nil {
		t.Log("ParsePKCS8PrivateKey error: ", err)
		t.Fail()
	}
	t.Log("secp256k1 key:", key2)

	//c := namedCurveFromOID(secp256k1OID)
	//key3, _ := ecdsa.GenerateKey(c, rand.Reader)

	hashed := []byte("testing")
	r, s, err := ecdsa.Sign(rand.Reader, key, hashed)
	if err != nil {
		t.Errorf("error signing: %s", err)
	}

	t.Log("r: ", r, "s: ", s)

	if !ecdsa.Verify(&key.PublicKey, hashed, r, s) {
		t.Errorf("Verify failed")
	}

	hashed[0] ^= 0xff
	if ecdsa.Verify(&key.PublicKey, hashed, r, s) {
		t.Errorf("Verify always works!")
	}
}
