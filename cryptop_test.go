package cryptop

import (
	"encoding/pem"
	"testing"
)

//samples generated with ssl:
//openssl ecparam -name secp256k1 -out secp256k1.pem
//openssl ecparam -in secp256k1.pem -genkey -noout -out secp256k1-key.pem
//openssl pkcs8 -topk8 -nocrypt -in secp256k1-key.pem -out p8file.pem

var secp256k1pem = []byte(`-----BEGIN EC PARAMETERS-----
BgUrgQQACg==
-----END EC PARAMETERS-----`)

var secp256k1keypem = []byte(`-----BEGIN EC PRIVATE KEY-----
MHQCAQEEINl/yMsvLn/cAwmEFzgMDROHJ4a4G3UCjcOfDis0/IDyoAcGBSuBBAAK
oUQDQgAE4iE974TyqfcwRf1hBJ3tCKfUTs5o5kE4ybffKhAwJnAmNnstCVe9lzHJ
5aMreK//yfOvhMNnBz8ILwL9vm39YA==
-----END EC PRIVATE KEY-----`)

var pkcs8pem = []byte(`-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQg2X/Iyy8uf9wDCYQXOAwN
E4cnhrgbdQKNw58OKzT8gPKhRANCAATiIT3vhPKp9zBF/WEEne0Ip9ROzmjmQTjJ
t98qEDAmcCY2ey0JV72XMcnloyt4r//J86+Ew2cHPwgvAv2+bf1g
-----END PRIVATE KEY-----`)

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

}
