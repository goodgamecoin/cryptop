package examples

import (
	"fmt"
	"testing"
	"time"
)

var privStr = "-----BEGIN PRIVATE KEY-----\n" +
	"MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgiBPYMVTjspLfqoq46oZd\n" +
	"j9A0C8p7aK3Fi6/4zLugCkehRANCAATU49QhsAEVfIVJUmB6SpUC6BPaku1g/dzn\n" +
	"0Nl7iIY7W7g2FoANWnoF51eEUb6lcZ3gzfgg8VFGTpJriwHQWf5T\n" +
	"-----END PRIVATE KEY-----"

	//change public pem string to public string
var pubStr = "-----BEGIN PUBLIC KEY-----\n" +
	"MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE1OPUIbABFXyFSVJgekqVAugT2pLtYP3c\n" +
	"59DZe4iGO1u4NhaADVp6BedXhFG+pXGd4M34IPFRRk6Sa4sB0Fn+Uw==\n" +
	"-----END PUBLIC KEY-----"

func assertEqual(t *testing.T, a interface{}, b interface{}, message string) {
	if a == b {
		return
	}
	if len(message) == 0 {
		message = fmt.Sprintf("%v != %v", a, b)
	}
	t.Fatal(message)
}

func TestTLSSignature(t *testing.T) {
	signature := &TLSSignature{
		AccountType: "1234",
		SDKAppId:    "1400000955",
		Identifier:  "xiaojun",
		PriKey:      privStr,
		PubKey:      pubStr,
		Time:        time.Now(),
		Expire:      3600 * 30 * 24,
	}
	userSig, _ := signature.GenTLSSig()
	result, _ := signature.CheckTLSSig(userSig)
	assertEqual(t, result, true, "Failed in checking sig")
}
