package cryptop

import (
	"crypto/elliptic"
	"encoding/asn1"
	"github.com/goodgamecoin/cryptop/kcurve"
	"math/big"
	"reflect"
)

var secp112r1 *elliptic.CurveParams
var secp112r1OID asn1.ObjectIdentifier = []int{1, 3, 132, 0, 6}
var secp128r1 *elliptic.CurveParams
var secp128r1OID asn1.ObjectIdentifier = []int{1, 3, 132, 0, 28}
var secp160r1 *elliptic.CurveParams
var secp160r1OID asn1.ObjectIdentifier = []int{1, 3, 132, 0, 8}
var secp256k1 *kcurve.CurveParams
var secp256k1OID asn1.ObjectIdentifier = []int{1, 3, 132, 0, 10}

func init() {
	secp112r1 = &elliptic.CurveParams{}
	secp112r1.Name = "secp112r1"
	secp112r1.P, _ = new(big.Int).SetString("00db7c2abf62e35e668076bead208b", 16) // Prime
	secp112r1.N, _ = new(big.Int).SetString("00db7c2abf62e35e7628dfac6561c5", 16) // Order
	secp112r1.B, _ = new(big.Int).SetString("659ef8ba043916eede8911702b22", 16)   // B
	secp112r1.Gx, _ = new(big.Int).SetString("09487239995a5ee76b55f9c2f098", 16)  // Generator X
	secp112r1.Gy, _ = new(big.Int).SetString("a89ce5af8724c0a23e0e0ff77500", 16)  // Generator Y
	secp112r1.BitSize = 112

	secp128r1 = &elliptic.CurveParams{}
	secp128r1.Name = "secp128r1"
	secp128r1.P, _ = new(big.Int).SetString("00fffffffdffffffffffffffffffffffff", 16) // Prime
	secp128r1.N, _ = new(big.Int).SetString("00fffffffe0000000075a30d1b9038a115", 16) // Order
	secp128r1.B, _ = new(big.Int).SetString("00e87579c11079f43dd824993c2cee5ed3", 16) // B
	secp128r1.Gx, _ = new(big.Int).SetString("161ff7528b899b2d0c28607ca52c5b86", 16)  // Generator X
	secp128r1.Gy, _ = new(big.Int).SetString("cf5ac8395bafeb13c02da292dded7a83", 16)  // Generator Y
	secp128r1.BitSize = 128

	secp160r1 = &elliptic.CurveParams{}
	secp160r1.Name = "secp160r1"
	secp160r1.P, _ = new(big.Int).SetString("00ffffffffffffffffffffffffffffffff7fffffff", 16) // Prime
	secp160r1.N, _ = new(big.Int).SetString("0100000000000000000001f4c8f927aed3ca752257", 16) // Order
	secp160r1.B, _ = new(big.Int).SetString("1c97befc54bd7a8b65acf89f81d4d4adc565fa45", 16)   // B
	secp160r1.Gx, _ = new(big.Int).SetString("4a96b5688ef573284664698968c38bb913cbfc82", 16)  // Generator X
	secp160r1.Gy, _ = new(big.Int).SetString("23a628553168947d59dcc912042351377ac5fb32", 16)  // Generator Y
	secp160r1.BitSize = 160

	// Koblitz elliptic curves
	secp256k1 = &kcurve.CurveParams{}
	secp256k1.Name = "secp256k1"
	secp256k1.P, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16)  // Prime
	secp256k1.N, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)  // Order
	secp256k1.B, _ = new(big.Int).SetString("0000000000000000000000000000000000000000000000000000000000000007", 16)  // B
	secp256k1.Gx, _ = new(big.Int).SetString("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16) // Generator X
	secp256k1.Gy, _ = new(big.Int).SetString("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16) // Generator Y
	secp256k1.BitSize = 256
}

func namedCurveFromOID(oid asn1.ObjectIdentifier) elliptic.Curve {
	switch {
	case reflect.DeepEqual(oid, secp112r1OID):
		return secp112r1
	case reflect.DeepEqual(oid, secp128r1OID):
		return secp128r1
	case reflect.DeepEqual(oid, secp160r1OID):
		return secp160r1
	case reflect.DeepEqual(oid, secp256k1OID):
		return secp256k1
	}
	return nil
}
