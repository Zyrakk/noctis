package promptsv2

import (
	"crypto/sha256"
	_ "embed"
	"errors"
	"fmt"
)

// Version 1 is immutable. Changing these instructions requires a new binding
// prompt version, new replay/canary evidence and invalidated promotion records.
//
//go:embed instructions-v1.txt
var Instructions string

//go:embed instructions-v2.txt
var instructionsV2 string

const DigestV1 = "f6c57e6cdaf3111015fbb98cf59b19f37fec99b02b6707163e2f3af79562ec48"
const DigestV2 = "cfec25c81badf27c83d704915404d1e5aca84e5cb742a20bda7af3d54bdd2e85"

// Resolve verifies the immutable bytes registered for the selected semantic
// version. Binary replacement cannot silently change a stored prompt identity.
func Resolve(version string) (instructions, digest string, err error) {
	switch version {
	case "1":
		instructions, digest = Instructions, DigestV1
	case "2":
		instructions, digest = instructionsV2, DigestV2
	default:
		return "", "", errors.New("prompt version unsupported")
	}
	if fmt.Sprintf("%x", sha256.Sum256([]byte(instructions))) != digest {
		return "", "", errors.New("prompt digest mismatch")
	}
	return instructions, digest, nil
}
