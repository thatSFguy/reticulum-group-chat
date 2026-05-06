package lxmf

import (
	"crypto/sha256"
	"hash"
)

// newSHA256 indirects through a tiny helper so delivery.go can reach
// SHA-256 without importing crypto/sha256 directly (keeps the surface tidy).
func newSHA256() hash.Hash { return sha256.New() }
