package services

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
)

func generateOTP() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

func hashOTP(key []byte, scope string, code string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(scope + ":" + code))
	return hex.EncodeToString(mac.Sum(nil))
}
