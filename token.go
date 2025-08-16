package access

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrMissingAuthHeader     = errors.New("missing Authorization header")
	ErrInvalidJWTSegments    = errors.New("invalid size of jwt segments")
	ErrNilInsecurePayload    = errors.New("insecure parsed token payload appears as nil")
	ErrInvalidInsecureUserID = errors.New("insecure parsed token user id is invalid")
	ErrInvalidSigningAlg     = errors.New("invalid signing algorithm")
	ErrInvalidSig            = errors.New("invalid token's signature")
	ErrInvalidClaims         = errors.New("claims casting did not go well")
	ErrInvalidPubKeyPtr      = errors.New("invalid pointer to public key")
	ErrInvalidUserID         = errors.New("user id is invalid")
)

func VerifyToken(rawToken string, getPublicKeyByUserID func(userID string) (*rsa.PublicKey, error)) (userID string, err error) {
	if rawToken == "" {
		return "", ErrMissingAuthHeader
	}
	if getPublicKeyByUserID == nil {
		return "", ErrInvalidPubKeyPtr
	}

	segments := strings.Split(rawToken, ".")
	if len(segments) != 3 {
		return "", ErrInvalidJWTSegments
	}

	insecurePayloadJsonStr, err := base64.RawStdEncoding.DecodeString(segments[1])
	if err != nil {
		return "", err
	}

	var insecurePayload map[string]any

	if err := json.Unmarshal(insecurePayloadJsonStr, &insecurePayload); err != nil {
		return "", err
	}

	if insecurePayload == nil {
		return "", ErrNilInsecurePayload
	}

	insecureUserID := fmt.Sprint(insecurePayload["u"])
	if len(insecureUserID) == 0 || len(insecureUserID) > 32 {
		return "", ErrInvalidInsecureUserID
	}

	token, err := jwt.Parse(rawToken, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, ErrInvalidSigningAlg
		}

		return getPublicKeyByUserID(insecureUserID)
	})
	if err != nil {
		return "", err
	}

	if !token.Valid {
		return "", ErrInvalidSig
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", ErrInvalidClaims
	}

	verifiedUserID := fmt.Sprint(claims["id"])
	if len(verifiedUserID) == 0 {
		return "", ErrInvalidUserID
	}

	return verifiedUserID, nil
}
