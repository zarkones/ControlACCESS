package access

import (
	"crypto/rsa"
	"net/http"
)

func AuthenticateAndAuthorize(
	w http.ResponseWriter,
	r *http.Request,
	permissionKey PermissionKey,
	metadata *string,
	getPublicKeyByUserID func(userID string) (*rsa.PublicKey, error),
	getPermissionsByUserID func(userID string) ([]Permission, error),
) (username string, permissions []Permission, reject bool) {
	username, permissions, reject = Authenticate(w, r, getPublicKeyByUserID, getPermissionsByUserID)
	if reject {
		return username, permissions, reject
	}

	if permissionKey != PERMISSION_NOT_SPECIFIED {
		if reject := Authorize(permissionKey, metadata, permissions); reject {
			http.Error(w, "", http.StatusUnauthorized)
			return "", nil, true
		}
	}

	return username, permissions, false
}

func Authenticate(
	w http.ResponseWriter,
	r *http.Request,
	getPublicKeyByUserID func(userID string) (*rsa.PublicKey, error),
	getPermissionsByUserID func(userID string) ([]Permission, error),
) (userID string, permissions []Permission, reject bool) {

	token := r.Header.Get("Authorization")

	userID, err := VerifyToken(token, getPublicKeyByUserID)
	if err != nil {
		ErrorHandler(userID, err)
		http.Error(w, "", http.StatusUnauthorized)
		return "", nil, true
	}

	permissions, err = getPermissionsByUserID(userID)
	if err != nil {
		ErrorHandler(userID, err)
		http.Error(w, "", http.StatusUnauthorized)
		return "", nil, true
	}

	return userID, permissions, false
}

func Authorize(permissionKey PermissionKey, metadata *string, permissions []Permission) (reject bool) {
	for _, permission := range permissions {
		if permission.Key != permissionKey {
			continue
		}
		if metadata != nil && *metadata != permission.Metadata {
			continue
		}

		return false
	}

	return true
}
