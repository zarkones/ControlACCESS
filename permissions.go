package access

import (
	"crypto/rsa"
	"errors"
	"net/http"
)

var (
	ErrEndpointNotRegistered = errors.New("endpoint not registered")
)

// Permissions = method + path (aka endpoint key) -> PermissionKey
var Permissions = map[string]PermissionKey{}

func Route(r *http.ServeMux, method, path string, permission PermissionKey, handler func(http.ResponseWriter, *http.Request)) {
	Permissions[method+path] = permission
	r.HandleFunc(method+" "+path, handler)
}

var HandlerGetUserPublicKey func(userID string) (*rsa.PublicKey, error)
var HandlerGetPermissionsByUserID func(userID string) ([]Permission, error)

// IsAuthorized returns error only if the process failed, not if it's not authorized.
func IsAuthorized(w http.ResponseWriter, r *http.Request, metadata *string) (userID string, isAuthorized bool, err error) {
	endpointKey := r.Method + r.URL.Path

	permissionKey, ok := Permissions[endpointKey]
	if !ok {
		return "", false, ErrEndpointNotRegistered
	}

	userID, permissions, reject := AuthenticateAndAuthorize(
		w,
		r,
		permissionKey,
		metadata,
		HandlerGetUserPublicKey,
		HandlerGetPermissionsByUserID,
	)

	_ = permissions

	if reject {
		return userID, false, nil
	}

	return userID, true, nil
}
