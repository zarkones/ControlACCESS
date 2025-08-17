package access

import (
	"context"
	"net/http"
)

func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, authorized, err := IsAuthorized(w, r, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if !authorized {
			// Response already handled by IsAuthorized.
			return
		}

		ctx := context.WithValue(r.Context(), "userID", userID)
		r = r.WithContext(ctx)
		next(w, r)
	}
}
