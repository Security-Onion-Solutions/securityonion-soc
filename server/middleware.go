package server

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/web"
)

type ContextKey string

const (
	ContextKeyRequestId   ContextKey = "ContextKeyRequestId"
	ContextKeyRequestorId ContextKey = "ContextKeyRequestorId"
	ContextKeyRequestor   ContextKey = "ContextKeyRequestor"
)

func Middleware(host *web.Host) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Version", host.Version)

			ctx := r.Context()
			ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())

			ctx, statusCode, err := host.Preprocess(ctx, r)
			if err != nil {
				r = r.WithContext(ctx)
				Respond(w, r, statusCode, err)
				return
			}

			r = r.WithContext(ctx)

			err = validateRequest(ctx, host, r)
			if err != nil {
				Respond(w, r, http.StatusBadRequest, err)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func validateRequest(ctx context.Context, host *web.Host, request *http.Request) error {
	if request.Method == http.MethodPost ||
		request.Method == http.MethodPut ||
		request.Method == http.MethodPatch ||
		request.Method == http.MethodDelete {

		userId := ctx.Value(web.ContextKeyRequestorId).(string)
		if userId != host.SrvExemptId {

			token := request.Header.Get("x-srv-token")
			if len(token) == 0 {
				return errors.New("Missing SRV token on request")
			}

			return model.ValidateSrvToken(host.SrvKey, userId, token)
		}
	}
	return nil
}
