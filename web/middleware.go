package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"

	"github.com/apex/log"
)

func Middleware(host *Host, isWS bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Version", host.Version)

			ctx := r.Context()
			ctx = context.WithValue(ctx, ContextKeyRequestStart, time.Now())

			ctx, statusCode, err := host.Preprocess(ctx, r)
			if err != nil {
				r = r.WithContext(ctx)
				Respond(w, r, statusCode, err)
				return
			}

			r = r.WithContext(ctx)

			if !isWS {
				err = validateRequest(ctx, host, r)
				if err != nil {
					Respond(w, r, http.StatusBadRequest, err)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

func validateRequest(ctx context.Context, host *Host, request *http.Request) error {
	if request.Method == http.MethodPost ||
		request.Method == http.MethodPut ||
		request.Method == http.MethodPatch ||
		request.Method == http.MethodDelete {

		userId := ctx.Value(ContextKeyRequestorId).(string)
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

func ReadJson(request *http.Request, obj interface{}) error {
	return json.NewDecoder(request.Body).Decode(obj)
}

// Respond is a helper that bookends the middleware process by logging the
// response. `obj` can be any type, but if it matches the error interface, it
// will be logged and the statusCode adjusted accordingly.
func Respond(w http.ResponseWriter, r *http.Request, statusCode int, obj any) {
	var contentLength int

	ctx := r.Context()
	start := ctx.Value(ContextKeyRequestStart).(time.Time)
	elapsed := time.Since(start).Milliseconds()

	err, isErr := obj.(error)
	if isErr {
		log.WithError(err).WithFields(log.Fields{
			"requestId": ctx.Value(ContextKeyRequestId),
			"requestor": ctx.Value(ContextKeyRequestor),
		}).Warn("Request did not complete successfully")

		var unauthorizedError *model.Unauthorized
		if errors.As(err, &unauthorizedError) {
			statusCode = http.StatusUnauthorized
		} else if statusCode < http.StatusBadRequest {
			statusCode = http.StatusInternalServerError
		}

		bytes := []byte(ConvertErrorToSafeString(err))
		contentLength = len(bytes)

		if w != nil {
			w.WriteHeader(statusCode)
			_, _ = w.Write(bytes)
		}
	} else if obj != nil {
		switch data := obj.(type) {
		case []byte:
			contentLength = len(data)
			if w != nil {
				_, _ = w.Write(data)
			}
		default:
			bytes, err := json.Marshal(obj)
			if err != nil {
				Respond(w, r, http.StatusInternalServerError, err)
				return
			}

			contentLength = len(bytes)

			if w != nil {
				w.WriteHeader(statusCode)
				_, _ = w.Write(bytes)
			}
		}
	}

	fnc, file, line := getCallerDetails(0)

	impl := "unknown"
	if line != -1 {
		impl = fmt.Sprintf("%s:%d:%s", file, line, fnc)
	}

	log.WithFields(log.Fields{
		"remoteAddr":    r.RemoteAddr,
		"sourceIp":      GetSourceIp(r),
		"path":          r.URL.Path,
		"query":         r.URL.Query(),
		"impl":          impl,
		"statusCode":    statusCode,
		"contentLength": contentLength,
		"method":        r.Method,
		"elapsedMs":     elapsed,
		"requestId":     ctx.Value(ContextKeyRequestId),
		"requestor":     ctx.Value(ContextKeyRequestor),
	}).Info("Handled request")
}
