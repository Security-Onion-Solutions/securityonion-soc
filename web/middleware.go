package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"runtime"
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

	rvObj := reflect.ValueOf(obj)

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
	} else if rvObj != (reflect.Value{}) && !rvObj.IsNil() {
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
		"requestPath":   r.URL.Path,
		"requestQuery":  r.URL.Query(),
		"impl":          impl,
		"statusCode":    statusCode,
		"contentLength": contentLength,
		"requestMethod": r.Method,
		"elapsedMs":     elapsed,
		"requestId":     ctx.Value(ContextKeyRequestId),
		"requestor":     ctx.Value(ContextKeyRequestor),
	}).Info("Handled request")
}

func getCallerDetails(skip int) (funcName string, file string, line int) {
	// yes, runtime.Callers and runtime.Caller treat their `skip` parameters
	// differently and so have different offsets in this function to account for
	// it

	pc := make([]uintptr, 4+skip) // more than enough room

	// skip = 3
	// 0 => runtime.Callers
	// 1 => getCallingFuncName
	// 2 => the function being called (i.e. Respond)
	// 3 => the calling function (i.e. the handler)
	count := runtime.Callers(3+skip, pc)

	if count == 0 {
		return "", "", -1
	}

	frames := runtime.CallersFrames(pc[:count])
	f, _ := frames.Next()

	// skip = 2
	// 0 => getCallerDetails
	// 1 => Respond
	// 2 => the caller we're interested in
	_, file, line, _ = runtime.Caller(2 + skip)

	return f.Function, file, line
}
