package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"time"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/web"
)

func ReadJson(request *http.Request, obj interface{}) error {
	return json.NewDecoder(request.Body).Decode(obj)
}

func Respond(w http.ResponseWriter, r *http.Request, statusCode int, obj any) {
	var contentLength int

	ctx := r.Context()
	start := ctx.Value(web.ContextKeyRequestStart).(time.Time)
	elapsed := time.Since(start).Milliseconds()

	err, isErr := obj.(error)
	if isErr {
		log.WithError(err).WithFields(log.Fields{
			"requestId": ctx.Value(web.ContextKeyRequestId),
			"requestor": ctx.Value(web.ContextKeyRequestor),
		}).Warn("Request did not complete successfully")

		var unauthorizedError *model.Unauthorized
		if errors.As(err, &unauthorizedError) {
			statusCode = http.StatusUnauthorized
		} else if statusCode < http.StatusBadRequest {
			statusCode = http.StatusInternalServerError
		}

		bytes := []byte(web.ConvertErrorToSafeString(err))
		contentLength = len(bytes)

		w.WriteHeader(statusCode)
		_, _ = w.Write(bytes)
	} else if obj != nil {
		switch data := obj.(type) {
		case []byte:
			contentLength = len(data)
			_, _ = w.Write(data)
		default:
			bytes, err := json.Marshal(obj)
			if err != nil {
				Respond(w, r, http.StatusInternalServerError, err)
				return
			}

			contentLength = len(bytes)

			w.WriteHeader(statusCode)
			_, _ = w.Write(bytes)
		}
	}

	fnc, file, line := getCallerDetails(0)

	impl := "unknown"
	if line != -1 {
		impl = fmt.Sprintf("%s:%d:%s", file, line, fnc)
	}

	log.WithFields(log.Fields{
		"remoteAddr":    r.RemoteAddr,
		"sourceIp":      web.GetSourceIp(r),
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
