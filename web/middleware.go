// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"

	"github.com/apex/log"
)

const ALL_GRIDS = "_all"

func Middleware(host *Host, isWS bool, subgrids []*model.Subgrid) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Version", host.Version)

			ctx := r.Context()
			ctx = context.WithValue(ctx, ContextKeyRequestStart, time.Now())

			ctx, statusCode, err := host.Preprocess(ctx, r)
			if err != nil {
				r = r.WithContext(ctx)
				Respond(w, r, statusCode, err)
				log.WithError(err).WithFields(log.Fields{
					"requestId":   ctx.Value(ContextKeyRequestId),
					"requestorId": ctx.Value(ContextKeyRequestorId),
				}).Warn("Request did not pass preprocessing")
				return
			}

			r = r.WithContext(ctx)

			if !isWS {
				err = validateRequest(ctx, host, r)
				if err != nil {
					Respond(w, r, http.StatusBadRequest, err)
					log.WithError(err).WithFields(log.Fields{
						"requestId":   ctx.Value(ContextKeyRequestId),
						"requestorId": ctx.Value(ContextKeyRequestorId),
					}).Warn("Request did not pass request validation")
					return
				}
			}

			// Proxy subgrid requests
			gridId := strings.TrimSpace(r.URL.Query().Get("gridId"))
			if len(gridId) > 0 {
				ctx = context.WithValue(ctx, ContextKeySubgridResponses, make(map[string][]byte))
				r = r.WithContext(ctx)
				proxySubgridRequest(subgrids, gridId, ctx, w, r)
			}

			// If there was no subgrid specified
			if len(gridId) == 0 {
				log.WithFields(log.Fields{
					"requestId":   ctx.Value(ContextKeyRequestId),
					"requestorId": ctx.Value(ContextKeyRequestorId),
				}).Debug("Serving HTTP request")

				next.ServeHTTP(w, r)
			}
		})
	}
}

func validateRequest(ctx context.Context, host *Host, request *http.Request) error {
	if request.Method == http.MethodPost ||
		request.Method == http.MethodPut ||
		request.Method == http.MethodPatch ||
		request.Method == http.MethodDelete {

		exempt := ctx.Value(ContextKeyRequestCSRFExempt).(bool)
		if exempt {
			return nil
		}

		token := request.Header.Get("x-srv-token")
		if len(token) == 0 {
			return errors.New("Missing SRV token on request")
		}

		userId := ctx.Value(ContextKeyRequestorId).(string)
		return model.ValidateSrvToken(host.SrvKey, userId, token)
	}
	return nil
}

func ReadJson(request *http.Request, obj interface{}) error {
	return json.NewDecoder(request.Body).Decode(obj)
}

// Respond is a helper that bookends the middleware process by logging the
// response. `obj` can be any type, but if it matches the error interface, it
// will be logged and the statusCode adjusted accordingly.
func Respond(w http.ResponseWriter, r *http.Request, statusCode int, obj interface{}) {
	var contentLength int

	ctx := r.Context()
	logger := log.FromContext(ctx)

	start := ctx.Value(ContextKeyRequestStart).(time.Time)
	elapsed := time.Since(start).Milliseconds()

	err, isErr := obj.(error)
	if isErr {
		logger.WithError(err).WithFields(log.Fields{
			"requestId":   ctx.Value(ContextKeyRequestId),
			"requestorId": ctx.Value(ContextKeyRequestorId),
		}).Warn("Request did not complete successfully")

		var unauthorizedError *model.Unauthorized
		if errors.As(err, &unauthorizedError) {
			statusCode = http.StatusForbidden
			err = errors.New("ERROR_PERMISSION_DENIED")
		} else if statusCode < http.StatusBadRequest {
			statusCode = http.StatusInternalServerError
		} else if err.Error() == "Object not found" {
			statusCode = http.StatusNotFound
		}

		bytes := []byte(ConvertErrorToSafeString(err))
		contentLength = len(bytes)

		if w != nil {
			w.WriteHeader(statusCode)
			_, _ = w.Write(bytes)
		}
	} else if !isNil(obj) {
		switch data := obj.(type) {
		case []byte:
			contentLength = len(data)
			if w != nil {
				_, _ = w.Write(data)
			}
		case http.Response:
			w.Header().Set("Content-Type", data.Header.Get("Content-Type"))
			w.WriteHeader(data.StatusCode)
			io.Copy(w, data.Body)
		default:
			bytes, err := json.Marshal(obj)
			if err != nil {
				Respond(w, r, http.StatusInternalServerError, err)
				return
			}

			contentLength = len(bytes)

			if w != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(statusCode)
				_, _ = w.Write(bytes)
			}
		}
	} else {
		if w != nil {
			w.WriteHeader(statusCode)
		}
	}

	fnc, file, line := getCallerDetails(0)

	impl := "unknown"
	if line != -1 {
		impl = fmt.Sprintf("%s:%d:%s", file, line, fnc)
	}

	logger.WithFields(log.Fields{
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
		"requestorId":   ctx.Value(ContextKeyRequestorId),
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

func isNil(i interface{}) bool {
	if i == nil {
		return true
	}
	switch reflect.TypeOf(i).Kind() {
	case reflect.Ptr, reflect.Map, reflect.Array, reflect.Chan, reflect.Slice:
		return reflect.ValueOf(i).IsNil()
	}
	return false
}

func proxySubgridRequest(subgrids []*model.Subgrid, gridId string, ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var subgridResponsesById map[string][]byte
	subgridResponses := ctx.Value(ContextKeySubgridResponses)
	if subgridResponses != nil {
		if responseMap, ok := subgridResponses.(map[string][]byte); ok {
			subgridResponsesById = responseMap
		}
	}

	for _, grid := range subgrids {
		if isSubgridSelected(grid, gridId) {
			// Proxy the request down to the subgrid
			subgridUrl, err := url.Parse(r.RequestURI)
			if err != nil {
				err := errors.New("ERROR_SUBGRID_URL_INVALID")
				Respond(w, r, http.StatusBadRequest, err)
				return
			}
			qry := subgridUrl.Query()
			qry.Del("gridId")
			qry.Add("assignedGridId", grid.Id)
			subgridUrl.RawQuery = qry.Encode()
			url := subgridUrl.Path
			subgridUrl.Path = strings.Replace(url, "api/", "", 1)

			headers := make(map[string]string)
			contentTypes := r.Header.Values("Content-Type")
			if len(contentTypes) > 0 {
				headers["Content-Type"] = contentTypes[0]
			}

			log.WithFields(log.Fields{
				"requestId":    ctx.Value(ContextKeyRequestId),
				"requestorId":  ctx.Value(ContextKeyRequestorId),
				"gridId":       grid.Id,
				"subgridUrl":   subgridUrl.String(),
				"proxyHeaders": headers,
			}).Info("Proxying request to subgrid")
			resp, err := grid.MakeApiCall(r.Method, subgridUrl.String(), r.Body, headers)
			if err != nil {
				log.WithError(err).WithFields(log.Fields{
					"requestId":   ctx.Value(ContextKeyRequestId),
					"requestorId": ctx.Value(ContextKeyRequestorId),
					"gridId":      grid.Id,
					"subgridUrl":  subgridUrl.String(),
				}).Error("Failed to proxy request to subgrid")

				if resp == nil {
					err = errors.New("ERROR_SUBGRID_API_UNREACHABLE")
					Respond(w, r, http.StatusBadGateway, err)
					return
				}
			} else {
				log.WithFields(log.Fields{
					"requestId":   ctx.Value(ContextKeyRequestId),
					"requestorId": ctx.Value(ContextKeyRequestorId),
				}).Debug("Finished proxying request to subgrid")
			}

			if checkForRedirect(ctx, w, r, resp) {
				return
			}

			if isOnlySubgridSelected(grid, gridId) {
				Respond(w, r, resp.StatusCode, *resp)
				return
			} else if subgridResponsesById != nil {
				bytes, err := io.ReadAll(resp.Body)
				if err != nil {
					// Store this grid's response in case it needs to be merged with the local grid response
					subgridResponsesById[grid.Id] = bytes
				}
			}
		}
	}

	if len(subgridResponsesById) == 0 && !isLocalGridSelected(gridId) {
		// Subgrid not found
		err := errors.New("ERROR_SUBGRID_INVALID")
		Respond(w, r, http.StatusBadRequest, err)
		return
	}
}

func isLocalGridSelected(gridId string) bool {
	return gridId == ALL_GRIDS
}

func isSubgridSelected(grid *model.Subgrid, gridId string) bool {
	return isOnlySubgridSelected(grid, gridId) || gridId == ALL_GRIDS
}

func isOnlySubgridSelected(grid *model.Subgrid, gridId string) bool {
	return grid.Id == gridId
}

func checkForRedirect(ctx context.Context, w http.ResponseWriter, r *http.Request, resp *http.Response) bool {
	// If the subgrid response includes a redirect, honor it. Currently only used for joblookup.
	redir := resp.Header.Get("location")
	if len(redir) > 0 {
		log.WithFields(log.Fields{
			"requestId":   ctx.Value(ContextKeyRequestId),
			"requestorId": ctx.Value(ContextKeyRequestorId),
			"redirectUrl": redir,
		}).Info("Subgrid requests a redirect")
		http.Redirect(w, r, redir, resp.StatusCode)
		return true
	}
	return false
}
