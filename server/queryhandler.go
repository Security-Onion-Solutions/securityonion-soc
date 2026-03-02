// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/go-chi/chi/v5"
)

type QueryHandler struct {
	server *Server
}

func RegisterQueryRoutes(srv *Server, r chi.Router, prefix string) {
	h := &QueryHandler{
		server: srv,
	}

	r.Route(prefix, func(r chi.Router) {
		r.Get("/{operation}", h.getQuery)
		r.Get("/active", h.getActiveQueries)

		r.Post("/cancel/{queryId}", h.postCancelQuery)
	})
}

// @Summary      Get Active Queries
// @Description  Returns a list of active event/data queries within the grid. Users will only see their
// @Description  queries unless they have privileged access to see active queries across all users.
// @Description  Requires a Security Onion Pro license.
// @Security     bearer[queries/read]
// @Tags         Query
// @Param        filter  query  bool  false  "If set to true the internal, child, uncancelable, and related queries will be filtered out of the results" example(true)
// @Produce      application/json
// @Success      200    {array}  model.QueryTask    "The list of active queries"
// @Failure      401        "Request was not properly authenticated"
// @Failure      403        "Insufficient permissions for this request"
// @Failure      500        "Internal SOC error; review SOC logs"
// @Router       /connect/query/active [get]
func (h *QueryHandler) getActiveQueries(w http.ResponseWriter, r *http.Request) {
	if !licensing.IsEnabled(licensing.FEAT_QRY) {
		web.Respond(w, r, http.StatusBadRequest, errors.New("ERROR_LICENSE_INVALID"))
		return
	}
	filter := strings.ToLower(r.URL.Query().Get("filter")) == "true"
	results, err := h.server.Eventstore.GetActiveQueries(r.Context(), filter)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	web.Respond(w, r, http.StatusOK, results)
}

// @Summary      Cancel Active Query
// @Description  Requests that the event storage system cancel a specific query identified by the provided input ID.
// @Description  Note that not all queries can be canceled.
// @Description  Requires a Security Onion Pro license.
// @Security     bearer[queries/delete]
// @Tags         Query
// @Param        queryId  path  string  true  "The unique query ID to cancel" example(jSliTqa12bOPhdW195TuuZ:321)
// @Produce      application/json
// @Success      200        "The query cancelation was submitted (may or may not actually get canceled)"
// @Failure      400        "Query could not be canceled"
// @Failure      404        "Query was not found"
// @Failure      401        "Request was not properly authenticated"
// @Failure      403        "Insufficient permissions for this request"
// @Failure      500        "Internal SOC error; review SOC logs"
// @Router       /connect/query/cancel/{queryId} [get]
func (h *QueryHandler) postCancelQuery(w http.ResponseWriter, r *http.Request) {
	if !licensing.IsEnabled(licensing.FEAT_QRY) {
		web.Respond(w, r, http.StatusBadRequest, errors.New("ERROR_LICENSE_INVALID"))
		return
	}
	queryId := chi.URLParam(r, "queryId")
	err := h.server.Eventstore.CancelQuery(r.Context(), queryId)
	if err != nil {
		if err.Error() == "query not found" {
			web.Respond(w, r, http.StatusNotFound, errors.New("ERROR_QUERY_NOT_FOUND"))
		} else {
			web.Respond(w, r, http.StatusBadRequest, err)
		}
		return
	}

	web.Respond(w, r, http.StatusOK, nil)
}

// @Summary      Build Query
// @Description  Requests the server provide a new query for the SOC client to show, given a particular change needed in the query.
// @Security     bearer
// @Tags         Query
// @Param        operation  path  string  true  "The type of operation for this query update. Supports: grouped, filtered, sorted" example(grouped)
// @Param        query formData string  true  "The current query string to be modified" example(somefield: somevalue | groupby anotherfield)
// @Param        field formData string  true  "The field to be used for the operation" example(newfield)
// @Param        scalar formData string  true  "Specify true is this field contains scalar values (numerical, etc)" example(true)
// @Param        mode formData string  true  "The operation mode." example(true)
// @Produce      plain
// @Success      200        "The job output stream was successfully saved and is being returned in the response body. Ex: somefield: somevalue | groupby anotherfield | groupby newfield"
// @Failure      400        "The provided input object or parameters are malformed or invalid"
// @Failure      401        "Request was not properly authenticated"
// @Failure      500        "Internal SOC error; review SOC logs"
// @Router       /connect/query/{operation} [get]
func (h *QueryHandler) getQuery(w http.ResponseWriter, r *http.Request) {
	operation := chi.URLParam(r, "operation")

	err := r.ParseForm()
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, errors.New("Invalid query operation inputs"))
		return
	}

	queryStr := r.Form.Get("query")
	query := model.NewQuery()

	err = query.Parse(queryStr)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	var alteredQuery string

	switch operation {
	case "filtered":
		field := r.Form.Get("field")
		scalar := r.Form.Get("scalar") == "true"
		mode := r.Form.Get("mode")
		value := r.Form.Get("value")
		condense := r.Form.Get("condense") == "true"

		if len(value) > 0 {
			alteredQuery, err = query.Filter(field, value, scalar, mode, condense)
			if err != nil {
				web.Respond(w, r, http.StatusBadRequest, err)
				return
			}
		} else {
			values := r.Form["value[]"]
			for _, value := range values {
				alteredQuery, err = query.Filter(field, value, scalar, mode, condense)
				if err != nil {
					web.Respond(w, r, http.StatusBadRequest, err)
					return
				}

				queryStr = query.String()
				query = model.NewQuery()

				err = query.Parse(queryStr)
				if err != nil {
					web.Respond(w, r, http.StatusBadRequest, err)
					return
				}
			}
		}
	case "grouped":
		field := r.Form.Get("field")
		groupStr := r.Form.Get("group")

		groupIdx, err := strconv.ParseInt(groupStr, 10, 32)
		if err != nil {
			groupIdx = 0
		}

		alteredQuery, err = query.Group(int(groupIdx), field)
		if err != nil {
			web.Respond(w, r, http.StatusBadRequest, err)
			return
		}
	case "sorted":
		field := r.Form.Get("field")

		alteredQuery, err = query.Sort(field)
		if err != nil {
			web.Respond(w, r, http.StatusBadRequest, err)
			return
		}
	default:
		web.Respond(w, r, http.StatusBadRequest, errors.New("Unsupported query operation"))
		return
	}

	web.Respond(w, r, http.StatusOK, alteredQuery)
}
