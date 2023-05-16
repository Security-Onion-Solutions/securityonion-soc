// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/security-onion-solutions/securityonion-soc/model"

	"github.com/go-chi/chi"
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
	})
}

func (h *QueryHandler) getQuery(w http.ResponseWriter, r *http.Request) {
	operation := chi.URLParam(r, "operation")

	err := r.ParseForm()
	if err != nil {
		Respond(w, r, http.StatusBadRequest, errors.New("Invalid query operation inputs"))
		return
	}

	queryStr := r.Form.Get("query")
	query := model.NewQuery()

	err = query.Parse(queryStr)
	if err != nil {
		Respond(w, r, http.StatusBadRequest, errors.New("Invalid query input"))
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
				Respond(w, r, http.StatusBadRequest, errors.New("Invalid query after filter applied"))
				return
			}
		} else {
			values := r.Form["value[]"]
			for _, value := range values {
				alteredQuery, err = query.Filter(field, value, scalar, mode, condense)
				if err != nil {
					Respond(w, r, http.StatusBadRequest, errors.New("Invalid query after filter applied"))
					return
				}

				queryStr = query.String()
				query = model.NewQuery()

				err = query.Parse(queryStr)
				if err != nil {
					Respond(w, r, http.StatusBadRequest, errors.New("Unable to parse query"))
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
			Respond(w, r, http.StatusBadRequest, errors.New("Invalid query after group applied"))
			return
		}
	case "sorted":
		field := r.Form.Get("field")

		alteredQuery, err = query.Sort(field)
		if err != nil {
			Respond(w, r, http.StatusBadRequest, errors.New("Invalid query after sort applied"))
			return
		}
	default:
		Respond(w, r, http.StatusBadRequest, errors.New("Unsupported query operation"))
		return
	}

	Respond(w, r, http.StatusOK, alteredQuery)
}
