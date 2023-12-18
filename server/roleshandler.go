// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/security-onion-solutions/securityonion-soc/web"
)

type RolesHandler struct {
	server *Server
}

func RegisterRolesRoutes(srv *Server, r chi.Router, prefix string) {
	h := &RolesHandler{
		server: srv,
	}

	r.Route(prefix, func(r chi.Router) {
		r.Use(rolesEnabled(srv))

		r.Get("/", h.getRoles)
	})
}

func rolesEnabled(server *Server) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if server.Rolestore == nil {
				web.Respond(w, r, http.StatusMethodNotAllowed, errors.New("Roles module not enabled"))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func (h *RolesHandler) getRoles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	roles := h.server.Rolestore.GetRoles(ctx)

	web.Respond(w, r, http.StatusOK, roles)
}
