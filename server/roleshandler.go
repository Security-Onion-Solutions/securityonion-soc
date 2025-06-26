// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
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
		r.Get("/permissions", h.getPermissions)
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

// @Summary      Get Roles
// @Description  Retrieves the set of available user roles.
// @Tags         Users
// @Security     bearer[roles/read]
// @Produce      json
// @Success      200  {array}   string       "List of user role names"
// @Failure      401         "Request was not properly authenticated"
// @Failure      405         "Roles module not configured on server"
// @Failure      500         "Internal SOC error; review SOC logs"
// @Router       /connect/roles [get]
func (h *RolesHandler) getRoles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	roles := h.server.Rolestore.GetRoles(ctx)

	web.Respond(w, r, http.StatusOK, roles)
}

// @Summary      Get Permissions
// @Description  Retrieves the set of available client permissions.
// @Description  Note: User roles are made up of assigned permissions. API clients do not
// @Description  use roles and instead are directly assigned individual permissions since
// @Description  each API client is expected to be configured for a specific task.
// @Tags         Clients
// @Security     bearer[permissions/read]
// @Produce      json
// @Success      200  {array}   string       "List of permission names"
// @Failure      401        "Request was not properly authenticated"
// @Failure      405        "Roles module not configured on server"
// @Failure      500        "Internal SOC error; review SOC logs"
// @Router       /connect/roles/permissions [get]
func (h *RolesHandler) getPermissions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	perms := h.server.Rolestore.GetPermissions(ctx)

	web.Respond(w, r, http.StatusOK, perms)
}
