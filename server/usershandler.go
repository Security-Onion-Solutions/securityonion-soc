// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/go-chi/chi/v5"
)

var idVerifier = regexp.MustCompile(`^[A-Za-z0-9-]+$`)
var roleVerifier = regexp.MustCompile(`^[A-Za-z0-9-_]+$`)

type UsersHandler struct {
	server *Server
}

func RegisterUsersRoutes(srv *Server, r chi.Router, prefix string) {
	h := &UsersHandler{
		server: srv,
	}

	r.Route(prefix, func(r chi.Router) {
		r.Use(h.usersEnabled)

		r.Get("/", h.getUsers)

		r.Post("/", h.postUser)
		r.Post("/{id}/role/{role}", h.postAddRole)

		r.Put("/sync", h.putSync)
		r.Put("/{id}", h.putUser)
		r.Put("/{id}/password", h.putPassword)
		r.Put("/{id}/{toggle}", h.putToggleUser)

		r.Delete("/{id}", h.deleteUser)
		r.Delete("/{id}/role/{role}", h.deleteUserRole)
	})
}

func (h *UsersHandler) usersEnabled(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.server.Userstore == nil {
			if h.server.Config.DeveloperEnabled {
				web.Respond(w, r, http.StatusOK, nil)
				return
			}

			web.Respond(w, r, http.StatusMethodNotAllowed, errors.New("Users module not enabled"))
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (h *UsersHandler) getUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	users, err := h.server.Userstore.GetUsers(ctx)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	web.Respond(w, r, http.StatusOK, users)
}

func (h *UsersHandler) postUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	user := model.NewUser()

	err := web.ReadJson(r, user)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	err = h.server.AdminUserstore.AddUser(ctx, user)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, user)
}

func (h *UsersHandler) postAddRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := chi.URLParam(r, "id")
	role := chi.URLParam(r, "role")

	safe := idVerifier.MatchString(id)
	if !safe {
		web.Respond(w, r, http.StatusBadRequest, errors.New("Invalid id"))
		return
	}

	safe = roleVerifier.MatchString(role)
	if !safe {
		web.Respond(w, r, http.StatusBadRequest, errors.New("Invalid role"))
		return
	}

	err := h.server.AdminUserstore.AddRole(ctx, id, role)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, nil)
}

func (h *UsersHandler) putUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := chi.URLParam(r, "id")

	user := model.NewUser()
	err := web.ReadJson(r, user)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	user.Id = id

	err = h.server.AdminUserstore.UpdateProfile(ctx, user)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, user)
}

func (h *UsersHandler) putSync(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	err := h.server.AdminUserstore.SyncUsers(ctx)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, nil)
}

func (h *UsersHandler) putPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := chi.URLParam(r, "id")

	user := model.NewUser()

	err := web.ReadJson(r, user)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	err = h.server.AdminUserstore.ResetPassword(ctx, id, user.Password)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, nil)
}

func (h *UsersHandler) putToggleUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var err error
	id := chi.URLParam(r, "id")

	toggle := chi.URLParam(r, "toggle")
	switch strings.ToLower(toggle) {
	case "disable":
		err = h.server.AdminUserstore.DisableUser(ctx, id)
	case "enable":
		err = h.server.AdminUserstore.EnableUser(ctx, id)
	default:
		err = errors.New("Invalid action")
	}

	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, nil)
}

func (h *UsersHandler) deleteUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := chi.URLParam(r, "id")
	safe := idVerifier.MatchString(id)
	if !safe {
		web.Respond(w, r, http.StatusBadRequest, errors.New("Invalid id"))
		return
	}

	err := h.server.AdminUserstore.DeleteUser(ctx, id)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, nil)
}

func (h *UsersHandler) deleteUserRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := chi.URLParam(r, "id")
	role := chi.URLParam(r, "role")

	safe := idVerifier.MatchString(id)
	if !safe {
		web.Respond(w, r, http.StatusBadRequest, errors.New("Invalid id"))
		return
	}

	safe = roleVerifier.MatchString(role)
	if !safe {
		web.Respond(w, r, http.StatusBadRequest, errors.New("Invalid role"))
		return
	}

	err := h.server.AdminUserstore.DeleteRole(ctx, id, role)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, nil)
}
