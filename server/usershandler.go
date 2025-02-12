// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
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

var idVerifier = regexp.MustCompile(`^[A-Za-z0-9-]{36}$`)
var roleVerifier = regexp.MustCompile(`^[A-Za-z0-9-_]{3,50}$`)

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

// @Summary      Get Users
// @Description  Returns all SOC users.
// @Tags         Users
// @Security     bearer[users/read]
// @Produce      json
// @Success      200  {array}   model.User   "List of user objects, or empty list if not permitted to view user list"
// @Failure      401         "Request was not properly authenticated"
// @Failure      405         "User module not configured on server"
// @Failure      500         "Internal SOC error; review SOC logs"
// @Router       /connect/users [get]
func (h *UsersHandler) getUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	users, err := h.server.Userstore.GetUsers(ctx)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, users)
}

// @Summary      Create User
// @Description  Creates a new SOC user.
// @Tags         Users
// @Security     bearer[users/write]
// @Param        request  body  model.User true "User object to be created. The provided email address, firstname, lastname, note, roles, and password will be used. All other fields are ignored."
// @Accept       json
// @Produce      json
// @Success      200  {object}  model.User   "Returns the same user object that was provided as input"
// @Failure      400         "The provided input object or parameters are malformed or invalid"
// @Failure      401         "Request was not properly authenticated"
// @Failure      405         "User module not configured on server"
// @Failure      500         "Internal SOC error; review SOC logs"
// @Router       /connect/users [post]
func (h *UsersHandler) postUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	user := model.NewUser()

	err := web.ReadJson(r, user)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	err = user.Verify()
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

// @Summary      Grant User Role
// @Description  Grants an existing user a role. The user will then have permissions that this role provides.
// @Param        id    path  string  true  "The user ID"
// @Param        role  path  string  true  "The role name"
// @Tags         Users
// @Security     bearer[users/write]
// @Success      200        "The role was successfully granted to the user"
// @Failure      400        "The provided input object or parameters are malformed or invalid"
// @Failure      401        "Request was not properly authenticated"
// @Failure      405        "User module not configured on server"
// @Failure      500        "Internal SOC error; review SOC logs"
// @Router       /connect/users/{id}/role/{role} [post]
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

// @Summary      Update User
// @Description  Update a user with the provided user object data.
// @Tags         Users
// @Security     bearer[users/write]
// @Param        id    path  string  true  "The user ID"
// @Param        request  body  model.User true "User object containing new updates. The provided email address, firstname, lastname, and note will be updated. All other fields are ignored."
// @Accept       json
// @Produce      json
// @Success      200  {object}  model.User   "Returns the same user object that was provided as input, with the requested id populated"
// @Failure      400       "The provided input object or parameters are malformed or invalid"
// @Failure      401       "Request was not properly authenticated"
// @Failure      405       "User module not configured on server"
// @Failure      500       "Internal SOC error; review SOC logs"
// @Router       /connect/users/{id} [put]
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
	err = user.Verify()
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}
	err = h.server.AdminUserstore.UpdateProfile(ctx, user)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, user)
}

// @Summary      Synchronize Users
// @Description  Synchronizes all SOC users across the grid. This is an asynchronous request.
// @Description  The background operation can take several minutes to complete.
// @Tags         Users
// @Security     bearer[users/write]
// @Success      200         "The synchronization request has been submitted"
// @Failure      401         "Request was not properly authenticated"
// @Failure      405         "User module not configured on server"
// @Failure      500         "Internal SOC error; review SOC logs"
// @Router       /connect/users/sync [put]
func (h *UsersHandler) putSync(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	err := h.server.AdminUserstore.SyncUsers(ctx)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, nil)
}

// @Summary      Change Password
// @Description  Update a user's password with the provided value.
// @Tags         Users
// @Security     bearer[users/write]
// @Param        id    path  string  true  "The user ID"
// @Param        request  body  model.User true "User object containing the new password. All other fields are ignored."
// @Accept       json
// @Success      200      "Password successfully updated."
// @Failure      400      "The provided input object or parameters are malformed or invalid"
// @Failure      401      "Request was not properly authenticated"
// @Failure      405      "User module not configured on server"
// @Failure      500      "Internal SOC error; review SOC logs"
// @Router       /connect/users/{id}/password [put]
func (h *UsersHandler) putPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := chi.URLParam(r, "id")
	safe := idVerifier.MatchString(id)
	if !safe {
		web.Respond(w, r, http.StatusBadRequest, errors.New("Invalid id"))
		return
	}

	user := model.NewUser()

	err := web.ReadJson(r, user)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}
	err = user.Verify()
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

// @Summary      Toggle User Enabled
// @Description  Update a user's status to enabled or disabled
// @Tags         Users
// @Security     bearer[users/write]
// @Param        id    path  string  true  "The user ID"
// @Param        toggle    path  string  true  "Desired toggle action. Set to 'enable' or 'disable'."
// @Success      200         "User status successfully updated"
// @Failure      400         "The provided input object or parameters are malformed or invalid"
// @Failure      401         "Request was not properly authenticated"
// @Failure      405         "User module not configured on server"
// @Failure      500         "Internal SOC error; review SOC logs"
// @Router       /connect/users/{id}/{toggle} [put]
func (h *UsersHandler) putToggleUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var err error
	id := chi.URLParam(r, "id")
	safe := idVerifier.MatchString(id)
	if !safe {
		web.Respond(w, r, http.StatusBadRequest, errors.New("Invalid id"))
		return
	}

	toggle := chi.URLParam(r, "toggle")
	switch strings.ToLower(toggle) {
	case "disable":
		err = h.server.AdminUserstore.DisableUser(ctx, id)
	case "enable":
		err = h.server.AdminUserstore.EnableUser(ctx, id)
	default:
		web.Respond(w, r, http.StatusBadRequest, errors.New("Invalid toggle action"))
		return
	}

	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, nil)
}

// @Summary      Delete User
// @Description  Deletes the provided user ID.
// @Tags         Users
// @Security     bearer[users/write]
// @Param        id    path  string  true  "The user ID"
// @Success      200        "User successfully deleted"
// @Failure      400        "The provided input object or parameters are malformed or invalid"
// @Failure      401        "Request was not properly authenticated"
// @Failure      405        "User module not configured on server"
// @Failure      500        "Internal SOC error; review SOC logs"
// @Router       /connect/users/{id} [delete]
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

// @Summary      Deny User Role
// @Description  Denies an existing user a role. The user will no longer have permissions that this role provides.
// @Param        id    path  string  true  "The user ID"
// @Param        role  path  string  true  "The role name"
// @Tags         Users
// @Security     bearer[users/write]
// @Success      200         "The role was successfully removed from the user"
// @Failure      400         "The provided input object or parameters are malformed or invalid"
// @Failure      401         "Request was not properly authenticated"
// @Failure      405         "User module not configured on server"
// @Failure      500         "Internal SOC error; review SOC logs"
// @Router       /connect/users/{id}/role/{role} [delete]
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
