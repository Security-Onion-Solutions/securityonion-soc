// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2023 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package kratos

import (
	"context"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"net/http"
)

type KratosPreprocessor struct {
	userstore *KratosUserstore
}

func NewKratosPreprocessor(impl *KratosUserstore) *KratosPreprocessor {
	return &KratosPreprocessor{
		userstore: impl,
	}
}

func (proc *KratosPreprocessor) PreprocessPriority() int {
	return 110
}

func (proc *KratosPreprocessor) Preprocess(ctx context.Context, request *http.Request) (context.Context, int, error) {
	var statusCode int
	var err error

	userId := request.Header.Get("x-user-id")
	if userId != "" {
		ctx = context.WithValue(ctx, web.ContextKeyRequestorId, userId)
		user, err := proc.userstore.GetUser(ctx, userId)
		if err == nil {
			ctx = context.WithValue(ctx, web.ContextKeyRequestor, user)
		}
	}

	return ctx, statusCode, err
}
