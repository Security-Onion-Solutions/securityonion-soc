// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2023 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package web

import (
	"context"
	"github.com/google/uuid"
	"net/http"
)

type ContextKey string

const ContextKeyRequestId = ContextKey("ContextKeyRequestId")
const ContextKeyRequestorId = ContextKey("ContextKeyRequestorId")
const ContextKeyRequestor = ContextKey("ContextKeyRequestor")

type BasePreprocessor struct {
}

func NewBasePreprocessor() *BasePreprocessor {
	return &BasePreprocessor{}
}

func (Processor *BasePreprocessor) PreprocessPriority() int {
	return 0
}

func (processor *BasePreprocessor) Preprocess(ctx context.Context, req *http.Request) (context.Context, int, error) {
	uuid := uuid.New().String()
	ctx = context.WithValue(ctx, ContextKeyRequestId, uuid)
	return ctx, 0, nil
}
