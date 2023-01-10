// Copyright 2020-2023 Security Onion Solutions. All rights reserved.
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
  "github.com/stretchr/testify/assert"
  "net/http"
  "testing"
)

func TestPreprocessPriority(tester *testing.T) {
  handler := NewBasePreprocessor()
  assert.Zero(tester, handler.PreprocessPriority())
}

func TestPreprocess(tester *testing.T) {
  handler := NewBasePreprocessor()
  request, _ := http.NewRequest("GET", "", nil)
  ctx, statusCode, err := handler.Preprocess(context.Background(), request)
  assert.NoError(tester, err)
  assert.Zero(tester, statusCode)

  actualId := ctx.Value(ContextKeyRequestId).(string)
  assert.Len(tester, actualId, 36, "Expected valid UUID")
}
