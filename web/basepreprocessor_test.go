// Copyright 2020-2021 Security Onion Solutions. All rights reserved.
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
  "net/http"
  "testing"
)

func TestPreprocessPriority(tester *testing.T) {
  handler := NewBasePreprocessor()
  if handler.PreprocessPriority() != 0 {
    tester.Error("expected 0 priority")
  }
}

func TestPreprocess(tester *testing.T) {
  handler := NewBasePreprocessor()
  request, _ := http.NewRequest("GET", "", nil)
  ctx, statusCode, err := handler.Preprocess(context.Background(), request)
  if err != nil {
    tester.Error("expected non-nil err")
  }
  if statusCode != 0 {
    tester.Error("expected 0 statusCode")
  }
  actualId := ctx.Value(ContextKeyRequestId).(string)
  if len(actualId) != 36 {
    tester.Errorf("Expected a valid UUID but got %s", actualId)
  }
}
