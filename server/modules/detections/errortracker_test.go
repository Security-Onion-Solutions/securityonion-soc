// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package detections

import (
	"errors"
	"testing"

	"github.com/tj/assert"
)

func TestErrorTracker(t *testing.T) {
	err := errors.New("err")
	err2 := errors.New("err2")

	tests := []struct {
		Name          string
		Tracker       *ErrorTracker
		Errors        []error
		ExpectedError bool
	}{
		{
			Name:          "No Errors",
			Tracker:       NewErrorTracker(1),
			Errors:        []error{nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil},
			ExpectedError: false,
		},
		{
			Name:          "Some Errors, Not Exceeding Limit",
			Tracker:       NewErrorTracker(5),
			Errors:        []error{nil, err, nil, nil, err, err, err, nil, err, nil, err, err, nil, err, err, nil, nil, nil},
			ExpectedError: false,
		},
		{
			Name:          "Worst Case, Not Exceeding Limit",
			Tracker:       NewErrorTracker(5),
			Errors:        []error{err, err, err, err, nil, err, err, err, err, nil, err, err, err, err, nil, err, err, err, err},
			ExpectedError: false,
		},
		{
			Name:          "Exceeding the Limit",
			Tracker:       NewErrorTracker(5),
			Errors:        []error{err, err, err, err, err},
			ExpectedError: true,
		},
		{
			Name:          "Exceeding the Limit Then No More Errors",
			Tracker:       NewErrorTracker(5),
			Errors:        []error{err, err, err, err, err, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil},
			ExpectedError: true,
		},
		{
			Name:          "Mixed Errors",
			Tracker:       NewErrorTracker(10),
			Errors:        []error{nil, err, nil, err2, err, err2, err2, err, err, err, err2, err, err, err2},
			ExpectedError: true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			var e error

			for _, err := range test.Errors {
				e = test.Tracker.AddError(err)
				if e != nil {
					break
				}
			}

			if test.ExpectedError {
				assert.Error(t, e)
			} else {
				assert.NoError(t, e)
			}
		})
	}
}
