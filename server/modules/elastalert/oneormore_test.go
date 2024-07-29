// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastalert

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

func TestOneOrMore(t *testing.T) {
	type TestStruct struct {
		Value *OneOrMore[string] `yaml:"value"`
	}

	// One
	data := []byte(`value: test`)
	ts := TestStruct{}

	err := yaml.Unmarshal(data, &ts)
	assert.NoError(t, err)
	assert.True(t, ts.Value.HasValue())
	assert.Equal(t, "test", ts.Value.Value)
	assert.Empty(t, ts.Value.Values)

	data, err = yaml.Marshal(ts)
	assert.NoError(t, err)
	assert.Equal(t, "value: test\n", string(data))

	// ...OrMore
	data = []byte(`value: [test1, test2]`)
	ts = TestStruct{}

	err = yaml.Unmarshal(data, &ts)
	assert.NoError(t, err)
	assert.True(t, ts.Value.HasValue())
	assert.Empty(t, ts.Value.Value)
	assert.Equal(t, []string{"test1", "test2"}, ts.Value.Values)

	data, err = yaml.Marshal(ts)
	assert.NoError(t, err)
	assert.Equal(t, "value:\n    - test1\n    - test2\n", string(data))

	// nil
	data = []byte(`value: null`)
	ts = TestStruct{}

	err = yaml.Unmarshal(data, &ts)
	assert.NoError(t, err)
	assert.False(t, ts.Value.HasValue())
	assert.Empty(t, ts)

	data, err = yaml.Marshal(ts)
	assert.NoError(t, err)
	assert.Equal(t, "value: null\n", string(data))

	null := (*OneOrMore[string])(nil)
	assert.False(t, null.HasValue())
}
