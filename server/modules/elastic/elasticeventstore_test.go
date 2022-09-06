// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastic

import (
	"fmt"
	"io/ioutil"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFieldMapping(tester *testing.T) {
	store := &ElasticEventstore{}

	json, err := ioutil.ReadFile("fieldcaps_response.json")
	assert.Nil(tester, err)
	store.cacheFieldsFromJson(string(json))

	// Exists as keyword and not already aggregatable
	actual := store.mapElasticField("smb.service")
	assert.Equal(tester, "smb.service.keyword", actual)

	// Exists as keyword but already aggregatable
	actual = store.mapElasticField("agent.ip")
	assert.Equal(tester, "agent.ip", actual)

	// Does not exist as valid keyword
	actual = store.mapElasticField("event.acknowledged")
	assert.Equal(tester, "event.acknowledged", actual)

	// Both non-keyword and keyword variants are aggregatable
	actual = store.unmapElasticField("agent.ip.keyword")
	assert.Equal(tester, "agent.ip.keyword", actual)

	// Only keyword variant is aggregatable
	actual = store.unmapElasticField("smb.service.keyword")
	assert.Equal(tester, "smb.service", actual)

	// Neither are aggregatable
	actual = store.unmapElasticField("event.acknowledged")
	assert.Equal(tester, "event.acknowledged", actual)
}

func TestFieldMappingCollisions(tester *testing.T) {
	store := &ElasticEventstore{}

	json, err := ioutil.ReadFile("fieldcaps_response.json")
	assert.Nil(tester, err)
	store.cacheFieldsFromJson(string(json))

	var testTable = []struct {
		given    string
		expected string
	}{
		{"event.module", "event.module.keyword"},
		{"event.category", "event.category.keyword"},
		{"event.dataset", "event.dataset.keyword"},
		{"event.kind", "event.kind.keyword"},
		{"event.outcome", "event.outcome.keyword"},
		{"event.type", "event.type.keyword"},
		{"event.timezone", "event.timezone.keyword"},
	}

	for _, test := range testTable {
		tester.Run("given="+test.given, func(t *testing.T) {
			actual := store.mapElasticField(test.given)
			assert.Equal(tester, test.expected, actual)
		})
	}
}

func TestFieldMappingCache(tester *testing.T) {
	store := &ElasticEventstore{}

	json, err := ioutil.ReadFile("fieldcaps_response.json")
	assert.Nil(tester, err)
	store.cacheFieldsFromJson(string(json))

	field := store.fieldDefs["smb.service"]
	if assert.NotNil(tester, field) {
		assert.Equal(tester, "smb.service", field.name)
		assert.Equal(tester, "text", field.fieldType)
		assert.False(tester, field.aggregatable)
		assert.True(tester, field.searchable)
	}

	fieldKeyword := store.fieldDefs["smb.service.keyword"]
	if assert.NotNil(tester, fieldKeyword) {
		assert.Equal(tester, "smb.service.keyword", fieldKeyword.name)
		assert.Equal(tester, "keyword", fieldKeyword.fieldType)
		assert.False(tester, field.aggregatable)
		assert.True(tester, field.searchable)
	}
}

func TestTransformIndex(tester *testing.T) {
	store := &ElasticEventstore{}
	assert.Equal(tester, "test", store.transformIndex("test"))

	actual := store.transformIndex("test_{today}")
	match, _ := regexp.MatchString("test_[0-9]{4}.[0-9]{2}.[0-9]{2}", actual)
	assert.True(tester, match, "expected transformed index to contain a date")
}

func TestReadErrorFromJson(tester *testing.T) {
	store := &ElasticEventstore{}
	json := `{"error":{"type":"some type","reason":"some reason"},"something.else":"yes"}`
	err := store.readErrorFromJson(json)
	assert.Error(tester, err)
	expected := `some type: some reason -> {"error":{"type":"some type","reason":"some reason"},"something.else":"yes"}`
	actual := fmt.Sprintf("%v", err)
	assert.Equal(tester, expected, actual)
}

func TestDisableCrossClusterIndexing(tester *testing.T) {
	store := &ElasticEventstore{}
	indexes := make([]string, 2, 2)
	indexes[0] = "*:so-*"
	indexes[1] = "my-*"
	newIndexes := store.disableCrossClusterIndexing(indexes)
	assert.Equal(tester, len(indexes), len(newIndexes))
	assert.Equal(tester, "so-*", newIndexes[0])
	assert.Equal(tester, "my-*", newIndexes[1])
}
