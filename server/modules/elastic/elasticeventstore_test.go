// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package elastic

import (
	"fmt"
	"io/ioutil"
	"regexp"
	"testing"
)

func TestFieldMapping(tester *testing.T) {
	store := &ElasticEventstore{}

	json, err := ioutil.ReadFile("fieldcaps_response.json")
	if err != nil {
		tester.Errorf("Unexpected error while loading test resource: %v", err)
	}
	store.cacheFieldsFromJson(string(json))

	// Exists as keyword and not already aggregatable
	actual := store.mapElasticField("smb.service")
	if actual != "smb.service.keyword" {
		tester.Errorf("expected mapped field %s but got %s", "smb.service.keyword", actual)
	}

	// Exists as keyword but already aggregatable
	actual = store.mapElasticField("agent.ip")
	if actual != "agent.ip" {
		tester.Errorf("expected mapped field %s but got %s", "agent.ip", actual)
	}

	// Does not exist as valid keyword
	actual = store.mapElasticField("event.acknowledged")
	if actual != "event.acknowledged" {
		tester.Errorf("expected unmapped field %s but got %s", "event.acknowledged", actual)
	}

	// Both non-keyword and keyword variants are aggregatable
	actual = store.unmapElasticField("agent.ip.keyword")
	if actual != "agent.ip.keyword" {
		tester.Errorf("expected unmapped field %s but got %s", "agent.ip.keyword", actual)
	}

	// Only keyword variant is aggregatable
	actual = store.unmapElasticField("smb.service.keyword")
	if actual != "smb.service" {
		tester.Errorf("expected unmapped field %s but got %s", "smb.service", actual)
	}

	// Neither are aggregatable
	actual = store.unmapElasticField("event.acknowledged")
	if actual != "event.acknowledged" {
		tester.Errorf("expected unmapped field %s but got %s", "event.acknowledged", actual)
	}
}

func TestFieldMappingCache(tester *testing.T) {
	store := &ElasticEventstore{}

	json, err := ioutil.ReadFile("fieldcaps_response.json")
	if err != nil {
		tester.Errorf("Unexpected error while loading test resource: %v", err)
	}
	store.cacheFieldsFromJson(string(json))

	field := store.fieldDefs["smb.service"]
	if field == nil {
		tester.Errorf("expected field definition")
	}
	if field.name != "smb.service" {
		tester.Errorf("expected name %s but got %s", "ack", field.name)
	}
	if field.fieldType != "text" {
		tester.Errorf("expected fieldType %s but got %s", "text", field.fieldType)
	}
	if field.aggregatable != false {
		tester.Errorf("expected aggregatable %t but got %t", false, field.aggregatable)
	}
	if field.searchable != true {
		tester.Errorf("expected searchable %t but got %t", true, field.searchable)
	}

	fieldKeyword := store.fieldDefs["smb.service.keyword"]
	if fieldKeyword == nil {
		tester.Errorf("expected field definition")
	}
	if fieldKeyword.name != "smb.service.keyword" {
		tester.Errorf("expected name %s but got %s", "smb.service.keyword", fieldKeyword.name)
	}
	if fieldKeyword.fieldType != "keyword" {
		tester.Errorf("expected fieldType %s but got %s", "keyword", fieldKeyword.fieldType)
	}
	if fieldKeyword.aggregatable != true {
		tester.Errorf("expected aggregatable %t but got %t", true, fieldKeyword.aggregatable)
	}
	if fieldKeyword.searchable != true {
		tester.Errorf("expected searchable %t but got %t", true, fieldKeyword.searchable)
	}
}

func TestTransformIndex(tester *testing.T) {
	store := &ElasticEventstore{}
	if store.transformIndex("test") != "test" {
		tester.Errorf("expected transformed index to be unmodified")
	}

	actual := store.transformIndex("test_{today}")
	match, _ := regexp.MatchString("test_[0-9]{4}.[0-9]{2}.[0-9]{2}", actual)
	if !match {
		tester.Errorf("expected transformed index to contain a date")
	}
}

func TestReadErrorFromJson(tester *testing.T) {
	store := &ElasticEventstore{}
	json := `{"error":{"type":"some type","reason":"some reason"},"something.else":"yes"}`
	err := store.readErrorFromJson(json)
	if err == nil {
		tester.Errorf("Expected error to be returned")
	}
	expected := `some type: some reason -> {"error":{"type":"some type","reason":"some reason"},"something.else":"yes"}`
	actual := fmt.Sprintf("%v", err)
	if actual != expected {
		tester.Errorf("Expected %s but got %s", expected, actual)
	}
}

func TestDisableCrossClusterIndexing(tester *testing.T) {
	store := &ElasticEventstore{}
	indexes := make([]string, 2, 2)
	indexes[0] = "*:so-*"
	indexes[1] = "my-*"
	newIndexes := store.disableCrossClusterIndexing(indexes)
	if len(newIndexes) != len(indexes) {
		tester.Errorf("Expected same array lengths")
	}
	if newIndexes[0] != "so-*" {
		tester.Errorf("Expected disabled cross cluster index but got: %s", newIndexes[0])
	}
	if newIndexes[1] != "my-*" {
		tester.Errorf("Expected unmodified index but got: %s", newIndexes[1])
	}
}
