// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package export

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
)

const RELATED_EVENT_FIELD_PREFIX = "fields:"

func (export *Export) sortComments(field string, dir string, list []*model.Comment) []*model.Comment {
	sort.Slice(list, func(i, j int) bool {
		a := list[i]
		b := list[j]
		if a == nil || b == nil {
			return false
		}
		switch strings.ToLower(field) {
		case "id":
			return export.compareWithDir(a.Id, b.Id, dir)
		case "createtime":
			return export.compareWithDir(a.CreateTime, b.CreateTime, dir)
		case "updatetime":
			return export.compareWithDir(a.UpdateTime, b.UpdateTime, dir)
		case "userid":
			return export.compareWithDir(a.UserId, b.UserId, dir)
		case "kind":
			return export.compareWithDir(a.Kind, b.Kind, dir)
		case "operation":
			return export.compareWithDir(a.Operation, b.Operation, dir)
		case "description":
			return export.compareWithDir(a.Description, b.Description, dir)
		case "hours":
			return export.compareWithDir(a.Hours, b.Hours, dir)
		default:
			return false
		}
	})
	return list
}

func (export *Export) sortArtifacts(field string, dir string, list []*model.Artifact) []*model.Artifact {
	sort.Slice(list, func(i, j int) bool {
		a := list[i]
		b := list[j]
		if a == nil || b == nil {
			return false
		}
		switch strings.ToLower(field) {
		case "id":
			return export.compareWithDir(a.Id, b.Id, dir)
		case "createtime":
			return export.compareWithDir(a.CreateTime, b.CreateTime, dir)
		case "updatetime":
			return export.compareWithDir(a.UpdateTime, b.UpdateTime, dir)
		case "userid":
			return export.compareWithDir(a.UserId, b.UserId, dir)
		case "kind":
			return export.compareWithDir(a.Kind, b.Kind, dir)
		case "operation":
			return export.compareWithDir(a.Operation, b.Operation, dir)
		case "description":
			return export.compareWithDir(a.Description, b.Description, dir)
		case "tlp":
			return export.compareWithDir(a.Tlp, b.Tlp, dir)
		case "value":
			return export.compareWithDir(a.Value, b.Value, dir)
		case "type":
			return export.compareWithDir(a.ArtifactType, b.ArtifactType, dir)
		case "ioc":
			return export.compareWithDir(a.Ioc, b.Ioc, dir)
		case "sha256":
			return export.compareWithDir(a.Sha256, b.Sha256, dir)
		case "sha1":
			return export.compareWithDir(a.Sha1, b.Sha1, dir)
		case "md5":
			return export.compareWithDir(a.Md5, b.Md5, dir)
		default:
			return false
		}
	})
	return list
}

func (export *Export) sortRelatedEvents(field string, dir string, list []*model.RelatedEvent) []*model.RelatedEvent {
	sort.Slice(list, func(i, j int) bool {
		a := list[i]
		b := list[j]
		if a == nil || b == nil {
			return false
		}
		switch strings.ToLower(field) {
		case "id":
			return export.compareWithDir(a.Id, b.Id, dir)
		case "createtime":
			return export.compareWithDir(a.CreateTime, b.CreateTime, dir)
		case "updatetime":
			return export.compareWithDir(a.UpdateTime, b.UpdateTime, dir)
		case "userid":
			return export.compareWithDir(a.UserId, b.UserId, dir)
		case "kind":
			return export.compareWithDir(a.Kind, b.Kind, dir)
		case "operation":
			return export.compareWithDir(a.Operation, b.Operation, dir)
		default:
			if strings.HasPrefix(field, RELATED_EVENT_FIELD_PREFIX) {
				fieldName := strings.TrimPrefix(field, RELATED_EVENT_FIELD_PREFIX)
				if a.Fields == nil || b.Fields == nil {
					return false // Handle nil or missing fields gracefully
				}
				if _, ok := a.Fields[fieldName]; !ok {
					return false // Handle nil or missing fields gracefully
				}
				if _, ok := b.Fields[fieldName]; !ok {
					return true // Handle nil or missing fields gracefully
				}
				return export.compareWithDir(a.Fields[fieldName], b.Fields[fieldName], dir)
			}
			return false
		}
	})
	return list
}

func (export *Export) sortHistory(field string, dir string, list []*model.Auditable) []*model.Auditable {
	sort.Slice(list, func(i, j int) bool {
		a := list[i]
		b := list[j]
		if a == nil || b == nil {
			return false
		}
		switch strings.ToLower(field) {
		case "id":
			return export.compareWithDir(a.Id, b.Id, dir)
		case "createtime":
			return export.compareWithDir(a.CreateTime, b.CreateTime, dir)
		case "updatetime":
			return export.compareWithDir(a.UpdateTime, b.UpdateTime, dir)
		case "userid":
			return export.compareWithDir(a.UserId, b.UserId, dir)
		case "kind":
			return export.compareWithDir(a.Kind, b.Kind, dir)
		case "operation":
			return export.compareWithDir(a.Operation, b.Operation, dir)
		default:
			return false
		}
	})
	return list
}

func (export *Export) sortDetections(field string, dir string, list []*model.Detection) []*model.Detection {
	sort.Slice(list, func(i, j int) bool {
		a := list[i]
		b := list[j]
		if a == nil || b == nil {
			return false
		}
		switch strings.ToLower(field) {
		case "id":
			return export.compareWithDir(a.Id, b.Id, dir)
		case "createtime":
			return export.compareWithDir(a.CreateTime, b.CreateTime, dir)
		case "updatetime":
			return export.compareWithDir(a.UpdateTime, b.UpdateTime, dir)
		case "userid":
			return export.compareWithDir(a.UserId, b.UserId, dir)
		case "kind":
			return export.compareWithDir(a.Kind, b.Kind, dir)
		case "operation":
			return export.compareWithDir(a.Operation, b.Operation, dir)
		case "author":
			return export.compareWithDir(a.Author, b.Author, dir)
		case "content":
			return export.compareWithDir(a.Content, b.Content, dir)
		case "description":
			return export.compareWithDir(a.Description, b.Description, dir)
		case "engine":
			return export.compareWithDir(a.Engine, b.Engine, dir)
		case "iscommunity":
			return export.compareWithDir(a.IsCommunity, b.IsCommunity, dir)
		case "isenabled":
			return export.compareWithDir(a.IsEnabled, b.IsEnabled, dir)
		case "isreporting":
			return export.compareWithDir(a.IsReporting, b.IsReporting, dir)
		case "language":
			return export.compareWithDir(a.Language, b.Language, dir)
		case "license":
			return export.compareWithDir(a.License, b.License, dir)
		case "publicid":
			return export.compareWithDir(a.PublicID, b.PublicID, dir)
		case "ruleset":
			return export.compareWithDir(a.Ruleset, b.Ruleset, dir)
		case "severity":
			return export.compareWithDir(a.Severity, b.Severity, dir)
		case "title":
			return export.compareWithDir(a.Title, b.Title, dir)
		default:
			return false
		}
	})
	return list
}

func (export *Export) sortAssistantMessages(field string, dir string, list []*model.StoredMessage) []*model.StoredMessage {
	sort.Slice(list, func(i, j int) bool {
		a := list[i]
		b := list[j]
		if a == nil || b == nil {
			return false
		}
		switch strings.ToLower(field) {
		case "id":
			return export.compareWithDir(a.Id, b.Id, dir)
		case "createtime":
			return export.compareWithDir(a.CreateTime, b.CreateTime, dir)
		case "updatetime":
			return export.compareWithDir(a.UpdateTime, b.UpdateTime, dir)
		case "userid":
			return export.compareWithDir(a.UserId, b.UserId, dir)
		case "kind":
			return export.compareWithDir(a.Kind, b.Kind, dir)
		case "operation":
			return export.compareWithDir(a.Operation, b.Operation, dir)
		case "sessionid":
			return export.compareWithDir(a.SessionId, b.SessionId, dir)
		case "role":
			if a.Message == nil || b.Message == nil {
				return false
			}
			return export.compareWithDir(a.Message.Role, b.Message.Role, dir)
		default:
			return false
		}
	})
	return list
}

func (export *Export) sortMetrics(field string, dir string, list []*model.EventMetric) []*model.EventMetric {
	sort.Slice(list, func(i, j int) bool {
		a := list[i]
		b := list[j]
		if a == nil || b == nil {
			return false
		}
		switch strings.ToLower(field) {
		case "key0":
			return export.compareWithDir(a.Keys[0], b.Keys[0], dir)
		case "key1":
			return export.compareWithDir(a.Keys[1], b.Keys[1], dir)
		case "key2":
			return export.compareWithDir(a.Keys[2], b.Keys[2], dir)
		case "key3":
			return export.compareWithDir(a.Keys[3], b.Keys[3], dir)
		case "key4":
			return export.compareWithDir(a.Keys[4], b.Keys[4], dir)
		case "key5":
			return export.compareWithDir(a.Keys[5], b.Keys[5], dir)
		case "key6":
			return export.compareWithDir(a.Keys[6], b.Keys[6], dir)
		case "key7":
			return export.compareWithDir(a.Keys[7], b.Keys[7], dir)
		case "key8":
			return export.compareWithDir(a.Keys[8], b.Keys[8], dir)
		case "key9":
			return export.compareWithDir(a.Keys[9], b.Keys[9], dir)
		case "value", "count", "size":
			return export.compareWithDir(a.Value, b.Value, dir)
		default:
			return false
		}
	})
	return list
}

func (export *Export) compareWithDir(a interface{}, b interface{}, dir string) bool {
	result := export.compare(a, b)
	if dir == "asc" {
		return result
	}
	return !result
}

func (export *Export) compare(a interface{}, b interface{}) bool {
	if a == nil || b == nil {
		return false // Handle nil values gracefully
	}
	aType := reflect.TypeOf(a)
	bType := reflect.TypeOf(b)
	if aType != bType {
		return false // Handle type mismatch gracefully
	}
	switch a.(type) {
	case int:
		return a.(int) < b.(int)
	case int64:
		return a.(int64) < b.(int64)
	case float32:
		return a.(float32) < b.(float32)
	case float64:
		return a.(float64) < b.(float64)
	case time.Time:
		return a.(time.Time).Before(b.(time.Time))
	default:
		aStr := fmt.Sprintf("%v", a)
		bStr := fmt.Sprintf("%v", b)
		return aStr < bStr
	}
}
