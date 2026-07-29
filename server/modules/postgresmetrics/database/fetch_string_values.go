// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file['s] license.

package database

import (
	"context"
	"fmt"
	"time"

	"github.com/apex/log"
)

func (s *Store) FetchStringValues(ctx context.Context, table, field, tagField, tagVal string, startTime time.Time, valueField ...string) map[string]string {
	res := make(map[string]string)
	valFld := field
	if len(valueField) > 0 && valueField[0] != "" {
		valFld = valueField[0]
	}

	q := fmt.Sprintf(`
		SELECT DISTINCT ON (tag.tags->>'host') tag.tags->>'host', m.fields->>'%s' 
		FROM telegraf.%s m 
		JOIN telegraf.%s_tag tag ON m.tag_id = tag.tag_id 
		WHERE m.time >= $1 AND m.fields->>'%s' IS NOT NULL AND m.fields->>'%s' IS NOT NULL`, valFld, table, table, field, valFld)

	var args []interface{}
	args = append(args, startTime)

	if tagField != "" && tagVal != "" {
		q += fmt.Sprintf(" AND tag.tags->>'%s' = $2", tagField)
		args = append(args, tagVal)
	}
	q += " ORDER BY tag.tags->>'host', m.time DESC"

	rows, err := s.db.Query(ctx, q, args...)
	if err != nil {
		s.handleQueryError(err, "FetchStringValues")
		return res
	}
	defer rows.Close()

	for rows.Next() {
		var host, val string
		if err := rows.Scan(&host, &val); err == nil {
			res[host] = val
		} else {
			log.Warnf("Postgres metrics: FetchStringValues scan failed: %v", err)
		}
	}
	log.Debugf("Postgres metrics: FetchStringValues query returned %d results", len(res))
	return res
}
