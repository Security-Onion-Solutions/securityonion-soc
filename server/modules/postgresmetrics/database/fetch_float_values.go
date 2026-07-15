// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package database

import (
	"context"
	"fmt"
	"time"

	"github.com/apex/log"
)

func (s *Store) FetchFloatValues(ctx context.Context, table, field, tagField, tagVal string, startTime time.Time, multiplier ...float64) map[string]float64 {
	res := make(map[string]float64)
	mult := 1.0
	if len(multiplier) > 0 {
		mult = multiplier[0]
	}

	q := fmt.Sprintf(`
		SELECT DISTINCT ON (tag.tags->>'host') tag.tags->>'host', (m.fields->>'%s')::double precision 
		FROM telegraf.%s m
		JOIN telegraf.%s_tag tag ON m.tag_id = tag.tag_id`,
		field, table, table,
	)

	var args []interface{}
	if tagField != "" && tagVal != "" {
		q = fmt.Sprintf("%s WHERE tag.tags->>'%s' = $1 AND m.time >= $2 AND m.fields->>'%s' IS NOT NULL", q, tagField, field)
		args = append(args, tagVal, startTime)
	} else {
		q = fmt.Sprintf("%s WHERE m.time >= $1 AND m.fields->>'%s' IS NOT NULL", q, field)
		args = append(args, startTime)
	}

	q = fmt.Sprintf("%s ORDER BY tag.tags->>'host', m.time DESC", q)

	rows, err := s.db.Query(ctx, q, args...)
	if err != nil {
		s.handleQueryError(err, "FetchFloatValues")
		return res
	}
	defer rows.Close()

	for rows.Next() {
		var host string
		var val float64
		if err := rows.Scan(&host, &val); err == nil {
			res[host] = val * mult
		} else {
			log.Warnf("Postgres metrics: FetchFloatValues scan failed: %v", err)
		}
	}
	log.Debugf("Postgres metrics: FetchFloatValues query returned %d results", len(res))
	return res
}
