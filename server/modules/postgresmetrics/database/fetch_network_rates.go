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

// Telegraf writes node_config every 5 minutes, so the lookback must exceed that interval. Both
// the grid interface lookup and the drops chart apply it, since their own windows can be shorter.
const nodeConfigLookback = "20 minutes"

// nodeInterfacesCTE resolves each host's latest non-empty manint and monint separately, so a
// host that reports no monitor interface still resolves its management interface. Its one
// verb is the lower time bound on node_config rows.
const nodeInterfacesCTE = `node_interfaces AS (
			SELECT
				COALESCE(man.host, mon.host) AS host,
				COALESCE(man.manint, '') AS manint,
				COALESCE(mon.monint, '') AS monint
			FROM (
				SELECT DISTINCT ON (tag.tags->>'host') tag.tags->>'host' AS host, m.fields->>'manint' AS manint
				FROM telegraf.node_config m
				JOIN telegraf.node_config_tag tag ON m.tag_id = tag.tag_id
				WHERE m.time >= %[1]s AND m.fields->>'manint' IS NOT NULL AND m.fields->>'manint' <> ''
				ORDER BY tag.tags->>'host', m.time DESC
			) man
			FULL OUTER JOIN (
				SELECT DISTINCT ON (tag.tags->>'host') tag.tags->>'host' AS host, m.fields->>'monint' AS monint
				FROM telegraf.node_config m
				JOIN telegraf.node_config_tag tag ON m.tag_id = tag.tag_id
				WHERE m.time >= %[1]s AND m.fields->>'monint' IS NOT NULL AND m.fields->>'monint' <> ''
				ORDER BY tag.tags->>'host', m.time DESC
			) mon ON man.host = mon.host
		)`

type NetworkRates struct {
	TrafficMonInMbs      map[string]float64
	TrafficMonInDropsPps map[string]float64
	TrafficManInMbs      map[string]float64
	TrafficManOutMbs     map[string]float64
}

func (s *Store) FetchNetworkRates(ctx context.Context, startTime time.Time) (*NetworkRates, error) {
	rates := &NetworkRates{
		TrafficMonInMbs:      make(map[string]float64),
		TrafficMonInDropsPps: make(map[string]float64),
		TrafficManInMbs:      make(map[string]float64),
		TrafficManOutMbs:     make(map[string]float64),
	}

	manint := make(map[string]string)
	monint := make(map[string]string)

	qConf := "WITH " + fmt.Sprintf(nodeInterfacesCTE, fmt.Sprintf("($1::timestamptz AT TIME ZONE 'UTC') - INTERVAL '%s'", nodeConfigLookback)) + `
		SELECT host, manint, monint FROM node_interfaces`

	confRows, err := s.db.Query(ctx, qConf, startTime)
	if err != nil {
		s.handleQueryError(err, "FetchNetworkRates config")
		if !s.isMissingRelationError(err) {
			return nil, err
		}
	} else {
		for confRows.Next() {
			var host, man, mon string
			if err := confRows.Scan(&host, &man, &mon); err != nil {
				log.WithError(err).Warn("Postgres metrics: skipping unreadable node interface row")
				continue
			}
			manint[host] = man
			monint[host] = mon
		}
		confErr := confRows.Err()
		confRows.Close()
		if confErr != nil {
			s.handleQueryError(confErr, "FetchNetworkRates config")
			return nil, confErr
		}
	}

	qRates := `
		WITH traffic_diff AS (
			SELECT 
				tag.tags->>'host' as host,
				tag.tags->>'interface' as interface,
				m.time,
				(m.fields->>'bytes_recv')::bigint as bytes_recv,
				(m.fields->>'bytes_sent')::bigint as bytes_sent,
				(m.fields->>'drop_in')::bigint as drop_in,
				LAG((m.fields->>'bytes_recv')::bigint) OVER (PARTITION BY tag.tags->>'host', tag.tags->>'interface' ORDER BY m.time) as prev_recv,
				LAG((m.fields->>'bytes_sent')::bigint) OVER (PARTITION BY tag.tags->>'host', tag.tags->>'interface' ORDER BY m.time) as prev_sent,
				LAG((m.fields->>'drop_in')::bigint) OVER (PARTITION BY tag.tags->>'host', tag.tags->>'interface' ORDER BY m.time) as prev_drop,
				LAG(m.time) OVER (PARTITION BY tag.tags->>'host', tag.tags->>'interface' ORDER BY m.time) as prev_time
			FROM telegraf.net m
			JOIN telegraf.net_tag tag ON m.tag_id = tag.tag_id
			WHERE m.time >= $1 AND m.fields->>'bytes_recv' IS NOT NULL AND m.fields->>'bytes_sent' IS NOT NULL AND m.fields->>'drop_in' IS NOT NULL
		),
		rates_cte AS (
			SELECT 
				host,
				interface,
				time,
				CASE 
					WHEN prev_time IS NOT NULL AND time > prev_time AND bytes_recv >= prev_recv 
					THEN (bytes_recv - prev_recv)::float / EXTRACT(EPOCH FROM (time - prev_time))
					ELSE 0.0
				END as recv_rate,
				CASE 
					WHEN prev_time IS NOT NULL AND time > prev_time AND bytes_sent >= prev_sent 
					THEN (bytes_sent - prev_sent)::float / EXTRACT(EPOCH FROM (time - prev_time))
					ELSE 0.0
				END as sent_rate,
				CASE 
					WHEN prev_time IS NOT NULL AND time > prev_time AND drop_in >= prev_drop 
					THEN (drop_in - prev_drop)::float / EXTRACT(EPOCH FROM (time - prev_time))
					ELSE 0.0
				END as drop_rate
			FROM traffic_diff
		)
		SELECT DISTINCT ON (host, interface)
			host,
			interface,
			recv_rate,
			sent_rate,
			drop_rate
		FROM rates_cte
		ORDER BY host, interface, time DESC`

	bytesToMb := 8.0 / (1000.0 * 1000.0)
	netStartTime := startTime.Add(-2 * time.Minute)

	rows, err := s.db.Query(ctx, qRates, netStartTime)
	if err != nil {
		s.handleQueryError(err, "FetchNetworkRates rates")
		return rates, err
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var host, iface string
		var recv, sent, drop float64
		if err := rows.Scan(&host, &iface, &recv, &sent, &drop); err == nil {
			count++
			manIface := manint[host]
			if manIface == "" {
				manIface = "eth0"
			}
			monIface := monint[host]

			if iface == manIface {
				rates.TrafficManInMbs[host] = recv * bytesToMb
				rates.TrafficManOutMbs[host] = sent * bytesToMb
			}
			if monIface == "" {
				rates.TrafficMonInMbs[host] = 0
				rates.TrafficMonInDropsPps[host] = 0
			} else if iface == monIface {
				rates.TrafficMonInMbs[host] = recv * bytesToMb
				rates.TrafficMonInDropsPps[host] = drop
			}
		}
	}
	log.Debugf("Postgres metrics: FetchNetworkRates rates query returned %d results", count)
	return rates, nil
}
