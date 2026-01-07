// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package export

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
)

func (export *Export) getTabularData(job *model.Job) ([][]string, error) {
	if query, ok := job.Filter.Parameters["query"].(string); ok {
		var eventLimit, metricLimit int
		if _, ok := job.Filter.Parameters["group"]; ok {
			metricLimit = export.getMetricLimit(job)
			eventLimit = 0
		} else {
			metricLimit = 0
			eventLimit = export.getEventLimit(job)
		}

		results := &model.EventSearchResults{}
		_, err := export.queryEventData(query, job.Filter, metricLimit, eventLimit, results)
		if err != nil {
			log.WithFields(log.Fields{
				"jobId":        job.Id,
				"tabularQuery": query,
			}).WithError(err).Error("failed to get tabular data")

			return nil, err
		}

		var records [][]string
		if metric, ok := job.Filter.Parameters["group"]; ok {
			metricName := metric.(string)
			if metrics, ok := results.Metrics[metricName]; ok {
				var headers []string
				// Add header row if this is the first record
				fields := strings.Split(metricName, "|")[1:]
				headers = append(headers, "count")
				headers = append(headers, fields...)
				records = append(records, headers)

				for _, metric := range metrics {
					var record []string
					record = append(record, export.convertToString(metric.Value))
					for _, key := range metric.Keys {
						record = append(record, export.convertToString(key))
					}
					records = append(records, record)
				}
			} else {
				log.WithFields(log.Fields{
					"jobId":        job.Id,
					"metricName":   metricName,
					"tabularQuery": query,
				}).Warn("metric not found in results")
				return nil, errors.New("metric not found in results")
			}
		} else {
			// Two-pass approach to collect headers and records
			// First pass: Collect headers from all events
			headerMap := make(map[string]bool)
			for _, event := range results.Events {
				for field := range event.Payload {
					headerMap[field] = true
				}
			}

			// Convert headerMap keys to a sorted slice
			var headers []string
			for field := range headerMap {
				headers = append(headers, field)
			}
			sort.Strings(headers)

			// Export event metadata field names at the end
			headers = append(headers, "soc_id")
			headers = append(headers, "soc_score")
			headers = append(headers, "soc_type")
			headers = append(headers, "soc_timestamp")
			headers = append(headers, "soc_source")

			records = append(records, headers)

			// Second pass: Collect values for each event using the headers
			for _, event := range results.Events {
				var record []string
				// Collect values for the current event using the header fields
				for _, header := range headers {
					value, exists := event.Payload[header]
					if !exists {
						switch header {
						case "soc_id":
							value = event.Id
						case "soc_score":
							value = event.Score
						case "soc_type":
							value = event.Type
						case "soc_timestamp":
							value = event.Timestamp
						case "soc_source":
							value = event.Source
						default:
							value = ""
						}
					}
					// Convert value to string and append to the record
					record = append(record, export.convertToString(value))
				}
				records = append(records, record)
			}
		}
		return records, nil
	} else {
		log.WithFields(log.Fields{
			"jobId": job.Id,
		}).Error("query parameter is missing or empty")
		return nil, errors.New("query parameter is missing or empty")
	}
}

func (export *Export) convertToString(value interface{}) string {
	if value == nil {
		return ""
	}
	switch v := value.(type) {
	case int8, uint8, int16, uint16, int, uint, int32, uint32, int64, uint64:
		return fmt.Sprintf("%d", v)
	case float32, float64:
		if v == math.Floor(v.(float64)) {
			return fmt.Sprintf("%.0f", v)
		}
		return fmt.Sprintf("%f", v)
	case bool:
		if v {
			return "true"
		}
		return "false"
	case time.Time:
		return v.Format("2006-01-02 15:04:05")
	default:
		return fmt.Sprintf("%v", v)
	}
}

func (export *Export) convertToCsv(records [][]string, csvSeparator string) (io.Reader, int, error) {
	var err error
	buffer := bytes.NewBufferString("")
	writer := csv.NewWriter(buffer)
	writer.Comma = []rune(csvSeparator)[0]
	defer writer.Flush()

	// Write all records at once
	err = writer.WriteAll(records)

	size := buffer.Len()

	return buffer, size, err
}
