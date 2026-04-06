// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package fileanalyze

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type dedupEntry struct {
	hash string
	seen time.Time
}

type Dedup struct {
	mu         sync.Mutex
	cache      map[string]time.Time
	order      []dedupEntry
	maxEntries int
	ttl        time.Duration
	historyDir string
}

func NewDedup(maxEntries int, ttlSeconds int, historyDir string) *Dedup {
	return &Dedup{
		cache:      make(map[string]time.Time),
		maxEntries: maxEntries,
		ttl:        time.Duration(ttlSeconds) * time.Second,
		historyDir: historyDir,
	}
}

func (d *Dedup) IsDuplicate(filePath string) (bool, string, error) {
	hash, err := hashFile(filePath)
	if err != nil {
		return false, "", err
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// Check in-memory cache
	if seen, ok := d.cache[hash]; ok {
		if time.Since(seen) < d.ttl {
			return true, hash, nil
		}
		delete(d.cache, hash)
	}

	// Check on-disk history
	if d.historyDir != "" {
		histPath := filepath.Join(d.historyDir, hash)
		if _, err := os.Stat(histPath); err == nil {
			// Exists on disk, add back to memory cache
			d.cache[hash] = time.Now()
			return true, hash, nil
		}
	}

	return false, hash, nil
}

func (d *Dedup) MarkSeen(hash string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	d.cache[hash] = now
	d.order = append(d.order, dedupEntry{hash: hash, seen: now})

	// Evict oldest if over capacity
	for len(d.cache) > d.maxEntries && len(d.order) > 0 {
		oldest := d.order[0]
		d.order = d.order[1:]
		if t, ok := d.cache[oldest.hash]; ok && t.Equal(oldest.seen) {
			delete(d.cache, oldest.hash)
		}
	}

	// Write to on-disk history
	if d.historyDir != "" {
		histPath := filepath.Join(d.historyDir, hash)
		f, err := os.Create(histPath)
		if err != nil {
			return err
		}
		f.Close()
	}

	return nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
