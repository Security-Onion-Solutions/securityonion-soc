// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

// Per the above-referenced Elastic license, the second limitation states:
//
//   "You may not move, change, disable, or circumvent the license key functionality
//    in the software, and you may not remove or obscure any functionality in the
//    software that is protected by the license key."

package licensing

import (
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/json"
)

const LICENSE_STATUS_ACTIVE = "active"
const LICENSE_STATUS_EXCEEDED = "exceeded"
const LICENSE_STATUS_EXPIRED = "expired"
const LICENSE_STATUS_INVALID = "invalid"
const LICENSE_STATUS_PENDING = "pending"
const LICENSE_STATUS_UNPROVISIONED = "unprovisioned"

const FEAT_TIMETRACKING = "timetracking"

const PUBLIC_KEY = `
-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA4w/cDz7rv6QotLWR7mn9
XOiU/9l4e1ewRyqZjICFOyw9Bi3oN09EWhG6pdwK8746Ss4+bsWc5PLigD+bhMRf
iZgks62TCaFa2FeKsDcyE6BIesdwZwgsodIDWdfONkxVAfw8it7oiHwqEvq/oDCg
eLs4Pqjqnv+oj3b5MRgK2vpxq7DOnSkm13SVt+NaiAVVkO40ZVh73xcXLtjHFvaD
wLnDfkEwb+lwh7Nc4ezf2oSv+7jeaGWruf58fvnnAKvcwv2w4TImFzguHk3DPDfi
qoF6ql9Rc+c4Sx3lyvUfTMwNIQWCNh0zBsYceVL126fi1xAUvNDOWfDmB+OXEb9Y
bvTIa+PynCzmy3aLvqu7hUk2lbC5yZNI3pjZM59YmuVxygfWn4YNlR4bRtCzRkcY
oe+Ss7/W8SBvQoZpZgxIogHwZ3fn99pw/78ybuLdW9zokVDIxvKoVZHeaqJBe3zW
rdA93ynlX+ihg6jL0iS4uFEV9YveqajjOyi3DYyUFCjFAgMBAAE=
-----END PUBLIC KEY-----
`

type licenseManager struct {
	status          string
	available       []string
	limits          map[string]bool
	expirationTimer *time.Timer
	effectiveTimer  *time.Timer
	licenseKey      *LicenseKey
}

type LicenseKey struct {
	Effective  time.Time `json:"effective"`
	Expiration time.Time `json:"expiration"`
	Name       string    `json:"name"`
	Id         string    `json:"id"`
	Licensee   string    `json:"licensee"`
	Features   []string  `json:"features"`
	Users      int       `json:"users"`
	Nodes      int       `json:"nodes"`
	SocUrl     string    `json:"socUrl"`
	DataUrl    string    `json:"dataUrl"`
}

type SignedLicenseKey struct {
	*LicenseKey
	Signature string `json:"signature"`
}

var mutex sync.Mutex
var manager *licenseManager

func newLicenseManager() *licenseManager {
	return &licenseManager{
		available: make([]string, 0, 0),
		limits:    make(map[string]bool),
	}
}

func getPublicKey() (*rsa.PublicKey, error) {
	publicKeyPem, _ := pem.Decode([]byte(PUBLIC_KEY))
	anyKey, err := x509.ParsePKIXPublicKey(publicKeyPem.Bytes)
	if err != nil {
		return nil, err
	}
	return anyKey.(*rsa.PublicKey), nil
}

func parseLicense(key string) (*LicenseKey, []byte, []byte, error) {
	decodedKey, decodeErr := base64.StdEncoding.DecodeString(strings.TrimSpace(key))
	if decodeErr != nil {
		return nil, nil, nil, decodeErr
	}

	gr, gerr := gzip.NewReader(bytes.NewReader(decodedKey))
	if gerr != nil {
		return nil, nil, nil, gerr
	}

	keyBytes, readErr := io.ReadAll(gr)
	if readErr != nil {
		return nil, nil, nil, readErr
	}

	originalKey := &SignedLicenseKey{}
	loadOrigErr := json.LoadJson(keyBytes, originalKey)
	if loadOrigErr != nil {
		return nil, nil, nil, loadOrigErr
	}

	hashableKey := originalKey.LicenseKey
	messageBytes, writeErr := json.WriteJson(hashableKey)
	if writeErr != nil {
		return nil, nil, nil, writeErr
	}

	sigBytes, decodeErr := base64.StdEncoding.DecodeString(originalKey.Signature)
	if decodeErr != nil {
		return nil, nil, nil, decodeErr
	}

	return hashableKey, messageBytes, sigBytes, nil
}

func verify(key string) (*LicenseKey, error) {
	pubKey, keyErr := getPublicKey()
	if keyErr != nil {
		return nil, keyErr
	}

	license, msgBytes, sigBytes, parseErr := parseLicense(key)
	if parseErr != nil {
		return nil, parseErr
	}

	hash := sha256.Sum256(msgBytes)
	return license, rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], sigBytes)
}

func Init(key string) {
	available := make([]string, 0, 0)
	available = append(available, FEAT_TIMETRACKING)

	status := LICENSE_STATUS_UNPROVISIONED
	licenseKey := &LicenseKey{}

	if key != "" {
		license, err := verify(key)
		if err != nil {
			log.WithError(err).Error("failed to verify license key")
			status = LICENSE_STATUS_INVALID
		} else {
			if license.Effective.After(time.Now()) {
				log.WithField("effective", license.Effective).Error("license is not yet effective")
				status = LICENSE_STATUS_PENDING
			} else if license.Expiration.Before(time.Now()) {
				log.WithField("expiration", license.Expiration).Error("license is expired")
				status = LICENSE_STATUS_EXPIRED
			} else {
				status = LICENSE_STATUS_ACTIVE
			}
			licenseKey = license
		}
	} else {
		log.Info("license key not provided")
	}

	createManager(status, available, licenseKey)
}

func Test(feat string, users int, nodes int, socUrl string, dataUrl string) {
	available := make([]string, 0, 0)
	available = append(available, feat)
	licenseKey := &LicenseKey{}
	licenseKey.Expiration = time.Now().Add(time.Minute * 1)
	licenseKey.Features = available
	licenseKey.Users = users
	licenseKey.Nodes = nodes
	licenseKey.SocUrl = socUrl
	licenseKey.DataUrl = dataUrl
	createManager(LICENSE_STATUS_ACTIVE, available, licenseKey)
}

func Shutdown() {
	mutex.Lock()
	defer mutex.Unlock()

	stopMonitor()
}

func createManager(status string, available []string, licenseKey *LicenseKey) {
	mutex.Lock()
	defer mutex.Unlock()

	stopMonitor()

	manager = newLicenseManager()
	manager.status = status
	manager.available = available
	manager.licenseKey = licenseKey

	if status == LICENSE_STATUS_ACTIVE || status == LICENSE_STATUS_PENDING {
		go startExpirationMonitor()
		go startEffectiveMonitor()
	}

	log.WithFields(log.Fields{
		"status":     manager.status,
		"available":  manager.available,
		"features":   manager.licenseKey.Features,
		"effective":  manager.licenseKey.Effective,
		"expiration": manager.licenseKey.Expiration,
		"users":      manager.licenseKey.Users,
		"nodes":      manager.licenseKey.Nodes,
		"socUrl":     manager.licenseKey.SocUrl,
		"dataUrl":    manager.licenseKey.DataUrl,
	}).Info("Initialized license manager")
}

func startExpirationMonitor() {
	if manager.licenseKey.Expiration.After(time.Now()) {
		duration := manager.licenseKey.Expiration.Sub(time.Now())
		if manager.expirationTimer != nil {
			log.Error("Expiration timer is already running; aborting thread")
			return
		}
		manager.expirationTimer = time.NewTimer(duration)
		<-manager.expirationTimer.C
		log.WithFields(log.Fields{
			"expiration": manager.licenseKey.Expiration,
			"duration":   duration,
		}).Warn("License has expired")
		manager.status = LICENSE_STATUS_EXPIRED
	}
	manager.expirationTimer = nil
}

func startEffectiveMonitor() {
	if manager.licenseKey.Effective.After(time.Now()) {
		duration := manager.licenseKey.Effective.Sub(time.Now())
		if manager.effectiveTimer != nil {
			log.Error("Effective timer is already running; aborting thread")
			return
		}
		manager.effectiveTimer = time.NewTimer(duration)
		<-manager.effectiveTimer.C

		if manager.status == LICENSE_STATUS_PENDING {
			if len(manager.limits) > 0 {
				log.WithFields(log.Fields{
					"effective": manager.licenseKey.Effective,
					"duration":  duration,
				}).Warn("License has become effective but limits are exceeded")
				manager.status = LICENSE_STATUS_EXCEEDED
			} else {
				log.WithFields(log.Fields{
					"effective": manager.licenseKey.Effective,
					"duration":  duration,
				}).Warn("License has become effective")
				manager.status = LICENSE_STATUS_ACTIVE
			}
		} else {
			log.WithFields(log.Fields{
				"effective": manager.licenseKey.Effective,
				"duration":  duration,
			}).Warn("License has become effective but current status is no longer pending")
		}
	}
	manager.effectiveTimer = nil
}

func stopMonitor() {
	if manager != nil {
		if manager.expirationTimer != nil {
			manager.expirationTimer.Stop()
		}
		if manager.effectiveTimer != nil {
			manager.effectiveTimer.Stop()
		}

		for loops := 0; loops < 30; loops++ {
			if manager.expirationTimer == nil && manager.effectiveTimer == nil {
				log.Info("stopped all license monitors")
				break
			}
			time.Sleep(100)
		}
	}
	manager = nil
}

func IsEnabled(feat string) bool {
	if manager == nil || manager.status != LICENSE_STATUS_ACTIVE {
		return false
	}

	if len(manager.licenseKey.Features) == 0 {
		return true
	}

	for i := 0; i < len(manager.licenseKey.Features); i++ {
		if strings.EqualFold(manager.licenseKey.Features[i], feat) {
			return true
		}
	}
	return false
}

func ListAvailableFeatures() []string {
	available := make([]string, 0, 0)
	if manager == nil || manager.status != LICENSE_STATUS_ACTIVE {
		return available
	}

	available = append(available, manager.available...)

	return available
}

func ListEnabledFeatures() []string {
	enabled := make([]string, 0, 0)
	if manager == nil {
		return enabled
	}

	if len(manager.licenseKey.Features) == 0 {
		enabled = append(enabled, manager.available...)
	} else {
		enabled = append(enabled, manager.licenseKey.Features...)
	}

	return enabled
}

func GetLicenseKey() *LicenseKey {
	if manager == nil {
		return nil
	}
	copy := *manager.licenseKey
	copy.Features = ListEnabledFeatures()
	return &copy
}

func GetStatus() string {
	if manager == nil {
		return ""
	}
	return manager.status
}

func GetId() string {
	if manager == nil {
		return ""
	}
	return manager.licenseKey.Id
}

func GetLicensee() string {
	if manager == nil {
		return ""
	}
	return manager.licenseKey.Licensee
}

func GetExpiration() time.Time {
	if manager == nil {
		return time.Now()
	}
	return manager.licenseKey.Expiration
}

func GetName() string {
	if manager == nil {
		return ""
	}
	return manager.licenseKey.Name
}

func checkExceeded(limit string, ok bool) bool {
	if manager == nil {
		return false
	}

	if !ok {
		_, exists := manager.limits[limit]
		if !exists {
			manager.limits[limit] = true
			log.WithFields(log.Fields{
				"limit": limit,
			}).Error("exceeded license limit")
		}
	} else {
		_, exists := manager.limits[limit]
		if exists {
			delete(manager.limits, limit)
			log.WithFields(log.Fields{
				"limit": limit,
			}).Error("no longer exceeding license limit")
		}
	}

	if len(manager.limits) > 0 {
		if manager.status == LICENSE_STATUS_ACTIVE {
			manager.status = LICENSE_STATUS_EXCEEDED
		}
	} else {
		if manager.status == LICENSE_STATUS_EXCEEDED {
			manager.status = LICENSE_STATUS_ACTIVE
		}
	}

	return ok
}

func ValidateUserCount(count int) bool {
	if manager == nil {
		return true
	}
	ok := manager.licenseKey.Users == 0 || manager.licenseKey.Users >= count
	return checkExceeded("users", ok)
}

func ValidateNodeCount(count int) bool {
	if manager == nil {
		return true
	}
	ok := manager.licenseKey.Nodes == 0 || manager.licenseKey.Nodes >= count
	return checkExceeded("nodes", ok)
}

func ValidateSocUrl(url string) bool {
	if manager == nil {
		return true
	}
	ok := manager.licenseKey.SocUrl == "" || strings.EqualFold(manager.licenseKey.SocUrl, url)
	return checkExceeded("socUrl", ok)
}

func ValidateDataUrl(url string) bool {
	if manager == nil {
		return true
	}
	ok := manager.licenseKey.DataUrl == "" || strings.EqualFold(manager.licenseKey.DataUrl, url)
	return checkExceeded("dataUrl", ok)
}
