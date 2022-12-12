// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
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
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
	"time"
)

const EXPIRED_KEY = `
{
  "effective": "2021-01-01T00:00:00Z",
  "expiration": "2022-01-01T00:00:00Z",
  "name": "Test License - NOT FOR USE IN PRODUCTION",
  "id": "fake-001",
  "licensee": "Fake License Key",
  "features": [],
  "users": 1,
  "nodes": 1,
  "socUrl": "https://somewhere.invalid",
  "dataUrl": "https://another.place",
  "signature": "gSnmOaKcpmENJh9aJ+pMxhZED4u17nYz6bbhfTULx6JBFmtYst9NfSTiMQ6w/+PEcAGe+5D6jCC/o33fsqfJKSGqBoaF82dB2cXVNCnwFnBG4LIeK4H5ohZWC4S/4Rf0YAzIaf6Q/CL5flkXLE36GLhLJQ/YxOKgg6r9HqD8jU2f5BMzcgTaYt/VbTT8oR0rGGR0thcT85B6rtKHpWPt/m5DDFrKSJELN6HsliTzPk6iFYMlHyptYWdQeQTy96wdg/cyvvyStELhaA8Zh8ohJ4yjPQ02AxGgoinW3tCSEWUDY5zQ+yY4bocaIc9ekxvp71Snyqfgc2I6uAP5KtlmZN12xI0CEfMRYQk6Pc20qyLsOwvB1zrYHye2upFjELPVXgix7Lsc5qTYKXSCIEpsRn7kbUX4RrUv2TPYfCnwmdzJTQ86F0VJ0zEgziNaaD3lEJpSpY+onwV3QaM/q5xxJ5ixqgzx9nmdBo7G4/m4LTpnVGoyB4S4G6jIWBwv733y"
}
`

func TestInit_Missing(tester *testing.T) {
	// None
	Init("")
	assert.Equal(tester, LICENSE_STATUS_UNPROVISIONED, GetStatus())

	// Corrupt
	Init("{}")
	assert.Equal(tester, LICENSE_STATUS_INVALID, GetStatus())

	// Compromised
	Init(strings.Replace(EXPIRED_KEY, "2022", "2122", 1))
	assert.Equal(tester, LICENSE_STATUS_INVALID, GetStatus())

	// Expired
	Init(EXPIRED_KEY)
	assert.Equal(tester, LICENSE_STATUS_EXPIRED, GetStatus())
}

func TestExpirationMonitor(tester *testing.T) {
	Init("")
	assert.Equal(tester, LICENSE_STATUS_UNPROVISIONED, GetStatus())
	manager.licenseKey.Expiration = time.Now().Add(time.Second * 1)
	startExpirationMonitor()
	assert.Equal(tester, LICENSE_STATUS_EXPIRED, GetStatus())
}

func TestEffectiveMonitor_Unprovisioned(tester *testing.T) {
	Init("")
	assert.Equal(tester, LICENSE_STATUS_UNPROVISIONED, GetStatus())
	manager.licenseKey.Effective = time.Now().Add(time.Second * 1)
	startEffectiveMonitor()
	assert.Equal(tester, LICENSE_STATUS_UNPROVISIONED, GetStatus())
}

func TestEffectiveMonitor_Pending(tester *testing.T) {
	Init("")
	manager.status = LICENSE_STATUS_PENDING
	manager.licenseKey.Effective = time.Now().Add(time.Second * 1)
	startEffectiveMonitor()
	assert.Equal(tester, LICENSE_STATUS_ACTIVE, GetStatus())
}

func TestEffectiveMonitor_Exceeded(tester *testing.T) {
	Init("")
	manager.status = LICENSE_STATUS_PENDING
	manager.limits["foo"] = true
	manager.licenseKey.Effective = time.Now().Add(time.Second * 1)
	startEffectiveMonitor()
	assert.Equal(tester, LICENSE_STATUS_EXCEEDED, GetStatus())
}

func TestIsEnabled(tester *testing.T) {
	Init("")
	assert.False(tester, IsEnabled("something"))

	manager.status = LICENSE_STATUS_ACTIVE
	assert.True(tester, IsEnabled("something")) // No explicit features defined, assume all enabled

	manager.status = LICENSE_STATUS_ACTIVE
	manager.licenseKey.Features = append([]string{}, "foo")
	assert.False(tester, IsEnabled("something")) // Not an explicitly enabled feature
	assert.True(tester, IsEnabled("FoO"))        // This is an explicitly enabled feature
}

func TestListAvailableFeatures(tester *testing.T) {
	Init("")
	assert.Len(tester, ListAvailableFeatures(), 0)

	Init(EXPIRED_KEY)
	manager.status = LICENSE_STATUS_ACTIVE
	assert.Len(tester, ListAvailableFeatures(), 1)
	assert.Equal(tester, ListAvailableFeatures()[0], FEAT_TIMETRACKING)
}

func TestListEnabledFeatures(tester *testing.T) {
	Init("")
	assert.Len(tester, ListEnabledFeatures(), 1)

	Init(EXPIRED_KEY)
	assert.Len(tester, ListEnabledFeatures(), 1)
	assert.Equal(tester, ListEnabledFeatures()[0], FEAT_TIMETRACKING)

	Init(EXPIRED_KEY)
	manager.licenseKey.Features = append(manager.licenseKey.Features, "foo")
	manager.licenseKey.Features = append(manager.licenseKey.Features, "bar")
	assert.Len(tester, ListEnabledFeatures(), 2)
	assert.Equal(tester, ListEnabledFeatures()[0], "foo")
	assert.Equal(tester, ListEnabledFeatures()[1], "bar")
}

func TestGetLicenseKey(tester *testing.T) {
	Init(EXPIRED_KEY)
	key := GetLicenseKey()
	assert.Equal(tester, key.Users, 1)
	assert.Equal(tester, key.Nodes, 1)
	assert.Equal(tester, key.SocUrl, "https://somewhere.invalid")
	assert.Equal(tester, key.DataUrl, "https://another.place")
	assert.Len(tester, key.Features, 1)

	// Modify the returned object and make sure it doesn't affect the orig object
	key.Users = 100
	key.Features = append(key.Features, "foo")
	assert.Equal(tester, GetLicenseKey().Users, 1)
	assert.Len(tester, key.Features, 2)
	assert.Len(tester, GetLicenseKey().Features, 1)
}

func TestGetStatus(tester *testing.T) {
	Init("")
	assert.Equal(tester, LICENSE_STATUS_UNPROVISIONED, GetStatus())

	Init(EXPIRED_KEY)
	assert.Equal(tester, LICENSE_STATUS_EXPIRED, GetStatus())
}

func TestGetId(tester *testing.T) {
	Init("")
	assert.Equal(tester, "", GetId())

	Init(EXPIRED_KEY)
	assert.Equal(tester, "fake-001", GetId())
}

func TestGetLicensee(tester *testing.T) {
	Init("")
	assert.Equal(tester, "", GetLicensee())

	Init(EXPIRED_KEY)
	assert.Equal(tester, "Fake License Key", GetLicensee())
}

func TestGetExpiration(tester *testing.T) {
	Init("")
	assert.Equal(tester, time.Time{}, GetExpiration())

	Init(EXPIRED_KEY)
	exp, _ := time.Parse(time.RFC3339, "2022-01-01T00:00:00Z")
	assert.Equal(tester, exp, GetExpiration())
}

func TestGetName(tester *testing.T) {
	Init("")
	assert.Equal(tester, "", GetName())

	Init(EXPIRED_KEY)
	assert.Equal(tester, "Test License - NOT FOR USE IN PRODUCTION", GetName())
}

func TestValidateUserCount(tester *testing.T) {
	Init("")
	manager.licenseKey.Users = 2
	assert.True(tester, ValidateUserCount(0))
	assert.True(tester, ValidateUserCount(1))
	assert.True(tester, ValidateUserCount(2))
	assert.False(tester, ValidateUserCount(3))
}

func TestValidateNodeCount(tester *testing.T) {
	Init("")
	manager.licenseKey.Nodes = 2
	assert.True(tester, ValidateNodeCount(0))
	assert.True(tester, ValidateNodeCount(1))
	assert.True(tester, ValidateNodeCount(2))
	assert.False(tester, ValidateNodeCount(3))
}

func TestValidateSocUrl(tester *testing.T) {
	Init("")
	manager.licenseKey.SocUrl = "foo"
	assert.True(tester, ValidateSocUrl("Foo"))
	assert.True(tester, ValidateSocUrl("foo"))
	assert.False(tester, ValidateSocUrl(""))
	assert.False(tester, ValidateSocUrl("bar"))
}

func TestValidateDataUrl(tester *testing.T) {
	Init("")
	manager.licenseKey.DataUrl = "foo"
	assert.True(tester, ValidateDataUrl("Foo"))
	assert.True(tester, ValidateDataUrl("foo"))
	assert.False(tester, ValidateDataUrl(""))
	assert.False(tester, ValidateDataUrl("bar"))
}