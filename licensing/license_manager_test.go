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
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const EXPIRED_KEY = ` H4sIAIvZnGMAA22QR4+bUBSF9/kVFlvPBExz2ZlqijHVNo6yeMaPYsOjPWMgyn8PMyNFihTpLm75zjnS/UXAOIYRzjpIbAiaohfv1Ef5FLX5rAvxRsC+yhqAsxJ9MfR/GASKDwcftnhmZhFELZy9z6yDP1MO7izw5JlmzWz3IAWirx2sSZHdJj4GD/hOUYtpzr9UHy7KtP3rYsBhusYQ4GcDW2Lz4+cb8WxhM7WLKbe8wa+uLaOgySd1inHVbkiyLQv4SmEDv2eoA/mU90bcAAb/UgCVeIK+VzmI4ES0WYI+oyYm8VBxAEZUFbKlp2ugz6t9n15kiX0uligc+es1jf3A7HldUAoctnhtxZ6f7R3+Rc5tOdqqcM5J/F0UyZJh4raOdcNTa6EEyoq+CXR0PloieilIUFlTgwa748r0chJZj2TdmAq3owZi3iFFk4vzx9mUGV41U1N3yLA/GEnCN+tdLa3uAR1zwn6MEh+EmDxefX9VulSjqi6F08hfcQLfYGNXnWxMFpwkKY3h6bJp8bs2z/zRfvCZEu7z3VDh8HRzoOMPa/51S8ho6LrBw7KZgu3qkq7KVGeHu+1Q9LZXkzJDJwaLnnwKpJAbnfkQstcyAlq0ho++q5YLDw11nES0xj+3NmfgvLhYC7rXKFGO927oPHg7oql6MNvDqxMWYxPuBkg/K+Uum/bxnGT90mwjrvZD4+yJmly1Llo+rsGZdZugo307jKf/FbdR950Vr1BHnRrlZMwsACQml/XKq8J5iV5HxgF7sub6Xueyvk7Gfo2Km1AuVZYsWNOv0FEtB4H1WJW/ayfh1S0ZZiB+f/sDb9bxLiEDAAA= 	`

func teardown() {
	if manager != nil {
		manager.running = false
	}
	os.Remove(pillarFilename)
}

func setup() func() {
	pillarFilename = "/tmp/soc_test_pillar_monitor.sls"
	runMode = false
	return teardown
}

func TestInit_Missing(tester *testing.T) {
	defer setup()()

	// None
	Init("")
	assert.Equal(tester, LICENSE_STATUS_UNPROVISIONED, GetStatus())

	// Corrupt
	Init("{}")
	assert.Equal(tester, LICENSE_STATUS_INVALID, GetStatus())

	// Compromised
	Init(strings.Replace(EXPIRED_KEY, "MAA22QR4", "foobar", 1))
	assert.Equal(tester, LICENSE_STATUS_INVALID, GetStatus())

	// Expired
	Init(EXPIRED_KEY)
	assert.Equal(tester, LICENSE_STATUS_EXPIRED, GetStatus())
}

func TestExpirationMonitor(tester *testing.T) {
	defer setup()()

	Init("")
	assert.Equal(tester, LICENSE_STATUS_UNPROVISIONED, GetStatus())
	manager.licenseKey.Expiration = time.Now().Add(time.Second * 1)
	startExpirationMonitor()
	assert.Equal(tester, LICENSE_STATUS_EXPIRED, GetStatus())
}

func TestEffectiveMonitor_Unprovisioned(tester *testing.T) {
	defer setup()()

	Init("")
	assert.Equal(tester, LICENSE_STATUS_UNPROVISIONED, GetStatus())
	manager.licenseKey.Effective = time.Now().Add(time.Second * 1)
	startEffectiveMonitor()
	assert.Equal(tester, LICENSE_STATUS_UNPROVISIONED, GetStatus())
}

func TestEffectiveMonitor_Pending(tester *testing.T) {
	defer setup()()

	Init("")
	manager.status = LICENSE_STATUS_PENDING
	manager.licenseKey.Effective = time.Now().Add(time.Second * 1)
	startEffectiveMonitor()
	assert.Equal(tester, LICENSE_STATUS_ACTIVE, GetStatus())
}

func TestEffectiveMonitor_Exceeded(tester *testing.T) {
	defer setup()()

	Init("")
	manager.status = LICENSE_STATUS_PENDING
	manager.limits["foo"] = true
	manager.licenseKey.Effective = time.Now().Add(time.Second * 1)
	startEffectiveMonitor()
	assert.Equal(tester, LICENSE_STATUS_EXCEEDED, GetStatus())
}

func TestIsEnabled(tester *testing.T) {
	defer setup()()

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
	defer setup()()

	Init("")
	assert.Len(tester, ListAvailableFeatures(), 0)

	Init(EXPIRED_KEY)
	manager.status = LICENSE_STATUS_ACTIVE
	assert.Len(tester, ListAvailableFeatures(), 3)
	assert.Equal(tester, ListAvailableFeatures()[0], FEAT_FIPS)
	assert.Equal(tester, ListAvailableFeatures()[1], FEAT_STIG)
	assert.Equal(tester, ListAvailableFeatures()[2], FEAT_TIMETRACKING)
}

func TestListEnabledFeatures(tester *testing.T) {
	defer setup()()

	Init("")
	assert.Len(tester, ListEnabledFeatures(), 3)

	Init(EXPIRED_KEY)
	assert.Len(tester, ListEnabledFeatures(), 3)
	assert.Equal(tester, ListEnabledFeatures()[0], FEAT_FIPS)
	assert.Equal(tester, ListEnabledFeatures()[1], FEAT_STIG)
	assert.Equal(tester, ListEnabledFeatures()[2], FEAT_TIMETRACKING)

	Init(EXPIRED_KEY)
	manager.licenseKey.Features = append(manager.licenseKey.Features, "foo")
	manager.licenseKey.Features = append(manager.licenseKey.Features, "bar")
	assert.Len(tester, ListEnabledFeatures(), 2)
	assert.Equal(tester, ListEnabledFeatures()[0], "foo")
	assert.Equal(tester, ListEnabledFeatures()[1], "bar")
}

func TestGetLicenseKey(tester *testing.T) {
	defer setup()()

	Init(EXPIRED_KEY)
	key := GetLicenseKey()
	assert.Equal(tester, key.Users, 1)
	assert.Equal(tester, key.Nodes, 1)
	assert.Equal(tester, key.SocUrl, "https://somewhere.invalid")
	assert.Equal(tester, key.DataUrl, "https://another.place")
	assert.Len(tester, key.Features, 3)

	// Modify the returned object and make sure it doesn't affect the orig object
	key.Users = 100
	key.Features = append(key.Features, "foo")
	assert.Equal(tester, GetLicenseKey().Users, 1)
	assert.Len(tester, key.Features, 4)
	assert.Len(tester, GetLicenseKey().Features, 3)
}

func TestGetStatus(tester *testing.T) {
	defer setup()()

	Init("")
	assert.Equal(tester, LICENSE_STATUS_UNPROVISIONED, GetStatus())

	Init(EXPIRED_KEY)
	assert.Equal(tester, LICENSE_STATUS_EXPIRED, GetStatus())
}

func TestGetId(tester *testing.T) {
	defer setup()()

	Init("")
	assert.Equal(tester, "", GetId())

	Init(EXPIRED_KEY)
	assert.Equal(tester, "fake-001", GetId())
}

func TestGetLicensee(tester *testing.T) {
	defer setup()()

	Init("")
	assert.Equal(tester, "", GetLicensee())

	Init(EXPIRED_KEY)
	assert.Equal(tester, "Fake License Key", GetLicensee())
}

func TestGetExpiration(tester *testing.T) {
	defer setup()()

	Init("")
	assert.Equal(tester, time.Time{}, GetExpiration())

	Init(EXPIRED_KEY)
	exp, _ := time.Parse(time.RFC3339, "2022-01-01T00:00:00Z")
	assert.Equal(tester, exp, GetExpiration())
}

func TestGetName(tester *testing.T) {
	defer setup()()

	Init("")
	assert.Equal(tester, "", GetName())

	Init(EXPIRED_KEY)
	assert.Equal(tester, "Test License - NOT FOR USE IN PRODUCTION", GetName())
}

func TestValidateUserCount(tester *testing.T) {
	defer setup()()

	Init("")
	manager.licenseKey.Users = 2
	assert.True(tester, ValidateUserCount(0))
	assert.True(tester, ValidateUserCount(1))
	assert.True(tester, ValidateUserCount(2))
	assert.False(tester, ValidateUserCount(3))
}

func TestValidateNodeCount(tester *testing.T) {
	defer setup()()

	Init("")
	manager.licenseKey.Nodes = 2
	assert.True(tester, ValidateNodeCount(0))
	assert.True(tester, ValidateNodeCount(1))
	assert.True(tester, ValidateNodeCount(2))
	assert.False(tester, ValidateNodeCount(3))
}

func TestValidateSocUrl(tester *testing.T) {
	defer setup()()

	Init("")
	manager.licenseKey.SocUrl = "foo"
	assert.True(tester, ValidateSocUrl("Foo"))
	assert.True(tester, ValidateSocUrl("foo"))
	assert.False(tester, ValidateSocUrl(""))
	assert.False(tester, ValidateSocUrl("bar"))
}

func TestValidateDataUrl(tester *testing.T) {
	defer setup()()

	Init("")
	manager.licenseKey.DataUrl = "foo"
	assert.True(tester, ValidateDataUrl("Foo"))
	assert.True(tester, ValidateDataUrl("foo"))
	assert.False(tester, ValidateDataUrl(""))
	assert.False(tester, ValidateDataUrl("bar"))
}

func TestPillarMonitor(tester *testing.T) {
	defer setup()()

	Test("stig", 0, 0, "", "")

	startPillarMonitor()
	assert.Equal(tester, manager.status, LICENSE_STATUS_ACTIVE)
	contents, _ := os.ReadFile(pillarFilename)

	expected := `
# Copyright Jason Ertel (github.com/jertel).
# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with 
# the Elastic License 2.0.

# Note: Per the Elastic License 2.0, the second limitation states:
#
#   "You may not move, change, disable, or circumvent the license key functionality
#    in the software, and you may not remove or obscure any functionality in the
#    software that is protected by the license key."

# This file is generated by Security Onion and contains a list of license-enabled features. 
features:
- stig
`

	assert.Equal(tester, expected, string(contents))
}

func TestPillarMonitor_Fail(tester *testing.T) {
	defer setup()()

	pillarFilename = "/tmp/does/not/exist"

	Init("")

	assert.Equal(tester, manager.status, LICENSE_STATUS_UNPROVISIONED)
	startPillarMonitor()
	assert.Equal(tester, manager.status, LICENSE_STATUS_INVALID)
}
