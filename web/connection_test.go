// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2023 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package web

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestIsAuthorized(tester *testing.T) {
	conn := NewConnection(nil, "")
	assert.True(tester, conn.IsAuthorized("test"))
}

func TestUpdatePingTime(tester *testing.T) {
	conn := NewConnection(nil, "")
	oldPingTime := conn.lastPingTime
	time.Sleep(3 * time.Millisecond)
	conn.UpdatePingTime()
	newPingTime := conn.lastPingTime

	assert.True(tester, newPingTime.Sub(oldPingTime).Milliseconds() >= 3, "expected 3s increase in lastPingTime")
}
