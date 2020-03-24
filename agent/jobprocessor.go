// Copyright 2019 Jason Ertel (jertel). All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package agent

import (
  "io"
  "time"
  "github.com/sensoroni/sensoroni/model"
)

type JobProcessor interface {
  ProcessJob(*model.Job, io.ReadCloser) (io.ReadCloser, error)
  GetDataEpoch() time.Time
}