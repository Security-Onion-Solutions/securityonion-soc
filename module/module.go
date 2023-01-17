// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2023 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package module

type ModuleConfig map[string]interface{}

type ModuleConfigMap map[string]ModuleConfig

type Module interface {
  PrerequisiteModules() []string
  Init(config ModuleConfig) error
  Start() error
  Stop() error
  IsRunning() bool
}
