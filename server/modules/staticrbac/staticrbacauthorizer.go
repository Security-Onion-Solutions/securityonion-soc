// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package staticrbac

import (
  "bufio"
  "context"
  "crypto/md5"
  "errors"
  "github.com/apex/log"
  "github.com/security-onion-solutions/securityonion-soc/model"
  "github.com/security-onion-solutions/securityonion-soc/web"
  "os"
  "sort"
  "strings"
  "sync"
  "time"
)

type StaticRbacAuthorizer struct {
  roleFiles      []string
  scanIntervalMs int
  roleMap        map[string][]string
  mutex          sync.Mutex
  running        bool
  previousHash   [16]byte
  timer          *time.Timer
}

func NewStaticRbacAuthorizer() *StaticRbacAuthorizer {
  return &StaticRbacAuthorizer{}
}

func (impl *StaticRbacAuthorizer) Init(files []string, scanIntervalMs int) error {
  impl.roleFiles = files

  if scanIntervalMs == 0 {
    return errors.New("scanIntervalMs must be a positive integer")
  }
  impl.scanIntervalMs = scanIntervalMs
  return nil
}

func (impl *StaticRbacAuthorizer) StartScanningFiles() {
  impl.running = true
  go impl.scanLoop()
}

func (impl *StaticRbacAuthorizer) StopScanningFiles() {
  impl.running = false
  impl.timer.Stop()
}

func (impl *StaticRbacAuthorizer) GetAssignments(ctx context.Context) (map[string][]string, error) {
  roleMap := impl.roleMap

  if err := impl.CheckContextOperationAuthorized(ctx, "read", "roles"); err != nil {
    // User is not allowed to access the entire role map, so only show their top-level roles
    roleMap = make(map[string][]string)

    if user, ok := ctx.Value(web.ContextKeyRequestor).(*model.User); ok {
      roles := impl.roleMap[user.Email]
      roleMap[user.Email] = roles
      log.WithFields(log.Fields{
        "email":     user.Email,
        "roles":     roles,
        "requestId": ctx.Value(web.ContextKeyRequestId),
      }).Debug("User does not have access to read all roles; limiting role map to self")
    }
  }

  return roleMap, nil
}

func (impl *StaticRbacAuthorizer) PopulateUserRoles(ctx context.Context, user *model.User) error {
  // Use the returned roles instead of the struct roles so that they are filtered for access permissions
  roleMap, _ := impl.GetAssignments(ctx)

  if roles, ok := roleMap[user.Email]; ok {
    sort.Strings(roles)
    user.Roles = roles
    log.WithFields(log.Fields{
      "email": user.Email,
      "roles": user.Roles,
    }).Debug("Populated roles for user")
  } else {
    log.WithField("email", user.Email).Debug("No roles found")
  }
  return nil
}

func (impl *StaticRbacAuthorizer) UpdateRoleMap(newRoleMap map[string][]string) {
  impl.mutex.Lock()
  defer impl.mutex.Unlock()

  impl.roleMap = newRoleMap
}

func (impl *StaticRbacAuthorizer) AdjustPermissionInRole(roleMap map[string][]string, role string, permission string, operation string) {
  perms := roleMap[role]
  if perms == nil {
    perms = make([]string, 0, 0)
  }
  if operation == "+" {
    perms = append(perms, permission)
  } else if operation == "-" {
    for idx, value := range perms {
      if value == permission {
        perms = append(perms[:idx], perms[idx+1:]...)
        break
      }
    }
  }
  roleMap[role] = perms
}

func (impl *StaticRbacAuthorizer) CheckContextOperationAuthorized(ctx context.Context, operation string, target string) error {
  var err error
  permission := target + "/" + operation

  if user, ok := ctx.Value(web.ContextKeyRequestor).(*model.User); ok {
    impl.mutex.Lock()
    defer impl.mutex.Unlock()

    if user.Email == permission {
      err = errors.New("Unable to check authorization of a subject name that matches the permission name itself")
    } else if !impl.isAuthorized(user.Email, permission) {
      err = model.NewUnauthorized(user.Email, operation, target)
    }
    log.WithFields(log.Fields{
      "userId":       user.Id,
      "username":     user.Email,
      "requestId":    ctx.Value(web.ContextKeyRequestId),
      "permission":   permission,
      "primaryRoles": impl.roleMap[user.Email],
      "authorized":   err == nil,
    }).Debug("Evaluating authorization for requestor")
  } else {
    log.Debug("Authorization user not found in context")
    err = model.NewUnauthorized("", operation, target)
  }
  return err
}

func (impl *StaticRbacAuthorizer) isAuthorized(subject string, requestedPermission string) bool {
  if subject == requestedPermission {
    return true
  }

  if permissions, ok := impl.roleMap[subject]; ok {
    for _, allowedPermission := range permissions {
      if impl.isAuthorized(allowedPermission, requestedPermission) {
        return true
      }
    }
  }

  return false
}

func (impl *StaticRbacAuthorizer) scanLoop() {
  log.WithField("scanIntervalMs", impl.scanIntervalMs).Info("Starting periodic role file scanner")
  for impl.running {
    impl.scanFiles()
    <-impl.timer.C
  }
  log.Info("Stopped scanning role files")
}

func (impl *StaticRbacAuthorizer) scanFiles() {
  log.Debug("Scanning role files for updates")
  newRoleMap := make(map[string][]string)
  hashText := ""
  for lineNum, path := range impl.roleFiles {
    file, err := os.Open(path)
    if err != nil {
      log.WithError(err).WithField("path", path).Error("Unable to open role file")
    } else {
      defer file.Close()

      scanner := bufio.NewScanner(file)
      for scanner.Scan() {
        line := scanner.Text()
        hashText = hashText + line
        impl.parseLine(newRoleMap, line, path, lineNum)
      }
    }
  }

  hash := md5.Sum([]byte(hashText))
  if hash != impl.previousHash {
    log.WithField("roleMap", newRoleMap).Info("Role files have changed; updating roles")
    impl.UpdateRoleMap(newRoleMap)
    impl.previousHash = hash
  }

  impl.timer = time.NewTimer(time.Millisecond * time.Duration(impl.scanIntervalMs))
}

func (impl *StaticRbacAuthorizer) parseLine(roleMap map[string][]string, line string, path string, lineNum int) {
  line = strings.ReplaceAll(line, ",", " ") // Allow comma delimiting
  line = strings.ReplaceAll(line, ";", " ") // Allow semi-colon delimiting
  line = strings.TrimSpace(line)

  if len(line) > 0 && !strings.HasPrefix(line, "#") {
    pieces := strings.Split(line, ":")
    if len(pieces) < 2 || len(pieces) > 3 {
      log.WithFields(log.Fields{
        "lineNumber": lineNum + 1,
        "filepath":   path,
      }).Warn("Invalid role mapping found while parsing role file")
    } else {
      permission := strings.TrimSpace(pieces[0])
      roles := strings.Split(pieces[1], " ")
      operation := "+"
      if len(pieces) > 2 {
        operation = pieces[2]
      }

      for _, role := range roles {
        role = strings.TrimSpace(role)
        if len(role) > 0 {
          impl.AdjustPermissionInRole(roleMap, role, permission, operation)
        }
      }
    }
  }
}
