// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package staticrbac

import (
  "bufio"
  "context"
  "crypto/md5"
  "errors"
  "github.com/apex/log"
  "github.com/security-onion-solutions/securityonion-soc/model"
  "github.com/security-onion-solutions/securityonion-soc/server"
  "github.com/security-onion-solutions/securityonion-soc/web"
  "os"
  "sort"
  "strings"
  "sync"
  "time"
)

type StaticRbacAuthorizer struct {
  server           *server.Server
  roleFiles        []string
  userFiles        []string
  scanIntervalMs   int
  roleMap          map[string][]string
  userMap          map[string][]string
  mutex            sync.Mutex
  running          bool
  previousRoleHash [16]byte
  previousUserHash [16]byte
  timer            *time.Timer
}

func NewStaticRbacAuthorizer(srv *server.Server) *StaticRbacAuthorizer {
  return &StaticRbacAuthorizer{
    server: srv,
  }
}

func (impl *StaticRbacAuthorizer) Init(userFiles []string, roleFiles []string, scanIntervalMs int) error {
  impl.roleFiles = roleFiles
  impl.userFiles = userFiles

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

func (impl *StaticRbacAuthorizer) identifyUser(user *model.User) string {
  return user.Id
}

func (impl *StaticRbacAuthorizer) GetAssignments(ctx context.Context) (map[string][]string, error) {
  userMap := make(map[string][]string)

  if err := impl.CheckContextOperationAuthorized(ctx, "read", "roles"); err != nil {
    // User is not allowed to access the entire role map, so only show their top-level roles

    if user, ok := ctx.Value(web.ContextKeyRequestor).(*model.User); ok {
      impl.mutex.Lock()
      defer impl.mutex.Unlock()

      userIdentifier := impl.identifyUser(user)
      roles := impl.userMap[userIdentifier]
      newRoles := make([]string, len(roles))
      copy(newRoles, roles)
      userMap[userIdentifier] = newRoles
      log.WithFields(log.Fields{
        "user":      userIdentifier,
        "roles":     roles,
        "requestId": ctx.Value(web.ContextKeyRequestId),
      }).Debug("User does not have access to read all roles; limiting role map to self")
    }
  } else {
    impl.mutex.Lock()
    defer impl.mutex.Unlock()

    for user, roles := range impl.userMap {
      newRoles := make([]string, len(roles))
      copy(newRoles, roles)
      userMap[user] = newRoles
    }
  }

  return userMap, nil
}

func (impl *StaticRbacAuthorizer) GetRoles(ctx context.Context) []string {
  roles := make([]string, 0, 0)
  tmp_roles := make([]string, 0, 0)
  perm_map := make(map[string]bool)
  if err := impl.CheckContextOperationAuthorized(ctx, "read", "roles"); err == nil {
    for role, perms := range impl.roleMap {
      tmp_roles = append(tmp_roles, role)
      for _, perm := range perms {
        perm_map[perm] = true
      }
    }
    for _, role := range tmp_roles {
      if _, ok := perm_map[role]; !ok {
        roles = append(roles, role)
      }
    }
    sort.Strings(roles)
  }
  return roles
}

func (impl *StaticRbacAuthorizer) PopulateUserRoles(ctx context.Context, user *model.User) error {
  // Use the returned roles instead of the struct roles so that they are filtered for access permissions
  userMap, _ := impl.GetAssignments(ctx)

  userIdentifier := impl.identifyUser(user)
  if roles, ok := userMap[userIdentifier]; ok {
    user.Roles = roles
    log.WithFields(log.Fields{
      "user":  userIdentifier,
      "roles": user.Roles,
    }).Debug("Populated roles for user")
  } else {
    log.WithField("user", userIdentifier).Debug("No roles found")
  }
  return nil
}

func (impl *StaticRbacAuthorizer) UpdateRoleMap(newRoleMap map[string][]string) {
  impl.mutex.Lock()
  defer impl.mutex.Unlock()

  impl.roleMap = newRoleMap
}

func (impl *StaticRbacAuthorizer) UpdateUserMap(newUserMap map[string][]string) {
  impl.mutex.Lock()
  defer impl.mutex.Unlock()

  impl.userMap = newUserMap
}

func (impl *StaticRbacAuthorizer) AddRoleToUser(user *model.User, role string) {
  impl.mutex.Lock()
  defer impl.mutex.Unlock()

  impl.adjustMap(impl.userMap, impl.identifyUser(user), role, "+")
}

func (impl *StaticRbacAuthorizer) RemoveRoleFromUser(user *model.User, role string) {
  impl.mutex.Lock()
  defer impl.mutex.Unlock()

  impl.adjustMap(impl.userMap, impl.identifyUser(user), role, "-")
}

func (impl *StaticRbacAuthorizer) adjustMap(mp map[string][]string, subject string, permission string, operation string) {
  perms := mp[subject]
  if perms == nil {
    perms = make([]string, 0, 0)
  }
  existsAtIdx := -1
  for idx, value := range perms {
    if value == permission {
      existsAtIdx = idx
      break
    }
  }

  if existsAtIdx == -1 && operation == "+" {
    perms = append(perms, permission)
    sort.Strings(perms)
  } else if existsAtIdx != -1 && operation == "-" {
    for idx, value := range perms {
      if value == permission {
        perms = append(perms[:idx], perms[idx+1:]...)
        break
      }
    }
  }
  mp[subject] = perms
}

func (impl *StaticRbacAuthorizer) CheckContextOperationAuthorized(ctx context.Context, operation string, target string) error {
  var err error
  if user, ok := ctx.Value(web.ContextKeyRequestor).(*model.User); ok {
    err = impl.CheckUserOperationAuthorized(user, operation, target)
  } else {
    log.WithFields(log.Fields{
      "requestId": ctx.Value(web.ContextKeyRequestId),
      "operation": operation,
      "target":    target,
    }).Debug("Authorization user not found in context")
    err = model.NewUnauthorized("", operation, target)
  }

  return err
}

func (impl *StaticRbacAuthorizer) CheckUserOperationAuthorized(user *model.User, operation string, target string) error {
  var err error
  permission := target + "/" + operation

  impl.mutex.Lock()
  defer impl.mutex.Unlock()

  authorized := false
  userIdentifier := impl.identifyUser(user)
  var primaryRoles []string
  var ok bool
  if primaryRoles, ok = impl.userMap[userIdentifier]; ok {
    for _, role := range primaryRoles {
      if impl.isAuthorized(role, permission) {
        authorized = true
        break
      }
    }
  }

  log.WithFields(log.Fields{
    "user":         userIdentifier,
    "permission":   permission,
    "primaryRoles": primaryRoles,
    "authorized":   authorized,
  }).Debug("Evaluated authorization for requestor")

  if !authorized {
    err = model.NewUnauthorized(userIdentifier, operation, target)
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

func (impl *StaticRbacAuthorizer) Reload() {
  impl.scanNow()
}

func (impl *StaticRbacAuthorizer) scanLoop() {
  log.WithField("scanIntervalMs", impl.scanIntervalMs).Info("Starting periodic role file scanner")
  for impl.running {
    impl.scanNow()
    impl.timer = time.NewTimer(time.Millisecond * time.Duration(impl.scanIntervalMs))

    <-impl.timer.C
  }
  log.Info("Stopped scanning role files")
}

func (impl *StaticRbacAuthorizer) scanNow() {
  log.Debug("Scanning role files for updates")
  newMap, hash := impl.scanFiles(impl.roleFiles)
  if hash != impl.previousRoleHash {
    log.WithField("roleMap", newMap).Info("Role files have changed; updating roles")
    impl.UpdateRoleMap(newMap)
    impl.previousRoleHash = hash
  }

  log.Debug("Scanning user files for updates")
  newMap, hash = impl.scanFiles(impl.userFiles)
  if hash != impl.previousUserHash {
    log.WithField("userMap", newMap).Info("User files have changed; updating users")
    impl.UpdateUserMap(newMap)

    // Ensure agent user/role exists
    impl.AddRoleToUser(impl.server.Agent, "agent")

    impl.previousUserHash = hash
  }
}

func (impl *StaticRbacAuthorizer) scanFiles(files []string) (map[string][]string, [16]byte) {
  newMap := make(map[string][]string)
  hashText := ""
  for lineNum, path := range files {
    file, err := os.Open(path)
    if err != nil {
      log.WithError(err).WithField("path", path).Error("Unable to open file")
    } else {
      defer file.Close()

      scanner := bufio.NewScanner(file)
      for scanner.Scan() {
        line := scanner.Text()
        hashText = hashText + line
        impl.parseLine(newMap, line, path, lineNum)
      }
    }
  }

  hash := md5.Sum([]byte(hashText))
  return newMap, hash
}

func (impl *StaticRbacAuthorizer) parseLine(mp map[string][]string, line string, path string, lineNum int) {
  line = strings.ReplaceAll(line, ",", " ") // Allow comma delimiting
  line = strings.ReplaceAll(line, ";", " ") // Allow semi-colon delimiting
  line = strings.TrimSpace(line)

  if len(line) > 0 && !strings.HasPrefix(line, "#") {
    pieces := strings.Split(line, ":")
    if len(pieces) < 2 || len(pieces) > 3 {
      log.WithFields(log.Fields{
        "lineNumber": lineNum + 1,
        "filepath":   path,
      }).Warn("Invalid mapping found while parsing file")
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
          impl.adjustMap(mp, role, permission, operation)
        }
      }
    }
  }
}
