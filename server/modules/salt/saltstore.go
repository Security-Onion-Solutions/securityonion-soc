// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package salt

import (
  "context"
  "errors"
  "fmt"
  "github.com/apex/log"
  "github.com/security-onion-solutions/securityonion-soc/json"
  "github.com/security-onion-solutions/securityonion-soc/model"
  "github.com/security-onion-solutions/securityonion-soc/server"
  "github.com/security-onion-solutions/securityonion-soc/syntax"
  "github.com/security-onion-solutions/securityonion-soc/web"
  "gopkg.in/yaml.v3"
  "os"
  "path/filepath"
  "sort"
  "strconv"
  "strings"
  "sync"
  "time"
)

type Saltstore struct {
  server        *server.Server
  client        *web.Client
  timeoutMs     int
  saltstackDir  string
  saltPipeReq   string
  saltPipeResp  string
  saltPipeMutex sync.Mutex
  bypassErrors  bool
}

func NewSaltstore(server *server.Server) *Saltstore {
  return &Saltstore{
    server: server,
  }
}

func (store *Saltstore) Init(timeoutMs int, saltstackDir string, saltPipeReq string, saltPipeResp string,
  bypassErrors bool) error {
  store.timeoutMs = timeoutMs
  store.saltstackDir = strings.TrimSuffix(saltstackDir, "/")
  store.saltPipeReq = saltPipeReq
  store.saltPipeResp = saltPipeResp
  store.bypassErrors = bypassErrors
  return nil
}

func (store *Saltstore) execCommand(ctx context.Context, args map[string]string) (string, error) {
  // Obtain exclusive lock to avoid interleaved responses
  store.saltPipeMutex.Lock()
  defer store.saltPipeMutex.Unlock()

  log.WithFields(log.Fields{
    "saltPipeReq": store.saltPipeReq,
  }).Debug("Opening salt pipe")

  pipe, err := os.OpenFile(store.saltPipeReq, os.O_WRONLY|os.O_APPEND, 0660)
  if err != nil {
    log.WithFields(log.Fields{
      "saltPipeReq": store.saltPipeReq,
    }).WithError(err).Error("Unable to open salt pipe")
    return "", err
  }

  var nanoseconds int64
  nanoseconds = int64(store.timeoutMs) * 1000 * 1000

  log.WithFields(log.Fields{
    "saltPipeReq": store.saltPipeReq,
    "timeoutNs":   nanoseconds,
  }).Info("Executing command via salt pipe")

  // Write command to pipe
  var wrote int

  var request_bytes []byte
  request_bytes, err = json.WriteJson(args)
  if err != nil {
    log.WithFields(log.Fields{}).WithError(err).Error("Unable to convert command args to JSON")
    return "", err
  }
  request := string(request_bytes)
  pipe.SetDeadline(time.Now().Add(time.Duration(nanoseconds)))
  wrote, err = pipe.WriteString(request)
  if err != nil || wrote != len(request) {
    log.WithFields(log.Fields{
      "saltPipeReq": store.saltPipeReq,
      "wrote":       wrote,
      "length":      len(request),
    }).WithError(err).Error("Unable to write to salt pipe")

    return "", err
  }

  err = pipe.Close()
  if err != nil {
    log.WithFields(log.Fields{
      "saltPipeReq": store.saltPipeReq,
    }).WithError(err).Error("Unable to close pipe after writing request")
    return "", err
  }

  log.WithFields(log.Fields{
    "saltPipeResp": store.saltPipeResp,
    "length":       len(request),
  }).Info("Reading response via salt pipe")

  // Read up to 1MB response from pipe
  totalRead := 0
  bytes := make([]byte, 1024*1024)

  pipe, err = os.OpenFile(store.saltPipeResp, os.O_RDONLY, 0660)
  if err != nil {
    log.WithFields(log.Fields{
      "saltPipeResp": store.saltPipeResp,
      "length":       len(request),
    }).WithError(err).Error("Unable to open salt pipe for read")
    return "", err
  }
  pipe.SetDeadline(time.Now().Add(time.Duration(nanoseconds)))
  for {
    read, err := pipe.Read(bytes[totalRead:])
    if err != nil {
      log.WithFields(log.Fields{
        "saltPipeResp": store.saltPipeResp,
        "length":       len(request),
      }).WithError(err).Debug("Unable to read response")
    }

    if read > 0 {
      totalRead += read
      log.WithFields(log.Fields{
        "saltPipeResp": store.saltPipeResp,
        "length":       len(request),
        "read":         read,
        "totalRead":    totalRead,
      }).Debug("Appending more read bytes to response")
    } else if read == 0 || bytes[totalRead+read] == 0 || err != nil {
      break
    }

  }
  pipe.Close()

  response := string(bytes[0:totalRead])
  response = strings.TrimSpace(response)
  if response == request {
    return "", errors.New("ERROR_SALT_RELAY_DOWN")
  }

  log.WithFields(log.Fields{
    "saltPipeResp": store.saltPipeResp,
    "length":       len(request),
    "bytesRead":    len(response),
    "response":     response,
  }).Debug("Finished reading response")

  return response, err
}

func (store *Saltstore) GetSettings(ctx context.Context) ([]*model.Setting, error) {
  var err error
  if err = store.server.CheckAuthorized(ctx, "read", "config"); err != nil {
    return nil, err
  }

  settings := make([]*model.Setting, 0, 0)

  // Parse the default values first.
  err = filepath.Walk(store.saltstackDir+"/default", func(path string, info os.FileInfo, err error) error {
    if (store.bypassErrors || err == nil) && !info.IsDir() && info.Name() == "defaults.yaml" {
      var mapped map[string]interface{}
      mapped, err = store.parseYaml(path)
      if err == nil {
        settings = store.recursivelyParseSettings(path, settings, mapped, "", "", false)
      }
    }

    if store.bypassErrors {
      if err != nil {
        log.WithField("path", path).WithError(err).Warn("Bypassing error while parsing defaults")
      }
      return nil
    }
    return err
  })

  // Since these are the defaults, set all settings' values as their defaults, so that users can easily revert
  // overrides.
  for _, setting := range settings {
    setting.Default = setting.Value
    setting.DefaultAvailable = true
  }

  // Now parse the local pillar overrides
  if store.bypassErrors || err == nil {
    err = filepath.Walk(store.saltstackDir+"/local", func(path string, info os.FileInfo, err error) error {
      if (store.bypassErrors || err == nil) && !info.IsDir() && strings.HasSuffix(info.Name(), ".sls") {
        setting_id := strings.TrimSuffix(info.Name(), ".sls")
        minion_id := ""

        is_minion := strings.Contains(path, "/minions/")

        if strings.HasPrefix(setting_id, "adv_") {
          setting_id = strings.TrimPrefix(setting_id, "adv_")

          if is_minion {
            minion_id = setting_id
            setting_id = "advanced"
          } else {
            setting_id = setting_id + ".advanced"
          }
          settings = store.parseAdvanced(path, settings, minion_id, setting_id)
        } else if strings.HasPrefix(setting_id, "soc_") || is_minion {
          if is_minion {
            minion_id = setting_id
          }
          var mapped map[string]interface{}
          mapped, err = store.parseYaml(path)
          if err == nil {
            settings = store.recursivelyParseSettings(path, settings, mapped, "", minion_id, true)
          }
        }
      }

      if store.bypassErrors {
        if err != nil {
          log.WithField("path", path).WithError(err).Warn("Bypassing error while parsing local pillars")
        }
        return nil
      }
      return err
    })
  }

  // Parse the static pillar annotations, to provide supporting details to the parsed settings above.
  if store.bypassErrors || err == nil {
    err = filepath.Walk(store.saltstackDir+"/default", func(path string, info os.FileInfo, err error) error {
      if (store.bypassErrors || err == nil) && !info.IsDir() && strings.HasPrefix(info.Name(), "soc_") && strings.HasSuffix(info.Name(), ".yaml") {
        var mapped map[string]interface{}
        mapped, err = store.parseYaml(path)
        if err == nil {
          settings, _ = store.recursivelyParseAnnotations(path, settings, mapped, "")
        }
      }

      if store.bypassErrors {
        if err != nil {
          log.WithField("path", path).WithError(err).Warn("Bypassing error while parsing annotations")
        }
        return nil
      }
      return err
    })
  }

  return store.sortSettings(settings), err
}

func (store *Saltstore) sortSettings(settings []*model.Setting) []*model.Setting {
  sort.Slice(settings, func(idx_a, idx_b int) bool {
    return (settings[idx_a].Id < settings[idx_b].Id && !strings.HasSuffix(settings[idx_a].Id, "advanced")) ||
      strings.HasSuffix(settings[idx_b].Id, "advanced")
  })
  return settings
}

func (store *Saltstore) parseYaml(path string) (map[string]interface{}, error) {
  var mapped map[string]interface{}
  content, err := os.ReadFile(path)
  if err != nil {
    log.WithFields(log.Fields{
      "path": path,
    }).WithError(err).Error("Unable to read YAML file")
  } else {
    log.WithFields(log.Fields{
      "path":   path,
      "length": len(content),
    }).Debug("Parsing YAML file")
    mapped = make(map[string]interface{})
    err = yaml.Unmarshal(content, &mapped)
    if err != nil {
      log.WithFields(log.Fields{
        "path": path,
      }).WithError(err).Error("Unable to parse YAML file")
    }
  }

  return mapped, err
}

func (store *Saltstore) writeYaml(path string, mapped map[string]interface{}) error {
  contents, err := yaml.Marshal(mapped)
  if err != nil {
    log.WithFields(log.Fields{
      "path": path,
    }).WithError(err).Error("Unable to convert map to YAML")
  } else {
    log.WithFields(log.Fields{
      "path":   path,
      "length": len(contents),
    }).Debug("Writing YAML file")
    err = os.WriteFile(path, contents, 0600)
    if err != nil {
      log.WithFields(log.Fields{
        "path": path,
      }).WithError(err).Error("Unable to write YAML file")
    }
  }

  return err
}

func (store *Saltstore) convertToJson(item interface{}) string {
  bytes, err := json.WriteJson(item)
  if err == nil {
    return string(bytes)
  }

  log.WithField("item", item).WithError(err).Error("Failed to convert map to JSON; setting will be blank")
  return ""
}

func (store *Saltstore) recursivelyParseSettings(
  path string,
  settings []*model.Setting,
  mapped map[string]interface{},
  prefix string,
  minion string,
  merge bool,
) []*model.Setting {

  for id, value := range mapped {
    foundSetting := true
    newValue := ""
    multiline := false

    newPrefix := prefix
    if newPrefix != "" {
      newPrefix = newPrefix + "."
    }

    switch value.(type) {
    case map[string]interface{}:
      foundSetting = false
      settings = store.recursivelyParseSettings(path, settings, value.(map[string]interface{}), newPrefix+id, minion, merge)
    case []interface{}:
      multiline = true
      for _, item := range value.([]interface{}) {

        var str string
        switch item.(type) {
        case []interface{}:
          str = store.convertToJson(item)
        case map[string]interface{}:
          str = store.convertToJson(item)
        default:
          str = fmt.Sprintf("%v", item)
        }

        if str != "" {
          if newValue != "" {
            newValue = newValue + "\n"
          }
          newValue = newValue + str
        }
      }
    default:
      newValue = fmt.Sprintf("%v", value)
    }

    if foundSetting {
      newId := newPrefix + id

      merged := false
      if minion == "" {
        for _, existing := range settings {
          if existing.Id == newId {
            existing.Value = newValue
            if existing.Multiline != multiline {
              log.WithFields(log.Fields{
                "newId":        newId,
                "newMultiline": multiline,
                "oldMultiline": existing.Multiline,
              }).Warn("Existing/Default setting's multiline attribute conflicts with override multiline attribute")
              existing.Multiline = multiline
            }
            merged = true
          }
        }
      }

      if !merged {
        setting := model.NewSetting(newId)
        setting.Value = newValue
        setting.NodeId = minion
        setting.Multiline = multiline
        settings = append(settings, setting)
      }
    }
  }
  return settings
}

func (store *Saltstore) recursivelyParseAnnotations(
  path string,
  settings []*model.Setting,
  mapped map[string]interface{},
  prefix string,
) ([]*model.Setting, bool) {

  foundAnnotation := false
  for id, value := range mapped {

    newPrefix := prefix
    if newPrefix != "" {
      newPrefix = newPrefix + "."
    }

    newId := newPrefix + id

    switch value.(type) {
    case map[string]interface{}:
      var endOfBranch bool
      settings, endOfBranch = store.recursivelyParseAnnotations(path, settings, value.(map[string]interface{}), newId)
      if endOfBranch {
        foundExisting := false
        for _, setting := range settings {
          if setting.Id == newId {
            store.updateSettingWithAnnotation(setting, value.(map[string]interface{}))

            // Do not allow settings that are marked as sensitive to be transmitted to remote API clients.
            if setting.Sensitive {
              setting.Value = "******"
              setting.Default = ""
            }
            foundExisting = true
          }
        }
        if !foundExisting {
          // Add a new setting since there is no existing setting for this annotation
          setting := model.NewSetting(newId)
          store.updateSettingWithAnnotation(setting, value.(map[string]interface{}))
          settings = append(settings, setting)
          log.WithFields(log.Fields{
            id: newId,
          }).Debug("Found annotation without a setting")
        }
      }
    default:
      foundAnnotation = true
      break
    }
  }
  return settings, foundAnnotation
}

func (store *Saltstore) updateSettingWithAnnotation(setting *model.Setting, annotations map[string]interface{}) {
  for key, value := range annotations {
    switch key {
    case "title":
      setting.Title = fmt.Sprintf("%v", value)
    case "description":
      setting.Description = fmt.Sprintf("%v", value)
    case "readonly":
      setting.Readonly = value.(bool)
    case "global":
      setting.Global = value.(bool)
    case "multiline":
      setting.Multiline = value.(bool)
    case "node":
      setting.Node = value.(bool)
    case "sensitive":
      setting.Sensitive = value.(bool)
    case "regex":
      setting.Regex = fmt.Sprintf("%v", value)
    case "regexFailureMessage":
      setting.RegexFailureMessage = fmt.Sprintf("%v", value)
    case "advanced":
      setting.Advanced = value.(bool)
    case "helpLink":
      setting.HelpLink = fmt.Sprintf("%v", value)
    case "syntax":
      setting.Syntax = fmt.Sprintf("%v", value)
    case "file":
      // This is a special type of annotation. It allows the contents
      // of any salt file to become a setting.
      setting.File = value.(bool)
      if setting.File {
        setting.Multiline = true

        relpath := store.relPathFromId(setting.Id)
        var err error
        setting.Default, err = store.readFile(fmt.Sprintf("%s/default/salt/%s", store.saltstackDir, relpath))
        if err == nil {
          setting.DefaultAvailable = true
        }
        setting.Value, _ = store.readFile(fmt.Sprintf("%s/local/salt/%s", store.saltstackDir, relpath))
        if setting.Value == "" {
          setting.Value = setting.Default
        }
      }
    }
  }
}

func (store *Saltstore) relPathFromId(id string) string {
  // Example of an ID conversion to path: soc.files.soc.banner_md -> soc/files/soc/banner.md
  relpath := strings.ReplaceAll(id, ".", "/")
  relpath = strings.ReplaceAll(relpath, "__", ".")
  relpath = strings.ReplaceAll(relpath, "..", "____") // Shenannigans
  return relpath
}

func (store *Saltstore) readFile(path string) (string, error) {
  content, err := os.ReadFile(path)
  if err != nil {
    log.WithFields(log.Fields{
      "path": path,
    }).WithError(err).Debug("Unable to read config file")
  } else {
    log.WithFields(log.Fields{
      "path":   path,
      "length": len(content),
    }).Debug("Reading config file")
    return string(content), nil
  }
  return "", err
}

func (store *Saltstore) parseAdvanced(path string, settings []*model.Setting, minion string, id string) []*model.Setting {
  content, err := store.readFile(path)
  if err == nil {
    setting := model.NewSetting(id)
    if minion != "" {
      setting.Global = false
      setting.Node = true
    } else {
      setting.Global = true
      setting.Node = false
    }
    setting.Value = content
    setting.NodeId = minion
    setting.Multiline = true
    setting.Syntax = "yaml"
    settings = append(settings, setting)
  }

  return settings
}

func (store *Saltstore) updateSetting(mapped map[string]interface{}, sections []string, value string) error {
  if mapped == nil || len(sections) == 0 {
    return errors.New("Settings map to section id mismatch")
  }

  name := sections[0]
  child := mapped[name]
  if child == nil && len(sections) > 1 {
    // This is a new override so the parent hierarchy doesn't yet exist. Create it.
    child = make(map[string]interface{})
    mapped[name] = child
  }

  if child != nil {
    switch child.(type) {
    case map[string]interface{}:
      if len(sections) == 1 {
        return errors.New("Unexpected setting value of map type during update")
      }
      return store.updateSetting(child.(map[string]interface{}), sections[1:], value)
    }
  }

  var err error
  if len(sections) == 1 {
    log.WithFields(log.Fields{
      "name":          name,
      "length":        len(value),
      "alreadyExists": mapped[name] != nil,
    }).Debug("Updating setting value")
    mapped[name], err = store.alignType(mapped[name], value)
  }

  return err
}

func (store *Saltstore) deleteSetting(mapped map[string]interface{}, sections []string) (bool, error) {
  if mapped == nil || len(sections) == 0 {
    return false, errors.New("Settings map to section id mismatch")
  }

  var err error
  name := sections[0]
  child := mapped[name]
  if child != nil {
    switch child.(type) {
    case map[string]interface{}:
      if len(sections) == 1 {
        return false, errors.New("Unexpected setting value of map type during delete")
      }

      var empty bool
      empty, err = store.deleteSetting(child.(map[string]interface{}), sections[1:])
      if empty && err == nil {
        log.WithFields(log.Fields{
          "name": name,
        }).Debug("Deleting empty parent")
        delete(mapped, name)
      }
    default:
      log.WithFields(log.Fields{
        "name": name,
      }).Debug("Deleting setting from parent")
      delete(mapped, name)
    }
  }

  empty := len(mapped) == 0

  return empty, err
}

func (store *Saltstore) UpdateSetting(ctx context.Context, setting *model.Setting, remove bool) error {
  var err error
  if err = store.server.CheckAuthorized(ctx, "write", "config"); err != nil {
    return err
  }

  sections := strings.Split(setting.Id, ".")

  if len(sections) == 0 {
    return errors.New("Invalid setting id: " + setting.Id)
  }

  if !remove {
    err = syntax.Validate(setting.Value, setting.Syntax)
    if err != nil {
      return err
    }
  }

  if len(sections) <= 2 && sections[len(sections)-1] == "advanced" {
    var path string
    if setting.NodeId == "" {
      path = fmt.Sprintf("%s/local/pillar/%s/adv_%s.sls", store.saltstackDir, sections[0], sections[0])
    } else {
      path = fmt.Sprintf("%s/local/pillar/minions/adv_%s.sls", store.saltstackDir, setting.NodeId)
    }

    log.WithFields(log.Fields{
      "settingId": setting.Id,
      "minionId":  setting.NodeId,
      "path":      path,
      "length":    len(setting.Value),
    }).Info("Updating advanced settings to new value")
    os.WriteFile(path, []byte(setting.Value), 0600)

  } else if setting.File {
    path := fmt.Sprintf("%s/local/salt/%s", store.saltstackDir, store.relPathFromId(setting.Id))

    log.WithFields(log.Fields{
      "settingId": setting.Id,
      "path":      path,
      "length":    len(setting.Value),
    }).Info("Updating custom file setting to new value")

    err = os.WriteFile(path, []byte(setting.Value), 0600)
  } else {
    var path string
    if setting.NodeId == "" {
      path = fmt.Sprintf("%s/local/pillar/%s/soc_%s.sls", store.saltstackDir, sections[0], sections[0])
    } else {
      path = fmt.Sprintf("%s/local/pillar/minions/%s.sls", store.saltstackDir, setting.NodeId)
    }

    var mapped map[string]interface{}
    mapped, err = store.parseYaml(path)
    if err == nil {
      if !remove {
        log.WithFields(log.Fields{
          "settingId": setting.Id,
          "path":      path,
          "length":    len(setting.Value),
        }).Info("Updating setting to new value")
        err = store.updateSetting(mapped, sections, setting.Value)
      } else {
        log.WithFields(log.Fields{
          "settingId": setting.Id,
          "path":      path,
        }).Info("Deleting setting")
        _, err = store.deleteSetting(mapped, sections)
      }

      if err == nil {
        err = store.writeYaml(path, mapped)
      }
    }
  }

  return err
}

func (store *Saltstore) alignInt64List(newValue string) ([]int64, error) {
  var newList []int64
  if len(newValue) > 0 {
    tmp := strings.Split(newValue, "\n")
    newList = make([]int64, 0, 0)
    for _, str := range tmp {
      i, err := strconv.ParseInt(str, 10, 64)
      if err != nil {
        return nil, err
      }
      newList = append(newList, i)
    }
  }
  return newList, nil
}

func (store *Saltstore) alignBoolList(newValue string) ([]bool, error) {
  var newList []bool
  if len(newValue) > 0 {
    tmp := strings.Split(newValue, "\n")
    newList = make([]bool, 0, 0)
    for _, str := range tmp {
      b, err := strconv.ParseBool(str)
      if err != nil {
        return nil, err
      }
      newList = append(newList, b)
    }
  }
  return newList, nil
}

func (store *Saltstore) alignFloat64List(newValue string) ([]float64, error) {
  var newList []float64
  if len(newValue) > 0 {
    tmp := strings.Split(newValue, "\n")
    newList = make([]float64, 0, 0)
    for _, str := range tmp {
      f, err := strconv.ParseFloat(str, 64)
      if err != nil {
        return nil, err
      }
      newList = append(newList, f)
    }
  }
  return newList, nil
}

func (store *Saltstore) alignListList(newValue string) ([][]interface{}, error) {
  var newList [][]interface{}
  if len(newValue) > 0 {
    tmp := strings.Split(newValue, "\n")
    newList = make([][]interface{}, 0, 0)
    for _, str := range tmp {
      l := make([]interface{}, 0, 0)
      err := json.LoadJson([]byte(str), &l)
      if err != nil {
        return nil, err
      }
      newList = append(newList, l)
    }
  }
  return newList, nil
}

func (store *Saltstore) alignMapList(newValue string) ([]map[string]interface{}, error) {
  var newList []map[string]interface{}
  if len(newValue) > 0 {
    tmp := strings.Split(newValue, "\n")
    newList = make([]map[string]interface{}, 0, 0)
    for _, str := range tmp {
      m := make(map[string]interface{})
      err := json.LoadJson([]byte(str), &m)
      if err != nil {
        return nil, err
      }
      newList = append(newList, m)
    }
  }
  return newList, nil
}

func (store *Saltstore) alignBestGuess(newValue string) interface{} {
  i, err := strconv.ParseInt(newValue, 10, 64)
  if err == nil {
    return i
  }
  f, err := strconv.ParseFloat(newValue, 64)
  if err == nil {
    return f
  }
  b, err := strconv.ParseBool(newValue)
  if err == nil {
    return b
  }
  if strings.Contains(newValue, "\n") {
    output, _ := store.alignBestGuessList(newValue)
    return output
  }

  newValueTrimmed := strings.TrimSpace(newValue)
  if strings.HasPrefix(newValueTrimmed, "{") && strings.HasSuffix(newValueTrimmed, "}") {
    tmp := make(map[string]interface{})
    err := json.LoadJson([]byte(newValueTrimmed), &tmp)
    if err == nil {
      return tmp
    }
  }
  if strings.HasPrefix(newValueTrimmed, "[") && strings.HasSuffix(newValueTrimmed, "]") {
    tmp := make([]interface{}, 0, 0)
    err := json.LoadJson([]byte(newValueTrimmed), &tmp)
    if err == nil {
      return tmp
    }
  }
  return newValue
}

func (store *Saltstore) alignBestGuessList(newValue string) (interface{}, error) {
  var newList []string
  if len(newValue) > 0 {
    newList = strings.Split(newValue, "\n")
    if len(newList) > 0 {
      firstValue := newList[0]
      bestGuess := store.alignBestGuess(firstValue)
      switch bestGuess.(type) {
      case int:
        return store.alignInt64List(newValue)
      case int64:
        return store.alignInt64List(newValue)
      case bool:
        return store.alignBoolList(newValue)
      case float32:
        return store.alignFloat64List(newValue)
      case float64:
        return store.alignFloat64List(newValue)
      case []interface{}:
        return store.alignListList(newValue)
      case map[string]interface{}:
        return store.alignMapList(newValue)
      }
    }
  }
  return newList, nil
}

func (store *Saltstore) alignType(oldValue interface{}, newValue string) (interface{}, error) {
  if oldValue != nil {
    switch oldValue.(type) {
    case float64:
      return strconv.ParseFloat(newValue, 64)
    case int:
      return strconv.ParseInt(newValue, 10, 64)
    case bool:
      return strconv.ParseBool(newValue)
    case []interface{}:
      newList := oldValue.([]interface{})
      if len(newList) > 0 {
        switch newList[0].(type) {
        case int:
          return store.alignInt64List(newValue)
        case int64:
          return store.alignInt64List(newValue)
        case bool:
          return store.alignBoolList(newValue)
        case float32:
          return store.alignFloat64List(newValue)
        case float64:
          return store.alignFloat64List(newValue)
        case []interface{}:
          return store.alignListList(newValue)
        case map[string]interface{}:
          return store.alignMapList(newValue)
        }
      }
      return store.alignBestGuessList(newValue)
    case []string:
      return strings.Split(newValue, "\n"), nil
    case []int64:
      return store.alignInt64List(newValue)
    case []bool:
      return store.alignBoolList(newValue)
    case []float64:
      return store.alignFloat64List(newValue)
    }
  }
  return store.alignBestGuess(newValue), nil
}

type ListResponse struct {
  Accepted   map[string]string `json:"minions"`
  Unaccepted map[string]string `json:"minions_pre"`
  Rejected   map[string]string `json:"minions_rejected"`
  Denied     map[string]string `json:"minions_denied"`
}

func getMembersFromJson(err error, output []byte) ([]*model.GridMember, error) {
  var members []*model.GridMember

  if err == nil {
    response := &ListResponse{}
    err = json.LoadJson(output, response)
    if err == nil {
      members = make([]*model.GridMember, 0, 0)
      for id, fingerprint := range response.Accepted {
        members = append(members, model.NewGridMember(id, model.GridMemberAccepted, fingerprint))
      }
      for id, fingerprint := range response.Unaccepted {
        members = append(members, model.NewGridMember(id, model.GridMemberUnaccepted, fingerprint))
      }
      for id, fingerprint := range response.Rejected {
        members = append(members, model.NewGridMember(id, model.GridMemberRejected, fingerprint))
      }
      for id, fingerprint := range response.Denied {
        members = append(members, model.NewGridMember(id, model.GridMemberDenied, fingerprint))
      }
    }
  }

  return members, err
}

func (store *Saltstore) GetMembers(ctx context.Context) ([]*model.GridMember, error) {
  if err := store.server.CheckAuthorized(ctx, "read", "grid"); err != nil {
    return nil, err
  }

  var members []*model.GridMember
  args := make(map[string]string)
  args["command"] = "list-minions"
  output, err := store.execCommand(ctx, args)
  if err == nil {
    if output == "false" {
      err = errors.New("ERROR_SALT_MANAGE_MEMBER")
    }

    members, err = getMembersFromJson(err, []byte(output))
  }

  return members, err
}

func (store *Saltstore) ManageMember(ctx context.Context, operation string, id string) error {
  if err := store.server.CheckAuthorized(ctx, "write", "grid"); err != nil {
    return err
  }

  args := make(map[string]string)
  args["command"] = "manage-minions"
  args["operation"] = operation
  args["id"] = id
  output, err := store.execCommand(ctx, args)
  if err == nil {
    if output == "false" {
      err = errors.New("ERROR_SALT_MANAGE_MEMBER")
    }
  }

  return err
}

func (store *Saltstore) lookupEmailFromId(ctx context.Context, id string) string {
  user, _ := store.server.Userstore.GetUserById(ctx, id)
  if user != nil && user.Id == id {
    return user.Email
  }
  return ""
}

func (store *Saltstore) AddUser(ctx context.Context, user *model.User) error {
  if err := store.server.CheckAuthorized(ctx, "write", "users"); err != nil {
    return err
  }

  args := make(map[string]string)
  args["command"] = "manage-user"
  args["operation"] = "add"
  args["email"] = user.Email
  if len(user.Roles) > 0 {
    args["role"] = user.Roles[0]
  }
  args["firstName"] = user.FirstName
  args["lastName"] = user.LastName
  args["note"] = user.Note
  args["password"] = user.Password
  output, err := store.execCommand(ctx, args)
  if err == nil {
    if output == "false" {
      err = errors.New("ERROR_SALT_MANAGE_USER")
    }
  }

  store.server.Rolestore.Reload()

  return err
}

func (store *Saltstore) DeleteUser(ctx context.Context, id string) error {
  if err := store.server.CheckAuthorized(ctx, "delete", "users"); err != nil {
    return err
  }

  args := make(map[string]string)
  args["command"] = "manage-user"
  args["operation"] = "delete"
  args["email"] = store.lookupEmailFromId(ctx, id)
  output, err := store.execCommand(ctx, args)
  if err == nil {
    if output == "false" {
      err = errors.New("ERROR_SALT_MANAGE_USER")
    }
  }

  return err
}

func (store *Saltstore) UpdateProfile(ctx context.Context, user *model.User) error {
  if err := store.server.CheckAuthorized(ctx, "write", "users"); err != nil {
    return err
  }

  args := make(map[string]string)
  args["command"] = "manage-user"
  args["operation"] = "profile"
  args["email"] = store.lookupEmailFromId(ctx, user.Id)
  args["firstName"] = user.FirstName
  args["lastName"] = user.LastName
  args["note"] = user.Note
  output, err := store.execCommand(ctx, args)
  if err == nil {
    if output == "false" {
      err = errors.New("ERROR_SALT_MANAGE_USER")
    }
  }

  return err
}

func (store *Saltstore) ResetPassword(ctx context.Context, id string, password string) error {
  if err := store.server.CheckAuthorized(ctx, "write", "users"); err != nil {
    return err
  }

  args := make(map[string]string)
  args["command"] = "manage-user"
  args["operation"] = "password"
  args["email"] = store.lookupEmailFromId(ctx, id)
  args["password"] = password
  output, err := store.execCommand(ctx, args)
  if err == nil {
    if output == "false" {
      err = errors.New("ERROR_SALT_MANAGE_USER")
    }
  }

  return err
}

func (store *Saltstore) EnableUser(ctx context.Context, id string) error {
  if err := store.server.CheckAuthorized(ctx, "write", "users"); err != nil {
    return err
  }

  args := make(map[string]string)
  args["command"] = "manage-user"
  args["operation"] = "enable"
  args["email"] = store.lookupEmailFromId(ctx, id)
  output, err := store.execCommand(ctx, args)
  if err == nil {
    if output == "false" {
      err = errors.New("ERROR_SALT_MANAGE_USER")
    }
  }

  return err
}

func (store *Saltstore) DisableUser(ctx context.Context, id string) error {
  if err := store.server.CheckAuthorized(ctx, "write", "users"); err != nil {
    return err
  }

  args := make(map[string]string)
  args["command"] = "manage-user"
  args["operation"] = "disable"
  args["email"] = store.lookupEmailFromId(ctx, id)
  output, err := store.execCommand(ctx, args)
  if err == nil {
    if output == "false" {
      err = errors.New("ERROR_SALT_MANAGE_USER")
    }
  }

  return err
}

func (store *Saltstore) AddRole(ctx context.Context, id string, role string) error {
  if err := store.server.CheckAuthorized(ctx, "write", "users"); err != nil {
    return err
  }

  args := make(map[string]string)
  args["command"] = "manage-user"
  args["operation"] = "addrole"
  args["email"] = store.lookupEmailFromId(ctx, id)
  args["role"] = role
  output, err := store.execCommand(ctx, args)
  if err == nil {
    if output == "false" {
      err = errors.New("ERROR_SALT_MANAGE_USER")
    }
  }

  store.server.Rolestore.Reload()

  return err
}

func (store *Saltstore) DeleteRole(ctx context.Context, id string, role string) error {
  if err := store.server.CheckAuthorized(ctx, "write", "users"); err != nil {
    return err
  }

  args := make(map[string]string)
  args["command"] = "manage-user"
  args["operation"] = "delrole"
  args["email"] = store.lookupEmailFromId(ctx, id)
  args["role"] = role
  output, err := store.execCommand(ctx, args)
  if err == nil {
    if output == "false" {
      err = errors.New("ERROR_SALT_MANAGE_USER")
    }
  }

  store.server.Rolestore.Reload()

  return err
}

func (store *Saltstore) SyncUsers(ctx context.Context) error {
  if err := store.server.CheckAuthorized(ctx, "write", "users"); err != nil {
    return err
  }

  args := make(map[string]string)
  args["command"] = "manage-user"
  args["operation"] = "sync"
  output, err := store.execCommand(ctx, args)
  if err == nil {
    if output == "false" {
      err = errors.New("ERROR_SALT_MANAGE_USER")
    }
  }

  return err
}

func (store *Saltstore) SyncSettings(ctx context.Context) error {
  if err := store.server.CheckAuthorized(ctx, "write", "config"); err != nil {
    return err
  }

  args := make(map[string]string)
  args["command"] = "manage-salt"
  args["operation"] = "highstate"
  output, err := store.execCommand(ctx, args)
  if err == nil {
    if output == "false" {
      err = errors.New("ERROR_SALT_STATE")
    }
  }

  return err
}
