// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
  "bytes"
  "crypto/md5"
  "crypto/sha1"
  "crypto/sha256"
  "encoding/base64"
  "fmt"
  "hash"
  "io"
  "net/http"
  "strings"
  "time"
)

const CASE_STATUS_NEW = "new"

type Auditable struct {
  Id         string     `json:"id,omitempty"`
  CreateTime *time.Time `json:"createTime"`
  UpdateTime *time.Time `json:"updateTime,omitempty"`
  UserId     string     `json:"userId"`
  Kind       string     `json:"kind,omitempty"`
  Operation  string     `json:"operation,omitempty"`
}

type Case struct {
  Auditable
  StartTime    *time.Time `json:"startTime"`
  CompleteTime *time.Time `json:"completeTime"`
  Title        string     `json:"title"`
  Description  string     `json:"description"`
  Priority     int        `json:"priority"`
  Severity     string     `json:"severity"`
  Status       string     `json:"status"`
  Template     string     `json:"template"`
  Tlp          string     `json:"tlp"`
  Pap          string     `json:"pap"`
  Category     string     `json:"category"`
  AssigneeId   string     `json:"assigneeId"`
  Tags         []string   `json:"tags"`
}

func NewCase() *Case {
  newCase := &Case{}
  return newCase
}

func (socCase *Case) ProcessWorkflowForStatus(oldCase *Case) {
  now := time.Now()
  if socCase.Status == "closed" && oldCase.Status != "closed" {
    socCase.CompleteTime = &now
  }
  if oldCase.StartTime != nil && !oldCase.StartTime.IsZero() {
    socCase.StartTime = oldCase.StartTime
  } else if socCase.Status == "in progress" && oldCase.Status != "in progress" {
    socCase.StartTime = &now
  }
}

type Comment struct {
  Auditable
  CaseId      string `json:"caseId"`
  Description string `json:"description"`
}

func NewComment() *Comment {
  newComment := &Comment{}
  return newComment
}

type RelatedEvent struct {
  Auditable
  CaseId string                 `json:"caseId"`
  Fields map[string]interface{} `json:"fields"`
}

func NewRelatedEvent() *RelatedEvent {
  newRelatedEvent := &RelatedEvent{}
  now := time.Now()
  newRelatedEvent.CreateTime = &now
  newRelatedEvent.Fields = make(map[string]interface{})
  return newRelatedEvent
}

type Artifact struct {
  Auditable
  CaseId       string   `json:"caseId"`
  GroupType    string   `json:"groupType"`
  GroupId      string   `json:"groupId"`
  ArtifactType string   `json:"artifactType"`
  Value        string   `json:"value"`
  MimeType     string   `json:"mimeType"`
  StreamLen    int      `json:"streamLength"`
  StreamId     string   `json:"streamId"`
  Tlp          string   `json:"tlp"`
  Tags         []string `json:"tags"`
  Description  string   `json:"description"`
  Ioc          bool     `json:"ioc"`
  Md5          string   `json:"md5"`
  Sha1         string   `json:"sha1"`
  Sha256       string   `json:"sha256"`
}

func NewArtifact() *Artifact {
  newArtifact := &Artifact{}
  now := time.Now()
  newArtifact.CreateTime = &now
  return newArtifact
}

type ArtifactStream struct {
  Auditable
  Content string `json:"content"`
}

func NewArtifactStream() *ArtifactStream {
  newStream := &ArtifactStream{}
  now := time.Now()
  newStream.CreateTime = &now
  return newStream
}

func (stream *ArtifactStream) hashBytes(hasher hash.Hash, input []byte) string {
  hasher.Write(input)
  output := hasher.Sum(nil)
  return fmt.Sprintf("%x", output)
}

func (stream *ArtifactStream) Write(reader io.Reader) (int, string, string, string, string, error) {
  var buffer bytes.Buffer
  var mimeType, md5hash, sha1hash, sha256hash string

  // Collect bytes in memory
  copyLen, err := buffer.ReadFrom(reader)
  if err == nil {
    raw := buffer.Bytes()
    stream.Content = base64.StdEncoding.EncodeToString(raw)
    mimeType = http.DetectContentType(raw)
    md5hash = stream.hashBytes(md5.New(), raw)
    sha1hash = stream.hashBytes(sha1.New(), raw)
    sha256hash = stream.hashBytes(sha256.New(), raw)
  }
  return int(copyLen), mimeType, md5hash, sha1hash, sha256hash, err
}

func (stream *ArtifactStream) Read() io.Reader {
  fmt.Printf("streamLen = %d", len(stream.Content))
  return base64.NewDecoder(base64.StdEncoding, strings.NewReader(stream.Content))
}
