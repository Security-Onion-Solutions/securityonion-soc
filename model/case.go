// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package model

import (
  "bytes"
  "encoding/base64"
  "fmt"
  "io"
  "math"
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

func (stream *ArtifactStream) Write(reader io.Reader) (int, string, error) {
  var buffer bytes.Buffer
  var mimeType string
  b64 := base64.NewEncoder(base64.StdEncoding, &buffer)
  copyLen, err := io.Copy(b64, reader)

  if err == nil {
    b64.Close()
    stream.Content = buffer.String()
    preview := stream.Content[:int64(math.Min(1024, float64(copyLen)))]
    previewDecoded, _ := base64.StdEncoding.DecodeString(preview)
    mimeType = http.DetectContentType(previewDecoded)
  }
  return int(copyLen), mimeType, err
}

func (stream *ArtifactStream) Read() io.Reader {
  fmt.Printf("streamLen = %d", len(stream.Content))
  return base64.NewDecoder(base64.StdEncoding, strings.NewReader(stream.Content))
}
