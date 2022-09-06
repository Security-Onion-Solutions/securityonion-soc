// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
  "errors"
  "strings"
)

const FILTER_INCLUDE = "INCLUDE"
const FILTER_EXCLUDE = "EXCLUDE"
const FILTER_EXACT = "EXACT"
const FILTER_DRILLDOWN = "DRILLDOWN"

func IsScalar(value interface{}) bool {
  scalar := false
  switch value.(type) {
  case bool, int, int32, int64, float32, float64:
    scalar = true
  }
  return scalar
}

type QueryTerm struct {
  Raw     string
  Quoted  bool
  Quote   rune
  Grouped bool
}

func sanitize(field string) string {
  field = strings.Trim(field, " \n\t")
  return field
}

func NewQueryTerm(str string) (*QueryTerm, error) {
  field := sanitize(str)
  if len(field) == 0 {
    return nil, errors.New("ERROR_QUERY_INVALID__TERM_MISSING")
  }

  term := &QueryTerm{
    Raw: sanitize(field),
  }
  return term, nil
}

func (term *QueryTerm) String() string {
  var builder strings.Builder
  if term.Grouped {
    builder.WriteString("(")
  }
  if term.Quoted {
    builder.WriteRune(term.Quote)
  }
  builder.WriteString(term.Raw)
  if term.Quoted {
    builder.WriteRune(term.Quote)
  }
  if term.Grouped {
    builder.WriteString(")")
  }
  return builder.String()
}

type QuerySegment interface {
  String() string
  Kind() string
}

type BaseSegment struct {
  terms []*QueryTerm
}

func (segment *BaseSegment) Terms() []*QueryTerm {
  return segment.terms
}

const SegmentKind_Search = "search"
const SegmentKind_GroupBy = "groupby"
const SegmentKind_SortBy = "sortby"

func NewSegment(kind string, terms []*QueryTerm) (QuerySegment, error) {
  switch kind {
  case SegmentKind_Search:
    return NewSearchSegment(terms)
  case SegmentKind_GroupBy:
    return NewGroupBySegment(terms)
  case SegmentKind_SortBy:
    return NewSortBySegment(terms)
  }
  return nil, errors.New("ERROR_QUERY_INVALID__SEGMENT_UNSUPPORTED")
}

func (segment *BaseSegment) TermsAsString() string {
  var segmentBuilder strings.Builder
  for termIdx, term := range segment.terms {
    if termIdx > 0 {
      segmentBuilder.WriteString(" ")
    }
    segmentBuilder.WriteString(term.String())
  }
  return segmentBuilder.String()
}

func (segment *BaseSegment) Clear() {
  segment.terms = make([]*QueryTerm, 0, 0)
}

func (segment *BaseSegment) RemoveTermsWith(raw string) int {
  removed := 0
  foundTerm := true
  for foundTerm {
    foundTerm = false
    for idx, term := range segment.terms {
      if strings.Contains(term.Raw, raw) {
        segment.terms = append(segment.terms[:idx], segment.terms[idx+1:]...)
        foundTerm = true
        removed++
        break
      }
    }
  }
  return removed
}

func (segment *BaseSegment) RawFields() []string {
  fields := make([]string, 0, 0)
  for _, field := range segment.terms {
    fields = append(fields, field.Raw)
  }
  return fields
}

func (segment *BaseSegment) Fields() []string {
  fields := make([]string, 0, 0)
  for _, field := range segment.terms {
    fields = append(fields, field.String())
  }
  return fields
}

func (segment *BaseSegment) AddField(field string) error {
  alreadyIncluded := false
  for _, term := range segment.terms {
    if term.Raw == field {
      alreadyIncluded = true
    }
  }
  var err error
  if !alreadyIncluded {
    term, err := NewQueryTerm(field)
    if err == nil {
      term.Quoted = true
      term.Quote = '"'
      segment.terms = append(segment.terms, term)
    }
  }
  return err
}

type SearchSegment struct {
  *BaseSegment
}

func NewSearchSegmentEmpty() *SearchSegment {
  return &SearchSegment{
    &BaseSegment{
      terms: make([]*QueryTerm, 0, 0),
    },
  }
}

func NewSearchSegment(terms []*QueryTerm) (*SearchSegment, error) {
  if terms == nil || len(terms) == 0 {
    return nil, errors.New("ERROR_QUERY_INVALID__SEARCH_TERMS_MISSING")
  }

  segment := NewSearchSegmentEmpty()
  segment.terms = terms

  return segment, nil
}

func (segment *SearchSegment) Kind() string {
  return SegmentKind_Search
}

func (segment *SearchSegment) String() string {
  return segment.TermsAsString()
}

func (segment *SearchSegment) escape(value string) string {
  value = strings.ReplaceAll(value, "\\", "\\\\")
  value = strings.ReplaceAll(value, "\"", "\\\"")
  return value
}

func (segment *SearchSegment) AddFilter(field string, value string, scalar bool, inclusive bool, condense bool) error {
  // This flag can be adjust to true once the query parser is more robust and better able to determine
  // when an inclusive filter already exists in a query, so that two inclusive filters are not allowed
  // to exist in a query together. For example, the following filters will prevent any matches:
  // Ex: foo:1 AND foo:2
  alreadyFiltered := false

  if len(field) > 4 && field[:4] == "soc_" {
    field = field[3:]
  }

  if condense {
    // Combine existing terms into a single grouped term
    condensed, _ := NewQueryTerm(segment.String())
    condensed.Grouped = true
    segment.Clear()
    segment.terms = append(segment.terms, condensed)
  }

  var err error
  if !alreadyFiltered {
    if len(segment.terms) > 0 {
      term, _ := NewQueryTerm("AND")
      segment.terms = append(segment.terms, term)
    }
    if !inclusive {
      term, _ := NewQueryTerm("NOT")
      segment.terms = append(segment.terms, term)
    }

    var strBuilder strings.Builder
    if len(field) > 0 {
      strBuilder.WriteString(field)
      strBuilder.WriteRune(':')
    }
    if !scalar {
      strBuilder.WriteRune('"')
      strBuilder.WriteString(segment.escape(value))
      strBuilder.WriteRune('"')
    } else {
      strBuilder.WriteString(value)
    }

    term, err := NewQueryTerm(strBuilder.String())
    if err == nil {
      segment.terms = append(segment.terms, term)
    }
  }
  return err
}

type GroupBySegment struct {
  *BaseSegment
}

func NewGroupBySegmentEmpty() *GroupBySegment {
  return &GroupBySegment{
    &BaseSegment{
      terms: make([]*QueryTerm, 0, 0),
    },
  }
}

func NewGroupBySegment(terms []*QueryTerm) (*GroupBySegment, error) {
  if terms == nil || len(terms) == 0 {
    return nil, errors.New("ERROR_QUERY_INVALID__GROUPBY_TERMS_MISSING")
  }

  segment := NewGroupBySegmentEmpty()
  segment.terms = terms

  return segment, nil
}

func (segment *GroupBySegment) Kind() string {
  return SegmentKind_GroupBy
}

func (segment *GroupBySegment) String() string {
  return segment.Kind() + " " + segment.TermsAsString()
}

type SortBySegment struct {
  *BaseSegment
}

func NewSortBySegmentEmpty() *SortBySegment {
  return &SortBySegment{
    &BaseSegment{
      terms: make([]*QueryTerm, 0, 0),
    },
  }
}

func NewSortBySegment(terms []*QueryTerm) (*SortBySegment, error) {
  if terms == nil || len(terms) == 0 {
    return nil, errors.New("ERROR_QUERY_INVALID__SORTBY_TERMS_MISSING")
  }

  segment := NewSortBySegmentEmpty()
  segment.terms = terms

  return segment, nil
}

func (segment *SortBySegment) Kind() string {
  return SegmentKind_SortBy
}

func (segment *SortBySegment) String() string {
  return segment.Kind() + " " + segment.TermsAsString()
}

type Query struct {
  Segments []QuerySegment
}

func NewQuery() *Query {
  return &Query{
    Segments: make([]QuerySegment, 0, 0),
  }
}

func (query *Query) NamedSegment(name string) QuerySegment {
  for _, segment := range query.Segments {
    if segment.Kind() == name {
      return segment
    }
  }
  return nil
}

func (query *Query) NamedSegments(name string) []QuerySegment {
  segments := make([]QuerySegment, 0, 0)
  for _, segment := range query.Segments {
    if segment.Kind() == name {
      segments = append(segments, segment)
    }
  }
  return segments
}

func (query *Query) AddSegment(segment QuerySegment) {
  query.Segments = append(query.Segments, segment)
}

func (query *Query) RemoveSegment(name string) QuerySegment {
  for idx, segment := range query.Segments {
    if segment.Kind() == name {
      query.Segments = append(query.Segments[:idx], query.Segments[idx+1:]...)
      return segment
    }
  }
  return nil
}

func (query *Query) Parse(str string) error {
  currentSegmentTerms := make([]*QueryTerm, 0, 0)
  currentSegmentKind := SegmentKind_Search
  var currentTermBuilder strings.Builder
  escaping := false
  quoting := false
  grouping := 0
  quotingChar := ' '
  for _, ch := range str {
    if !quoting {
      if grouping == 0 {
        if !escaping && ch == '"' || ch == '\'' {
          if currentTermBuilder.Len() > 0 {
            term, err := NewQueryTerm(currentTermBuilder.String())
            if err != nil {
              return err
            }
            currentSegmentTerms = append(currentSegmentTerms, term)
            currentTermBuilder.Reset()
          }
          quoting = true
          quotingChar = ch
        } else if !escaping && ch == '|' {
          if currentTermBuilder.Len() > 0 {
            term, err := NewQueryTerm(currentTermBuilder.String())
            if err != nil {
              return err
            }
            currentSegmentTerms = append(currentSegmentTerms, term)
            currentTermBuilder.Reset()
          }
          if len(currentSegmentTerms) == 0 {
            return errors.New("ERROR_QUERY_INVALID__SEGMENT_EMPTY")
          }
          if currentSegmentKind == "" {
            currentSegmentKind = currentSegmentTerms[0].String()
            currentSegmentTerms = currentSegmentTerms[1:]
          }
          segment, err := NewSegment(currentSegmentKind, currentSegmentTerms)
          if err != nil {
            return err
          }
          query.AddSegment(segment)
          currentSegmentKind = ""
          currentSegmentTerms = make([]*QueryTerm, 0, 0)
        } else if !escaping && (ch == ' ' || ch == ',' || ch == '\n' || ch == '\t') {
          if currentTermBuilder.Len() > 0 {
            term, err := NewQueryTerm(currentTermBuilder.String())
            if err != nil {
              return err
            }
            currentSegmentTerms = append(currentSegmentTerms, term)
            currentTermBuilder.Reset()
          }
        } else if !escaping && ch == '(' {
          grouping++
        } else if !escaping && ch == ')' {
          return errors.New("ERROR_QUERY_INVALID__GROUP_NOT_STARTED")
        } else {
          currentTermBuilder.WriteRune(ch)
        }
      } else if !escaping && ch == ')' && grouping == 1 {
        if currentTermBuilder.Len() == 0 {
          return errors.New("ERROR_QUERY_INVALID__GROUP_EMPTY")
        }
        term, err := NewQueryTerm(currentTermBuilder.String())
        if err != nil {
          return err
        }
        term.Grouped = true
        currentSegmentTerms = append(currentSegmentTerms, term)
        currentTermBuilder.Reset()
        grouping = 0
      } else {
        if ch == '(' {
          grouping++
        } else if ch == ')' {
          grouping--
        }
        currentTermBuilder.WriteRune(ch)
      }
    } else if !escaping && ch == quotingChar {
      term, err := NewQueryTerm(currentTermBuilder.String())
      if err != nil {
        return err
      }
      term.Quoted = quoting
      term.Quote = quotingChar
      currentSegmentTerms = append(currentSegmentTerms, term)
      currentTermBuilder.Reset()
      quoting = false
    } else {
      currentTermBuilder.WriteRune(ch)
    }
    if !escaping && ch == '\\' {
      escaping = true
    } else {
      escaping = false
    }
  }
  if quoting {
    return errors.New("ERROR_QUERY_INVALID__QUOTE_INCOMPLETE")
  }
  if grouping > 0 {
    return errors.New("ERROR_QUERY_INVALID__GROUP_INCOMPLETE")
  }
  if currentTermBuilder.Len() > 0 {
    term, err := NewQueryTerm(currentTermBuilder.String())
    if err != nil {
      return err
    }
    term.Quoted = quoting
    term.Grouped = grouping > 0
    term.Quote = quotingChar
    currentSegmentTerms = append(currentSegmentTerms, term)
  }
  if len(currentSegmentTerms) > 0 {
    if currentSegmentKind == "" {
      currentSegmentKind = currentSegmentTerms[0].String()
      currentSegmentTerms = currentSegmentTerms[1:]
    }
    segment, err := NewSegment(currentSegmentKind, currentSegmentTerms)
    if err != nil {
      return err
    }
    query.AddSegment(segment)
  }

  if len(query.Segments) == 0 {
    return errors.New("ERROR_QUERY_INVALID__SEARCH_MISSING")
  }

  return nil
}

func (query *Query) String() string {
  var queryBuilder strings.Builder
  for idx, segment := range query.Segments {
    if idx > 0 {
      queryBuilder.WriteString(" | ")
    }
    queryBuilder.WriteString(segment.String())
  }
  return queryBuilder.String()
}

func (query *Query) Filter(field string, value string, scalar bool, mode string, condense bool) (string, error) {
  var err error

  segment := query.NamedSegment(SegmentKind_Search)
  if segment == nil {
    segment = NewSearchSegmentEmpty()
    query.AddSegment(segment)
  }
  searchSegment := segment.(*SearchSegment)

  if mode == FILTER_EXACT {
    searchSegment.Clear()
  }

  include := mode != FILTER_EXCLUDE
  err = searchSegment.AddFilter(field, value, scalar, include, condense)

  if mode == FILTER_DRILLDOWN {
    query.RemoveSegment(SegmentKind_GroupBy)
  }

  return query.String(), err
}

func (query *Query) Group(segmentIdx int, field string) (string, error) {
  var err error
  var groupBySegment *GroupBySegment

  segments := query.NamedSegments(SegmentKind_GroupBy)
  if segmentIdx < 0 || len(segments) <= segmentIdx {
    groupBySegment = NewGroupBySegmentEmpty()
    query.AddSegment(groupBySegment)
  } else {
    groupBySegment = segments[segmentIdx].(*GroupBySegment)
  }
  err = groupBySegment.AddField(field)

  return query.String(), err
}

func (query *Query) Sort(field string) (string, error) {
  var err error

  segment := query.NamedSegment(SegmentKind_SortBy)
  if segment == nil {
    segment = NewSortBySegmentEmpty()
    query.AddSegment(segment)
  }
  sortBySegment := segment.(*SortBySegment)
  err = sortBySegment.AddField(field)

  return query.String(), err
}
