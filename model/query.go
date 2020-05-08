package model

import (
	"errors"
	"strings"
)

type QueryTerm struct {
	Raw   			string
	Quoted			bool
	Quote				rune
	Grouped			bool
}

func sanitize(field string) string {
	field = strings.Trim(field, " \n\t")
	return field
}

func NewQueryTerm(str string) (*QueryTerm, error) {
	field := sanitize(str)
	if len(field) == 0 {
		return nil, errors.New("QUERY_INVALID__TERM_MISSING")
	}
	
  term := &QueryTerm {
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
	String()		string
	Kind()			string
}
	
type BaseSegment struct {
	terms     []*QueryTerm
}

const SegmentKind_Search = "search"
const SegmentKind_GroupBy = "groupby"

func NewSegment(kind string, terms []*QueryTerm) (QuerySegment, error) {
	switch kind {
	case SegmentKind_Search: return NewSearchSegment(terms)
	case SegmentKind_GroupBy: return NewGroupBySegment(terms)
	}
	return nil, errors.New("QUERY_INVALID__SEGMENT_UNSUPPORTED")
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

type SearchSegment struct {
	*BaseSegment
}

func NewSearchSegmentEmpty() *SearchSegment {
	return &SearchSegment {
		&BaseSegment {
			terms: make([]*QueryTerm, 0, 0),
		},
	}
}

func NewSearchSegment(terms []*QueryTerm) (*SearchSegment, error) {
	if terms == nil || len(terms) == 0 {
		return nil, errors.New("QUERY_INVALID__SEARCH_TERMS_MISSING")
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

func (segment *SearchSegment) AddFilter(field string, value string, inclusive bool) error {
	alreadyFiltered := false
	for _, term := range segment.terms {
		if term.String() == field {
			alreadyFiltered = true
		}
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
		term, err := NewQueryTerm(field + ":\"" + value + "\"")
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
	return &GroupBySegment {
		&BaseSegment {
			terms: make([]*QueryTerm, 0, 0),
		},
	}
}

func NewGroupBySegment(terms []*QueryTerm) (*GroupBySegment, error) {
	if terms == nil || len(terms) == 0 {
		return nil, errors.New("QUERY_INVALID__GROUPBY_TERMS_MISSING")
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

func (segment *GroupBySegment) Fields() []string {
	fields := make([]string, 0, 0)
	for _, field := range segment.terms {
		fields = append(fields, field.String())
	}
	return fields
}

func (segment *GroupBySegment) AddGrouping(group string) error {
	fields := segment.Fields()
	alreadyGrouped := false
	for _, field := range fields {
		if field == group {
			alreadyGrouped = true
		}
	}
	var err error
	if !alreadyGrouped {
		term, err := NewQueryTerm(group)
		if err == nil {
			segment.terms = append(segment.terms, term)
		}
	}
	return err
}

type Query struct {
	Segments    []QuerySegment
}

func NewQuery() *Query {
  return &Query {
    Segments: make([]QuerySegment, 0, 0),
  }
}

func (query *Query) NamedSegment(name string) QuerySegment {
	for _, segment := range query.Segments {
		if segment.Kind() == name {
			return segment;
		}
	}
	return nil
}

func (query *Query) Parse(str string) error {
	currentSegmentTerms := make([]*QueryTerm, 0, 0)
	currentSegmentKind := SegmentKind_Search
	var currentTermBuilder strings.Builder
	quoting := false
	grouping := false
  quotingChar := ' '
  for _, ch := range str {
    if !quoting {
			if !grouping {
				if ch == '"' || ch == '\'' {
					quoting = true
					quotingChar = ch
				} else if ch == '|' {
					if currentTermBuilder.Len() > 0 {
						term, err := NewQueryTerm(currentTermBuilder.String())
						if err != nil {
							return err
						}
						currentSegmentTerms = append(currentSegmentTerms, term)
						currentTermBuilder.Reset()
					}
					if len(currentSegmentTerms) == 0 {
						return errors.New("QUERY_INVALID__SEGMENT_EMPTY")
					}
					if currentSegmentKind == "" {
						currentSegmentKind = currentSegmentTerms[0].String()
						currentSegmentTerms = currentSegmentTerms[1:]
					}
					segment, err := NewSegment(currentSegmentKind, currentSegmentTerms)
					if err != nil {
						return err
					}
					query.Segments = append(query.Segments, segment)
					currentSegmentKind = ""
					currentSegmentTerms = make([]*QueryTerm, 0, 0)
				} else if (ch == ' ' || ch == ',' || ch == '\n' || ch == '\t') {
					if currentTermBuilder.Len() > 0 {
						term, err := NewQueryTerm(currentTermBuilder.String())
						if err != nil {
							return err
						}
						currentSegmentTerms = append(currentSegmentTerms, term)
						currentTermBuilder.Reset()
					}
				} else if ch == '(' {
					grouping = true
				} else if ch == ')' {
					return errors.New("QUERY_INVALID__GROUP_NOT_STARTED")	
				} else {
					currentTermBuilder.WriteRune(ch)
				}
			} else if ch == ')' {
				if currentTermBuilder.Len() ==  0 {
					return errors.New("QUERY_INVALID__GROUP_EMPTY")	
				}
				term, err := NewQueryTerm(currentTermBuilder.String())
				if err != nil {
					return err
				}
				term.Grouped = grouping
				currentSegmentTerms = append(currentSegmentTerms, term)
				currentTermBuilder.Reset()
				grouping = false
			} else {
				currentTermBuilder.WriteRune(ch)
			}
    } else if ch == quotingChar {
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
	}
	if quoting {
		return errors.New("QUERY_INVALID__QUOTE_INCOMPLETE")	
	}
	if grouping {
		return errors.New("QUERY_INVALID__GROUP_INCOMPLETE")	
	}
  if currentTermBuilder.Len() > 0 {
		term, err := NewQueryTerm(currentTermBuilder.String())
		if err != nil {
			return err
		}
		term.Quoted = quoting
		term.Grouped = grouping
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
		query.Segments = append(query.Segments, segment)
	}

	if len(query.Segments) == 0 {
		return errors.New("QUERY_INVALID__SEARCH_MISSING")
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

func (query *Query) Filter(field string, value string, include bool) (string, error) {
	var err error

	segment := query.NamedSegment(SegmentKind_Search)
	if segment == nil {
		segment = NewSearchSegmentEmpty()
		query.Segments = append(query.Segments, segment)
	}
	searchSegment := segment.(*SearchSegment)
	err = searchSegment.AddFilter(field, value, include)
	
	return query.String(), err
}

func (query *Query) Group(field string) (string, error) {
	var err error

	segment := query.NamedSegment(SegmentKind_GroupBy)
	if segment == nil {
		segment = NewGroupBySegmentEmpty()
		query.Segments = append(query.Segments, segment)
	}
	groupBySegment := segment.(*GroupBySegment)
	err = groupBySegment.AddGrouping(field)
	
	return query.String(), err
}