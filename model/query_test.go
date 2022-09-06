// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGroupWithQuotes(tester *testing.T) {
	query := NewQuery()
	err := query.Parse(`foo:"bar" | groupby "complex field" "another complex field"`)
	assert.NoError(tester, err)
	groupbySegment := query.NamedSegment(SegmentKind_GroupBy).(*GroupBySegment)
	fields := groupbySegment.Fields()
	assert.Len(tester, fields, 2)
	assert.Equal(tester, `"complex field"`, fields[0])
	assert.Equal(tester, `"another complex field"`, fields[1])
}

func TestRawFields(tester *testing.T) {
	query := NewQuery()
	err := query.Parse(`foo:"bar" | groupby "complex field" "another complex field"`)
	assert.NoError(tester, err)
	groupbySegment := query.NamedSegment(SegmentKind_GroupBy).(*GroupBySegment)
	rawFields := groupbySegment.RawFields()
	assert.Len(tester, rawFields, 2)
	assert.Equal(tester, "complex field", rawFields[0])
	assert.Equal(tester, "another complex field", rawFields[1])
}

func validateQuery(tester *testing.T, args ...string) {
	query := NewQuery()
	err := query.Parse(args[0])
	expected := args[0]
	if len(args) > 1 {
		expected = args[1]
	}
	actual := query.String()
	if err != nil {
		actual = err.Error()
	}
	assert.Equal(tester, expected, actual)
}

func TestQueries(tester *testing.T) {
	validateQuery(tester, "abc")
	validateQuery(tester, "abc def")
	validateQuery(tester, "abc:'def'", "abc: 'def'")
	validateQuery(tester, "   abc0   def  ", "abc0 def")
	validateQuery(tester, "'abc1' def")
	validateQuery(tester, "'abc2 def'")
	validateQuery(tester, `"abc3' def"`)

	validateQuery(tester, "abc5,def", "abc5 def")
	validateQuery(tester, "abc def | groupby jkl")
	validateQuery(tester, "abc def | groupby 'jkl'")
	validateQuery(tester, "'abc8 | groupby'")
	validateQuery(tester, "abcA|", "abcA")

	validateQuery(tester, "(abc AND def)")
	validateQuery(tester, "((abc AND def))")
	validateQuery(tester, "((abc AND def:\"ghi\") AND (xyz=\"123\"))")

	validateQuery(tester, "abcA|groupby\njjj", "abcA | groupby jjj")
	validateQuery(tester, "abcA|\ngroupby\tjjj", "abcA | groupby jjj")

	validateQuery(tester, "'abc4 def", "ERROR_QUERY_INVALID__QUOTE_INCOMPLETE")
	validateQuery(tester, "'abc9|", "ERROR_QUERY_INVALID__QUOTE_INCOMPLETE")

	validateQuery(tester, "|", "ERROR_QUERY_INVALID__SEGMENT_EMPTY")
	validateQuery(tester, " |", "ERROR_QUERY_INVALID__SEGMENT_EMPTY")
	validateQuery(tester, " | abc", "ERROR_QUERY_INVALID__SEGMENT_EMPTY")
	validateQuery(tester, "abc6 def | |", "ERROR_QUERY_INVALID__SEGMENT_EMPTY")
	validateQuery(tester, "abc7 def || ", "ERROR_QUERY_INVALID__SEGMENT_EMPTY")

	validateQuery(tester, "abc7 def ) ", "ERROR_QUERY_INVALID__GROUP_NOT_STARTED")
	validateQuery(tester, "abc7 def () ", "ERROR_QUERY_INVALID__GROUP_EMPTY")
	validateQuery(tester, "abc (d e f", "ERROR_QUERY_INVALID__GROUP_INCOMPLETE")
	validateQuery(tester, "abc (d e f | ghi 'jkl' | mno", "ERROR_QUERY_INVALID__GROUP_INCOMPLETE")

	validateQuery(tester, "abc (d e f) | groupby 'jkl' | mno", "ERROR_QUERY_INVALID__SEGMENT_UNSUPPORTED")

	validateQuery(tester, "", "ERROR_QUERY_INVALID__SEARCH_MISSING")
	validateQuery(tester, " ", "ERROR_QUERY_INVALID__SEARCH_MISSING")

	validateQuery(tester, "abcA|groupby", "ERROR_QUERY_INVALID__GROUPBY_TERMS_MISSING")
	validateQuery(tester, "abcA|groupby ", "ERROR_QUERY_INVALID__GROUPBY_TERMS_MISSING")

	validateQuery(tester, "abcA|sortby\njjj, lll", "abcA | sortby jjj lll")
	validateQuery(tester, "abcA|\nsortby\tjjj", "abcA | sortby jjj")

	validateQuery(tester, "abcA|sortby", "ERROR_QUERY_INVALID__SORTBY_TERMS_MISSING")
	validateQuery(tester, "abcA|sortby ", "ERROR_QUERY_INVALID__SORTBY_TERMS_MISSING")
}

func validateGroup(tester *testing.T, orig string, groupIdx int, group string, expected string) {
	query := NewQuery()
	query.Parse(orig)
	actual, err := query.Group(groupIdx, group)
	if err != nil {
		actual = err.Error()
	}
	assert.Equal(tester, expected, actual)
}

func TestGroup(tester *testing.T) {
	validateGroup(tester, "a", 0, "b", `a | groupby "b"`)
	validateGroup(tester, "a|groupby b", 0, "c", `a | groupby b "c"`)
	validateGroup(tester, "a|groupby b", 0, "b", `a | groupby b`)
	validateGroup(tester, "a|groupby b", 1, "c", `a | groupby b | groupby "c"`)
	validateGroup(tester, "a|groupby b", 2, "c", `a | groupby b | groupby "c"`)
	validateGroup(tester, "a|groupby b", -2, "c", `a | groupby b | groupby "c"`)
}

func validateSort(tester *testing.T, orig string, sort string, expected string) {
	query := NewQuery()
	query.Parse(orig)
	actual, err := query.Sort(sort)
	if err != nil {
		actual = err.Error()
	}
	assert.Equal(tester, expected, actual)
}

func TestSort(tester *testing.T) {
	validateSort(tester, "a", "b", `a | sortby "b"`)
	validateSort(tester, "a|sortby b", "c", `a | sortby b "c"`)
	validateSort(tester, "a|sortby b", "b", "a | sortby b")
}

func validateFilter(tester *testing.T, orig string, key string, value string, scalar bool, mode string, condense bool, expected string) {
	query := NewQuery()
	query.Parse(orig)
	actual, err := query.Filter(key, value, scalar, mode, condense)
	if err != nil {
		actual = err.Error()
	}
	assert.Equal(tester, expected, actual)
}

func TestFilter(tester *testing.T) {
	validateFilter(tester, "a", "b", "c", false, FILTER_INCLUDE, false, "a AND b:\"c\"")
	validateFilter(tester, "a", "b", "c", false, FILTER_EXCLUDE, false, "a AND NOT b:\"c\"")
	validateFilter(tester, "", "b", "c", false, FILTER_INCLUDE, false, "b:\"c\"")
	validateFilter(tester, "", "b", "1", true, FILTER_INCLUDE, false, "b:1")
	validateFilter(tester, "(a:1 OR c:2) | groupby z", "b", "1", true, FILTER_EXACT, false, "b:1 | groupby z")
	validateFilter(tester, "(a:1 OR c:2) | groupby z", "b", "1", true, FILTER_DRILLDOWN, false, "(a:1 OR c:2) AND b:1")
	validateFilter(tester, "a", "soc_b", "1", true, FILTER_INCLUDE, false, "a AND _b:1")
	validateFilter(tester, "a:1", "a", "2", true, FILTER_INCLUDE, false, "a:1 AND a:2")
	validateFilter(tester, "a: 1", "a", "2", true, FILTER_INCLUDE, false, "a: 1 AND a:2")
	validateFilter(tester, "NOT a:1", "a", "2", true, FILTER_EXCLUDE, false, "NOT a:1 AND NOT a:2")
	validateFilter(tester, "a:1 OR b:1", "c", "3", true, FILTER_INCLUDE, true, "(a:1 OR b:1) AND c:3")
}

func TestIsScalar(tester *testing.T) {
	assert.True(tester, IsScalar(1))
	assert.True(tester, IsScalar(false))
	assert.True(tester, IsScalar(true))
	assert.True(tester, IsScalar(22.1))
	assert.False(tester, IsScalar("str"))
}

func TestRemoveTermsWith(tester *testing.T) {
	segment := NewSearchSegmentEmpty()
	assert.Zero(tester, segment.RemoveTermsWith("hello"), "Expected no terms removed on empty segment")
	segment.AddFilter("hello", "a", false, false, false)
	assert.Equal(tester, 1, segment.RemoveTermsWith("hello"))
	assert.Zero(tester, segment.RemoveTermsWith("hello"), "Expected no terms removed on already removed term")
	segment.AddFilter("there", "b", false, false, false)
	assert.Zero(tester, segment.RemoveTermsWith("hello"), "Expected no terms removed on unmatched term")
	segment.AddFilter("and", "c", false, false, false)
	segment.AddFilter("goodbye", "d", false, false, false)
	assert.Equal(tester, 2, segment.RemoveTermsWith("e"))
}

func TestNamedSegments(tester *testing.T) {
	query := NewQuery()
	t1, _ := NewQueryTerm("t1")
	t2, _ := NewQueryTerm("t2")
	t3, _ := NewQueryTerm("t3")
	terms := []*QueryTerm{t1, t2}
	segment1, _ := NewGroupBySegment(terms)
	query.AddSegment(segment1)
	terms = []*QueryTerm{t3}
	segment2, _ := NewGroupBySegment(terms)
	query.AddSegment(segment2)
	segments := query.NamedSegments(SegmentKind_GroupBy)
	assert.Equal(tester, 2, len(segments))
	assert.Equal(tester, segment1, segments[0])
	assert.Equal(tester, segment2, segments[1])
}
