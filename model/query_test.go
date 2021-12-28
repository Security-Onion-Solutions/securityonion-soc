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
	"testing"

	"github.com/stretchr/testify/assert"
)

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

	validateQuery(tester, "'abc4 def", "QUERY_INVALID__QUOTE_INCOMPLETE")
	validateQuery(tester, "'abc9|", "QUERY_INVALID__QUOTE_INCOMPLETE")

	validateQuery(tester, "|", "QUERY_INVALID__SEGMENT_EMPTY")
	validateQuery(tester, " |", "QUERY_INVALID__SEGMENT_EMPTY")
	validateQuery(tester, " | abc", "QUERY_INVALID__SEGMENT_EMPTY")
	validateQuery(tester, "abc6 def | |", "QUERY_INVALID__SEGMENT_EMPTY")
	validateQuery(tester, "abc7 def || ", "QUERY_INVALID__SEGMENT_EMPTY")

	validateQuery(tester, "abc7 def ) ", "QUERY_INVALID__GROUP_NOT_STARTED")
	validateQuery(tester, "abc7 def () ", "QUERY_INVALID__GROUP_EMPTY")
	validateQuery(tester, "abc (d e f", "QUERY_INVALID__GROUP_INCOMPLETE")
	validateQuery(tester, "abc (d e f | ghi 'jkl' | mno", "QUERY_INVALID__GROUP_INCOMPLETE")

	validateQuery(tester, "abc (d e f) | groupby 'jkl' | mno", "QUERY_INVALID__SEGMENT_UNSUPPORTED")

	validateQuery(tester, "", "QUERY_INVALID__SEARCH_MISSING")
	validateQuery(tester, " ", "QUERY_INVALID__SEARCH_MISSING")

	validateQuery(tester, "abcA|groupby", "QUERY_INVALID__GROUPBY_TERMS_MISSING")
	validateQuery(tester, "abcA|groupby ", "QUERY_INVALID__GROUPBY_TERMS_MISSING")

	validateQuery(tester, "abcA|sortby\njjj, lll", "abcA | sortby jjj lll")
	validateQuery(tester, "abcA|\nsortby\tjjj", "abcA | sortby jjj")

	validateQuery(tester, "abcA|sortby", "QUERY_INVALID__SORTBY_TERMS_MISSING")
	validateQuery(tester, "abcA|sortby ", "QUERY_INVALID__SORTBY_TERMS_MISSING")
}

func validateGroup(tester *testing.T, orig string, group string, expected string) {
	query := NewQuery()
	query.Parse(orig)
	actual, err := query.Group(group)
	if err != nil {
		actual = err.Error()
	}
	assert.Equal(tester, expected, actual)
}

func TestGroup(tester *testing.T) {
	validateGroup(tester, "a", "b", "a | groupby b")
	validateGroup(tester, "a|groupby b", "c", "a | groupby b c")
	validateGroup(tester, "a|groupby b", "b", "a | groupby b")
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
	validateSort(tester, "a", "b", "a | sortby b")
	validateSort(tester, "a|sortby b", "c", "a | sortby b c")
	validateSort(tester, "a|sortby b", "b", "a | sortby b")
}

func validateFilter(tester *testing.T, orig string, key string, value string, scalar bool, mode string, expected string) {
	query := NewQuery()
	query.Parse(orig)
	actual, err := query.Filter(key, value, scalar, mode)
	if err != nil {
		actual = err.Error()
	}
	assert.Equal(tester, expected, actual)
}

func TestFilter(tester *testing.T) {
	validateFilter(tester, "a", "b", "c", false, FILTER_INCLUDE, "a AND b:\"c\"")
	validateFilter(tester, "a", "b", "c", false, FILTER_EXCLUDE, "a AND NOT b:\"c\"")
	validateFilter(tester, "", "b", "c", false, FILTER_INCLUDE, "b:\"c\"")
	validateFilter(tester, "", "b", "1", true, FILTER_INCLUDE, "b:1")
	validateFilter(tester, "(a:1 OR c:2) | groupby z", "b", "1", true, FILTER_EXACT, "b:1 | groupby z")
	validateFilter(tester, "(a:1 OR c:2) | groupby z", "b", "1", true, FILTER_DRILLDOWN, "(a:1 OR c:2) AND b:1")
	validateFilter(tester, "a", "soc_b", "1", true, FILTER_INCLUDE, "a AND _b:1")
	validateFilter(tester, "a:1", "a", "2", true, FILTER_INCLUDE, "a:1 AND a:2")
	validateFilter(tester, "a: 1", "a", "2", true, FILTER_INCLUDE, "a: 1 AND a:2")
	validateFilter(tester, "NOT a:1", "a", "2", true, FILTER_EXCLUDE, "NOT a:1 AND NOT a:2")
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
	segment.AddFilter("hello", "a", false, false)
	assert.Equal(tester, 1, segment.RemoveTermsWith("hello"))
	assert.Zero(tester, segment.RemoveTermsWith("hello"), "Expected no terms removed on already removed term")
	segment.AddFilter("there", "b", false, false)
	assert.Zero(tester, segment.RemoveTermsWith("hello"), "Expected no terms removed on unmatched term")
	segment.AddFilter("and", "c", false, false)
	segment.AddFilter("goodbye", "d", false, false)
	assert.Equal(tester, 2, segment.RemoveTermsWith("e"))
}
