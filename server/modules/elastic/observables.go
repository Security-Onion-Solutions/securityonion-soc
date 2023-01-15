// Copyright 2020-2022 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package elastic

import (
	"net"
	"net/url"
	"regexp"
)

type ObservableType string

const (
	ObservableIP       ObservableType = "ip"
	ObservableFQDN     ObservableType = "fqdn"
	ObservableDomain   ObservableType = "domain"
	ObservableURL      ObservableType = "url"
	ObservableFilename ObservableType = "filename"
	ObservableURIPath  ObservableType = "uriPath"
	ObservableHash     ObservableType = "hash"
	ObservableOther    ObservableType = "other"
)

// Use a regexp for validtion if it is set, else use the match function.
type matchFunc func(string) bool
type matcher struct {
	exp     *regexp.Regexp
	matcher matchFunc
}
type Observables struct {
	match map[ObservableType]*matcher
	order []ObservableType
}

func NewObservables() Observables {
	match := make(map[ObservableType]*matcher)

	// Perl regexp doesn't work with Golang, besides, IP parse() function is more bullet-proof.
	//obs[ObservableIP] = &matcher{exp: regexp.MustCompile(`/^[0-9a-fA-F:]*([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F:]*$|^(\d{1,3}\.){3}\d{1,3}$/`)}
	match[ObservableIP] = &matcher{matcher: func(s string) bool { return net.ParseIP(s) != nil }}

	// Regexp too simplistic, let Go parse URL and ensure it is a full URL.
	//obs[ObservableURL] = &matcher{exp: regexp.MustCompile(`/^[a-z]+:\/\//`)}
	match[ObservableURL] = &matcher{matcher: func(s string) bool { u, err := url.Parse(s); return err == nil && u.Scheme != "" }}

	// Perl regexp for fqdn not supported in Go, use alternate expression, source:
	// https://www.folkstalk.com/2022/09/golang-regular-expression-to-validate-domain-name-with-code-examples.html
	//obs[ObservableFQDN] = regexp.MustCompile(`/(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$)/`)
	match[ObservableFQDN] = &matcher{exp: regexp.MustCompile(
		`(\b(?:(?:[^.-/]{0,1})[\w-]{1,63}[-]{0,1}[.]{1})+(?:[a-zA-Z]{2,63})\b)`)}
	//`^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|([a-zA-Z0-9][a-zA-Z0-9-_]{1,61}[a-zA-Z0-9]))\.([a-zA-Z]{2,6}|[a-zA-Z0-9-]{2,30}\.[a-zA-Z]{2,3})$`)}

	match[ObservableDomain] = &matcher{exp: regexp.MustCompile(`/^(xn\-\-)?([a-z0-9\-]{1,61}|[a-z0-9\-]{1,30})\.[a-z]{2,}$/`)}

	match[ObservableFilename] = &matcher{exp: regexp.MustCompile(`/(\/)?[\w,\\s-]+\.[A-Za-z]{3}$/`)}
	match[ObservableURIPath] = &matcher{exp: regexp.MustCompile(`/^\/[\w,\s-]/`)}
	match[ObservableHash] = &matcher{exp: regexp.MustCompile(`/^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$|^[0-9a-fA-F]{128}$/`)}
	return Observables{
		match: match,
		order: []ObservableType{
			ObservableIP, ObservableURL, ObservableFilename, ObservableFQDN,
			ObservableDomain, ObservableURIPath, ObservableHash},
	}
}

func (obs Observables) GetType(expr string) ObservableType {
	for _, v := range obs.order {
		match := obs.match[v]
		if match.exp != nil {
			if match.exp.MatchString(expr) {
				return v
			}
		} else if match.matcher(expr) {
			return v
		}
	}
	return ObservableOther
}
