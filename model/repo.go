// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"fmt"
	"strconv"
)

type Repo struct {
	RepoUrl     string `json:"repo"`
	Branch      *string
	License     string
	Folder      *string
	Community   bool
	RulesetName string
}

func GetReposDefault(cfg map[string]interface{}, field string, licenseRequired bool, dflt []*Repo) ([]*Repo, error) {
	cfgInter, ok := cfg[field]
	if !ok {
		// config doesn't have any rulesRepos, no error, return defaults
		return dflt, nil
	}

	repoMaps, ok := cfgInter.([]interface{})
	if !ok {
		return nil, fmt.Errorf(`top level config value "%s" is not an array of objects`, field)
	}

	repos := make([]*Repo, 0, len(repoMaps))

	for _, repoMap := range repoMaps {
		obj, ok := repoMap.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf(`"%s" entry is not an object`, field)
		}

		repo, ok := obj["repo"].(string)
		if !ok {
			return nil, fmt.Errorf(`missing "repo" link from "%s" entry`, field)
		}

		license, ok := obj["license"].(string)
		if !ok && licenseRequired {
			return nil, fmt.Errorf(`missing "license" from "%s" entry`, field)
		}

		isCommunity := false

		community := obj["community"]
		switch c := community.(type) {
		case bool:
			isCommunity = c
		case int:
			isCommunity = c != 0
		case string:
			var err error
			isCommunity, err = strconv.ParseBool(c)
			if err != nil {
				isCommunity = false
			}
		}

		rulesetName, _ := obj["rulesetName"].(string)

		r := &Repo{
			RepoUrl:     repo,
			License:     license,
			Community:   isCommunity,
			RulesetName: rulesetName,
		}

		folder, ok := obj["folder"].(string)
		if ok {
			r.Folder = &folder
		}

		branch, ok := obj["branch"].(string)
		if ok {
			r.Branch = &branch
		}

		repos = append(repos, r)
	}

	return repos, nil
}
