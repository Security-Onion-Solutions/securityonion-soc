package model

import (
	"fmt"
	"strconv"
)

type RuleRepo struct {
	Repo      string
	License   string
	Folder    *string
	Community bool
}

func GetReposDefault(cfg map[string]interface{}, field string, dflt []*RuleRepo) ([]*RuleRepo, error) {
	cfgInter, ok := cfg[field]
	if !ok {
		// config doesn't have any rulesRepos, no error, return defaults
		return dflt, nil
	}

	repoMaps, ok := cfgInter.([]interface{})
	if !ok {
		return nil, fmt.Errorf(`top level config value "%s" is not an array of objects`, field)
	}

	repos := make([]*RuleRepo, 0, len(repoMaps))

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
		if !ok {
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

		r := &RuleRepo{
			Repo:      repo,
			License:   license,
			Community: isCommunity,
		}

		folder, ok := obj["folder"].(string)
		if ok {
			r.Folder = &folder
		}

		repos = append(repos, r)
	}

	return repos, nil
}
