package model

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/apex/log"
)

type CustomRuleset struct {
	Community  bool   `json:"community"`
	License    string `json:"license"`
	Url        string `json:"url"`
	TargetFile string `json:"target-file"`
	File       string `json:"file"`
	Ruleset    string `json:"ruleset"`
}

func GetCustomRulesetsDefault(cfg map[string]interface{}, field string, dflt []*CustomRuleset) ([]*CustomRuleset, error) {
	cfgInter, ok := cfg[field]
	if !ok {
		// config doesn't have any customRulesets, no error, return defaults
		return dflt, nil
	}

	ruleMaps, ok := cfgInter.([]interface{})
	if !ok {
		return nil, fmt.Errorf(`top level config value "%s" is not an array of objects`, field)
	}

	rulesets := make([]*CustomRuleset, 0, len(ruleMaps))

	for _, item := range ruleMaps {
		obj, ok := item.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf(`"%s" entry is not an object`, field)
		}

		file, _ := obj["file"].(string)
		url, _ := obj["url"].(string)
		target, _ := obj["target-file"].(string)

		if file == "" && url == "" && target == "" {
			return nil, fmt.Errorf(`missing "file" or "url"+"target-file" from "%s" entry`, field)
		}

		if url != "" && target == "" {
			return nil, fmt.Errorf(`missing "target-file" from "%s" entry`, field)
		}
		if target != "" && url == "" {
			return nil, fmt.Errorf(`missing "url" from "%s" entry`, field)
		}

		ruleset, ok := obj["ruleset"].(string)
		if !ok {
			return nil, fmt.Errorf(`missing "ruleset" from "%s" entry`, field)
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

		ext := filepath.Ext(file)
		if strings.ToLower(ext) != ".rules" {
			log.WithFields(log.Fields{
				"customRulesetFile": file,
			}).Warn("customRulesets file should have a .rules extension")
		}

		r := &CustomRuleset{
			File:       file,
			Url:        url,
			TargetFile: target,
			License:    license,
			Community:  isCommunity,
			Ruleset:    ruleset,
		}

		rulesets = append(rulesets, r)
	}

	return rulesets, nil
}
