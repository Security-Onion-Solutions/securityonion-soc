// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package navigator

var DefaultNavigatorLayer = `{
	"name": "Detections Coverage",
	"versions": {
		"attack": "16",
		"navigator": "5.1.0",
		"layer": "4.5"
	},
	"domain": "enterprise-attack",
	"description": "",
	"filters": {
		"platforms": [
			"Linux",
			"macOS",
			"Windows",
			"Network",
			"PRE",
			"Containers",
			"Office 365",
			"SaaS",
			"Google Workspace",
			"IaaS",
			"Azure AD"
		]
	},
	"sorting": 0,
	"layout": {
		"layout": "side",
		"aggregateFunction": "average",
		"showID": false,
		"showName": true,
		"showAggregateScores": false,
		"countUnscored": false,
		"expandedSubtechniques": "none"
	},
	"hideDisabled": false,
	"techniques": [],
	"gradient": {
		"colors": [
			"#ffffff00",
			"#66b1ffff"
		],
		"minValue": 0,
		"maxValue": 100
	},
	"legendItems": [],
	"metadata": [],
	"links": [],
	"showTacticRowBackground": false,
	"tacticRowBackground": "#dddddd",
	"selectTechniquesAcrossTactics": true,
	"selectSubtechniquesWithParent": false,
	"selectVisibleTechniques": false
}`
