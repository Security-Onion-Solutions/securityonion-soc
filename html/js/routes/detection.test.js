// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js');
require('./detection.js');

let comp;

beforeEach(() => {
	comp = getComponent("detection");
	resetPapi();
	comp.$root.initializeEditor = () => { };
	comp.created();
});

test('extract suricata', () => {
	comp.detect = {
		engine: 'suricata',
		content: '(reference:url,example.com; reference:text,Research;)',
		title: 'test',
	};

	comp.extractSummary();
	expect(comp.extractedSummary).toBe('test');
	comp.extractLogic();
	expect(comp.extractedLogic).toBe('');

	comp.detect = {
		engine: 'suricata',
		content: 'alert any any <> any any (classtype:Summary; reference:url,example.com; reference:text,Research; metadata: created_at 2020-01-01, updated_at 2020-01-02, author Bob;)',
	};
	comp.$route = { params: { id: '123' } };

	comp.extractSummary();
	comp.extractReferences();
	comp.extractLogic();

	expect(comp.extractedSummary).toBe('Summary');
	expect(comp.extractedReferences).toEqual([
		{ type: 'url', text:'example.com', link: 'http://example.com' },
		{ type: 'text', text: 'Research' },
	]);
	expect(comp.extractedLogic).toBe('any any <> any any');
	expect(comp.extractedLogicClass).toBe('language-suricata-logic');
});

test('extract strelka', () => {
	comp.detect = {
		engine: 'strelka',
		content: 'rule Test {\n meta:\n reference1="example.com"\n reference2="example_text"\n date = "2020-01-01";\n author = "Bob";\n condition:\n $a\n }',
		title: 'Test',
		description: 'Example Rule',
	};

	comp.extractLogic();
	expect(comp.extractedLogic).toBe('condition:\n$a\n');

	comp.detect = {
		engine: 'strelka',
		content: 'rule Test {\nmeta:\nreference1="example.com"\nreference2="example_text"\ndate = "2020-01-01";\nauthor = "Bob";\n condition:\n$a\n\n }',
		title: 'Test',
		description: 'Example Rule',
	};

	comp.extractLogic();
	expect(comp.extractedLogic).toBe('condition:\n$a');

	comp.detect = {
		engine: 'strelka',
		content: 'rule Test {\nmeta:\nreference1="example.com"\nreference2="example_text"\ndate = "2020-01-01";\nauthor = "Bob";\nstrings:\n$a = "test"\ncondition:\n$a\n}',
		title: 'Test',
		description: 'Example Rule',
	};
	comp.$route = { params: { id: '123' } };

	comp.extractSummary();
	comp.extractReferences();
	comp.extractLogic();

	expect(comp.extractedSummary).toBe('Example Rule');
	expect(comp.extractedReferences).toEqual([
		{ type: 'url', text: 'example.com', link: 'http://example.com' },
		{ type: 'text', text: 'example_text'},
	]);
	expect(comp.extractedLogic).toBe('strings:\n$a = "test"\ncondition:\n$a');
	expect(comp.extractedLogicClass).toBe('language-yara');
});

test('extract elastalert', () => {
	comp.detect = {
		engine: 'elastalert',
		content: `title: APT29 2018 Phishing Campaign File Indicators\nid: 3a3f81ca-652c-482b-adeb-b1c804727f74\nrelated:\n  - id: 7453575c-a747-40b9-839b-125a0aae324b # ProcessCreation\n    type: derived\nstatus: stable\ndescription: Detects indicators of APT 29 (Cozy Bear) phishing-campaign as reported by mandiant\nreferences:\nauthor: '@41thexplorer'\ndate: 2018/11/20\nmodified: 2023/02/20\ntags:\n  - attack.defense_evasion\n  - attack.t1218.011\n  - detection.emerging_threats\nlogsource:\n  product: windows\n  category: file_event\ndetection:\n  selection:\n    TargetFilename|contains:\n      - 'ds7002.lnk'\n      - 'ds7002.pdf'\n      - 'ds7002.zip'\n    condition: selection\nfalsepositives:\n  - Unlikely\nlevel: critical`,
		title: 'Title',
	};

	comp.extractReferences();
	expect(comp.extractedReferences).toEqual([]);

	comp.detect = {
		engine: 'elastalert',
		content: `title: APT29 2018 Phishing Campaign File Indicators\nid: 3a3f81ca-652c-482b-adeb-b1c804727f74\nrelated:\n  - id: 7453575c-a747-40b9-839b-125a0aae324b # ProcessCreation\n    type: derived\nstatus: stable\ndescription: Detects indicators of APT 29 (Cozy Bear) phishing-campaign as reported by mandiant\nreferences:\n  - https://twitter.com/DrunkBinary/status/1063075530180886529\n  - test_text \nauthor: '@41thexplorer'\ndate: 2018/11/20\nmodified: 2023/02/20\ntags:\n  - attack.defense_evasion\n  - attack.t1218.011\n  - detection.emerging_threats\nlogsource:\n  product: windows\n  category: file_event\ndetection:\n  selection:\n    TargetFilename|contains:\n      - 'ds7002.lnk'\n      - 'ds7002.pdf'\n      - 'ds7002.zip'\n    condition: selection\nfalsepositives:\n  - Unlikely\nlevel: critical`,
		title: 'Title',
	};
	comp.$route = { params: { id: '123' } };

	comp.extractSummary();
	comp.extractReferences();
	comp.extractLogic();

	expect(comp.extractedSummary).toBe('Detects indicators of APT 29 (Cozy Bear) phishing-campaign as reported by mandiant');
	expect(comp.extractedReferences).toEqual([
		{ type: 'url', text: 'https://twitter.com/DrunkBinary/status/1063075530180886529', link: 'https://twitter.com/DrunkBinary/status/1063075530180886529' },
		{ type: 'text', text: 'test_text' },
	]);
	expect(comp.extractedLogic).toBe('logsource:\n  product: windows\n  category: file_event\ndetection:\n  selection:\n    TargetFilename|contains:\n      - ds7002.lnk\n      - ds7002.pdf\n      - ds7002.zip\n    condition: selection');
	expect(comp.extractedLogicClass).toBe('language-yaml');

	// content with no description
	comp.detect.content = `title: APT29 2018 Phishing Campaign File Indicators\nid: 3a3f81ca-652c-482b-adeb-b1c804727f74\nrelated:\n  - id: 7453575c-a747-40b9-839b-125a0aae324b # ProcessCreation\n    type: derived\nstatus: stable\nreferences:\n  - https://twitter.com/DrunkBinary/status/1063075530180886529\n  - https://www.mandiant.com/resources/blog/not-so-cozy-an-uncomfortable-examination-of-a-suspected-apt29-phishing-campaign\nauthor: '@41thexplorer'\ndate: 2018/11/20\nmodified: 2023/02/20\ntags:\n  - attack.defense_evasion\n  - attack.t1218.011\n  - detection.emerging_threats\nlogsource:\n  product: windows\n  category: file_event\ndetection:\n  selection:\n    TargetFilename|contains:\n      - 'ds7002.lnk'\n      - 'ds7002.pdf'\n      - 'ds7002.zip'\n    condition: selection\nfalsepositives:\n  - Unlikely\nlevel: critical`;
	comp.detect.description = 'Description'
	comp.extractSummary();

	// fallback first to detection Description...
	expect(comp.extractedSummary).toBe('Description');

	comp.detect.description = '';

	comp.extractSummary();

	// ... else fallback to title
	expect(comp.extractedSummary).toBe('Title');
});

test('fixProtocol', () => {
	expect(comp.fixProtocol('http://example.com')).toBe('http://example.com');
	expect(comp.fixProtocol('https://example.com')).toBe('https://example.com');
	expect(comp.fixProtocol('example.com')).toBe('http://example.com');
});

test('cleanOverrides suricata', () => {
	comp.detect = {
		engine: 'suricata',
		overrides: [
			{
				type: 'modify',
				isEnabled: 'isEnabled',
				createdAt: 'createdAt',
				updatedAt: 'updatedAt',
				customFilter: 'custom filter',
				regex: 'regex',
				value: 'value',
				thresholdType: 'thresholdType',
				track: 'track',
				count: '10',
				seconds: '10',
				ip: 'ip',
			},
			{
				type: 'threshold',
				isEnabled: 'isEnabled',
				createdAt: 'createdAt',
				updatedAt: 'updatedAt',
				customFilter: 'custom filter',
				regex: 'regex',
				value: 'value',
				thresholdType: 'thresholdType',
				track: 'track',
				count: '10',
				seconds: '10',
				ip: 'ip',
			},
			{
				type: 'suppress',
				isEnabled: 'isEnabled',
				createdAt: 'createdAt',
				updatedAt: 'updatedAt',
				customFilter: 'custom filter',
				regex: 'regex',
				value: 'value',
				thresholdType: 'thresholdType',
				track: 'track',
				count: '10',
				seconds: '10',
				ip: 'ip',
			}
		],
	};

	comp.cleanupOverrides();

	expect(comp.detect.overrides[0]).toStrictEqual({
		type: 'modify',
		isEnabled: 'isEnabled',
		createdAt: 'createdAt',
		updatedAt: 'updatedAt',
		regex: 'regex',
		value: 'value',
	});
	expect(comp.detect.overrides[1]).toStrictEqual({
		type: 'threshold',
		isEnabled: 'isEnabled',
		createdAt: 'createdAt',
		updatedAt: 'updatedAt',
		thresholdType: 'thresholdType',
		track: 'track',
		count: 10,
		seconds: 10,
	});
	expect(comp.detect.overrides[2]).toStrictEqual({
		type: 'suppress',
		isEnabled: 'isEnabled',
		createdAt: 'createdAt',
		updatedAt: 'updatedAt',
		track: 'track',
		ip: 'ip',
	});
});

test('cleanOverrides elastalert', () => {
	comp.detect = {
		engine: 'elastalert',
		overrides: [
			{
				type: 'custom filter',
				isEnabled: 'isEnabled',
				createdAt: 'createdAt',
				updatedAt: 'updatedAt',
				customFilter: 'custom filter',
				regex: 'regex',
				value: 'value',
				thresholdType: 'thresholdType',
				track: 'track',
				count: '10',
				seconds: '10',
				ip: 'ip',
			},
		],
	};

	comp.cleanupOverrides();

	expect(comp.detect.overrides[0]).toStrictEqual({
		type: 'custom filter',
		isEnabled: 'isEnabled',
		createdAt: 'createdAt',
		updatedAt: 'updatedAt',
		customFilter: 'custom filter',
	});
});

test('canAddOverride suricata', () => {
	comp.detect = {
		engine: 'suricata',
	};

	expect(comp.canAddOverride()).toBe(true);

	comp.detect.overrides = [
		{
			type: 'modify',
			isEnabled: 'isEnabled',
			createdAt: 'createdAt',
			updatedAt: 'updatedAt',
			customFilter: 'custom filter',
			regex: 'regex',
			value: 'value',
			thresholdType: 'thresholdType',
			track: 'track',
			count: '10',
			seconds: '10',
			ip: 'ip',
		},
		{
			type: 'threshold',
			isEnabled: 'isEnabled',
			createdAt: 'createdAt',
			updatedAt: 'updatedAt',
			customFilter: 'custom filter',
			regex: 'regex',
			value: 'value',
			thresholdType: 'thresholdType',
			track: 'track',
			count: '10',
			seconds: '10',
			ip: 'ip',
		},
		{
			type: 'suppress',
			isEnabled: 'isEnabled',
			createdAt: 'createdAt',
			updatedAt: 'updatedAt',
			customFilter: 'custom filter',
			regex: 'regex',
			value: 'value',
			thresholdType: 'thresholdType',
			track: 'track',
			count: '10',
			seconds: '10',
			ip: 'ip',
		}
	];

	expect(comp.canAddOverride()).toBe(true);
});

test('canAddOverride strelka', () => {
	comp.detect = {
		engine: 'strelka',
	};

	expect(comp.canAddOverride()).toBe(false);
});

test('canAddOverride elastalert', () => {
	comp.detect = {
		engine: 'elastalert',
	};

	expect(comp.canAddOverride()).toBe(true);

	comp.detect.overrides = [
		{
			type: 'customFilter',
			isEnabled: 'isEnabled',
			createdAt: 'createdAt',
			updatedAt: 'updatedAt',
			customFilter: 'custom filter',
			regex: 'regex',
			value: 'value',
			thresholdType: 'thresholdType',
			track: 'track',
			count: '10',
			seconds: '10',
			ip: 'ip',
		},
	];

	expect(comp.canAddOverride()).toBe(true);
});

test('tagOverrides', () => {
	comp.detect = {};

	comp.tagOverrides();

	expect(comp.detect.overrides).toStrictEqual([]);

	comp.detect.overrides = [{}, {}, {}];

	comp.tagOverrides();

	for (let i = 0; i < comp.detect.overrides.length; i++) {
		expect(comp.detect.overrides[i]).toStrictEqual({ index: i });
	}
});

test('isDetectionSourceDirty', () => {
	comp.detect = {
		content: 'X',
	};
	comp.origDetect = Object.assign({}, comp.detect);

	expect(comp.isDetectionSourceDirty()).toBe(false);

	comp.detect.content = 'Y';

	expect(comp.isDetectionSourceDirty()).toBe(true);

	comp.origDetect.content = 'Y';

	expect(comp.isDetectionSourceDirty()).toBe(false);
});

test('revertEnabled', () => {
	comp.detect = {
		isEnabled: true,
	};
	comp.origDetect = Object.assign({}, comp.detect);

	// both true
	comp.revertEnabled();
	expect(comp.detect.isEnabled).toBe(true);
	expect(comp.origDetect.isEnabled).toBe(true);

	// det false, orig true
	comp.detect.isEnabled = false;
	comp.revertEnabled();
	expect(comp.detect.isEnabled).toBe(true);
	expect(comp.origDetect.isEnabled).toBe(true);

	// det true, orig false
	comp.detect.isEnabled = true;
	comp.origDetect.isEnabled = false;
	comp.revertEnabled();
	expect(comp.detect.isEnabled).toBe(false);
	expect(comp.origDetect.isEnabled).toBe(false);

	// both false
	comp.revertEnabled();
	expect(comp.detect.isEnabled).toBe(false);
	expect(comp.origDetect.isEnabled).toBe(false);
});

function ClassList(arr) {
	this.arr = arr;
	this.contains = (cls) => {
		return this.arr.includes(cls);
	}
}

test('isFieldValid', () => {
	comp.$refs = {};
	expect(comp.isFieldValid('foo')).toBe(true);

	comp.$refs = { bar: { classList: new ClassList(['a', 'v-input--error', 'b', 'c']) } };
	expect(comp.isFieldValid('foo')).toBe(true);
	expect(comp.isFieldValid('bar')).toBe(false);

	comp.$refs = { bar: { classList: new ClassList(['a', 'b', 'c']) } };
	expect(comp.isFieldValid('bar')).toBe(true);

	comp.$refs = { bar: {} };
	expect(comp.isFieldValid('bar')).toBe(false);
});

test('onNewDetectionLanguageChange', async () => {
	comp.ruleTemplates = {
		"suricata": 'a [publicId]',
		"strelka": 'b [publicId]',
		"elastalert": 'c [publicId]',
	};
	// no language means no engine means no request means no change
	comp.detect = { language: '', content: 'x' };
	await comp.onNewDetectionLanguageChange();
	expect(comp.detect.content).toBe('x');

	// yara, no publicId, results in template without publicId, note that the template is trimmed and there is no [publicId]
	comp.detect = { language:'yara', content: 'x' };
	await comp.onNewDetectionLanguageChange();
	expect(comp.detect.content).toBe('b');

	// suricata, sid, results in template with publicId
	resetPapi().mockPapi("get", { data: { publicId: 'X' } }, null);
	comp.detect = { language:'suricata', content: 'x' };
	await comp.onNewDetectionLanguageChange();
	expect(comp.detect.content).toBe('a X');

	// sigma, uuid, results in template with publicId
	resetPapi().mockPapi("get", { data: { publicId: 'X' } }, null);
	comp.detect = { language:'sigma', content: 'x' };
	await comp.onNewDetectionLanguageChange();
	expect(comp.detect.content).toBe('c X');
});

test('getDefaultPreset', () => {
	comp.presets = {
		"language": {
		"customEnabled": false,
		"labels": [
			"suricata",
			"sigma",
			"yara"
		]
		},
		"license": {
		"customEnabled": true,
		"labels": [
			"Apache-2.0",
			"AGPL-3.0-only",
			"BSD-3-Clause",
			"DRL-1.1",
			"GPL-2.0-only",
			"GPL-3.0-only",
			"MIT"
		]
		},
		"severity": {
		"customEnabled": false,
		"labels": [
			"unknown",
			"informational",
			"low",
			"medium",
			"high",
			"critical"
		]
		}
	}

	expect(comp.getDefaultPreset('language')).toBe('suricata');
	expect(comp.getDefaultPreset('license')).toBe('Apache-2.0');
	expect(comp.getDefaultPreset('severity')).toBe('unknown');
    expect(comp.getDefaultPreset('test')).toBe('');
});

test('getPresets', () => {
	comp.presets = {
		"language": {
		"customEnabled": false,
		"labels": [
			"suricata",
			"sigma",
			"yara"
		]
		},
		"license": {
		"customEnabled": true,
		"labels": [
			"Apache-2.0",
			"AGPL-3.0-only",
			"BSD-3-Clause",
			"DRL-1.1",
			"GPL-2.0-only",
			"GPL-3.0-only",
			"MIT"
		]
		},
		"severity": {
		"customEnabled": false,
		"labels": [
			"unknown",
			"informational",
			"low",
			"medium",
			"high",
			"critical"
		]
		}
	}

	expect(comp.getPresets('language')).toEqual(['Suricata', 'Sigma', 'YARA']);
	expect(comp.getPresets('license')).toEqual([
		"Apache-2.0",
		"AGPL-3.0-only",
		"BSD-3-Clause",
		"DRL-1.1",
		"GPL-2.0-only",
		"GPL-3.0-only",
		"MIT"
	])
	expect(comp.getPresets('test')).toEqual([]);
});

test('findHistoryChange', () => {
	// elastalert
	comp.history = [
		{
			"id": "oHypPJABXppUUuo3IHDO",
			"createTime": "2024-06-21T17:17:14.951585268-04:00",
			"updateTime": "2024-06-21T17:17:14.951616529-04:00",
			"userId": "5ac4acbe-6299-463d-9449-9a728ec48ab8",
			"kind": "detection",
			"operation": "create",
			"publicId": "aaca8e61-0365-4e50-8cee-6f7102a46b08",
			"title": "test history",
			"severity": "high",
			"author": "matthew.wright@securityonionsolutions.com",
			"description": "This should be a detailed description of what this Detection focuses on: what we are trying to find and why we are trying to find it.\n",
			"content": "title: 'test history'\nid: aaca8e61-0365-4e50-8cee-6f7102a46b08\nstatus: 'experimental'\ndescription: |\n    This should be a detailed description of what this Detection focuses on: what we are trying to find and why we are trying to find it.\nreferences:\n  - 'https://local.invalid'\nauthor: '@SecurityOnion'\ndate: 'YYYY/MM/DD'\ntags:\n  - detection.threat_hunting\n  - attack.technique_id\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    Image: 'whoami.exe'\n    User: 'backup'\n  condition: selection\nlevel: 'high'",
			"isEnabled": false,
			"isReporting": false,
			"isCommunity": false,
			"engine": "elastalert",
			"language": "sigma",
			"overrides": null,
			"tags": null,
			"ruleset": "__custom__",
			"license": "Apache-2.0"
		},
		{
			"id": "BHypPJABXppUUuo3UnEl",
			"createTime": "2024-06-21T17:17:14.951585268-04:00",
			"updateTime": "2024-06-21T17:17:27.563141416-04:00",
			"userId": "5ac4acbe-6299-463d-9449-9a728ec48ab8",
			"kind": "detection",
			"operation": "update",
			"publicId": "aaca8e61-0365-4e50-8cee-6f7102a46b08",
			"title": "test history updated",
			"severity": "high",
			"author": "matthew.wright@securityonionsolutions.com",
			"description": "This should be a detailed description of what this Detection focuses on: what we are trying to find and why we are trying to find it.\n",
			"content": "title: 'test history updated'\nid: aaca8e61-0365-4e50-8cee-6f7102a46b08\nstatus: 'experimental'\ndescription: |\n    This should be a detailed description of what this Detection focuses on: what we are trying to find and why we are trying to find it.\nreferences:\n  - 'https://local.invalid'\nauthor: '@SecurityOnion'\ndate: 'YYYY/MM/DD'\ntags:\n  - detection.threat_hunting\n  - attack.technique_id\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    Image: 'whoami.exe'\n    User: 'backup'\n  condition: selection\nlevel: 'high'",
			"isEnabled": false,
			"isReporting": false,
			"isCommunity": false,
			"engine": "elastalert",
			"language": "sigma",
			"overrides": [],
			"tags": null,
			"ruleset": "__custom__",
			"license": "Apache-2.0"
		}
	];
	expect(Object.keys(comp.changedKeys).length).toBe(0);
	id = comp.history[1]['id'];
	comp.findHistoryChange(id);
	expect(comp.changedKeys[id]).toStrictEqual(['title']);

	// suricata
	comp.history = [
		{
			"id": "ftBXVpABn3BnwwVaSfjx",
			"createTime": "2024-06-26T16:57:58.910704718-04:00",
			"updateTime": "2024-06-26T16:57:58.910735621-04:00",
			"userId": "5ac4acbe-6299-463d-9449-9a728ec48ab8",
			"kind": "detection",
			"operation": "create",
			"publicId": "1997691",
			"title": "test rule",
			"severity": "low",
			"author": "matthew.wright@securityonionsolutions.com",
			"description": "Detection description not yet provided",
			"content": "alert http $EXTERNAL_NET any -> $HOME_NET any (msg:\"test rule\"; content:\"example\"; sid:1997691; rev:1; metadata:signature_severity Minor;)\n",
			"isEnabled": false,
			"isReporting": false,
			"isCommunity": false,
			"engine": "suricata",
			"language": "suricata",
			"overrides": null,
			"tags": null,
			"ruleset": "__custom__",
			"license": "Apache-2.0"
		},
		{
			"id": "oNBXVpABn3BnwwVa_vmG",
			"createTime": "2024-06-26T16:57:58.910704718-04:00",
			"updateTime": "2024-06-26T16:58:45.341119411-04:00",
			"userId": "5ac4acbe-6299-463d-9449-9a728ec48ab8",
			"kind": "detection",
			"operation": "update",
			"publicId": "1997691",
			"title": "test rule",
			"severity": "high",
			"author": "matthew.wright@securityonionsolutions.com",
			"description": "Detection description not yet provided",
			"content": "alert http $EXTERNAL_NET any -> $HOME_NET any (msg:\"test rule\"; content:\"example\"; sid:1997691; rev:1; metadata:signature_severity Major;)\n",
			"isEnabled": false,
			"isReporting": false,
			"isCommunity": false,
			"engine": "suricata",
			"language": "suricata",
			"overrides": [],
			"tags": null,
			"ruleset": "__custom__",
			"license": "Apache-2.0"
		}
	];
	comp.severityTranslations = { "major" : "high", "minor" : "low" };
	id = comp.history[1]['id'];
	comp.findHistoryChange(id);
	expect(comp.changedKeys[id]).toStrictEqual(['severity']);

	// strelka
	comp.history = [
		{
			"id": "xtBaVpABn3BnwwVaKv0Z",
			"createTime": "2024-06-26T17:01:07.363478251-04:00",
			"updateTime": "2024-06-26T17:01:07.3635097-04:00",
			"userId": "5ac4acbe-6299-463d-9449-9a728ec48ab8",
			"kind": "detection",
			"operation": "create",
			"publicId": "testRuleStrelka",
			"title": "testRuleStrelka",
			"severity": "unknown",
			"author": "matthew.wright@securityonionsolutions.com",
			"description": "Generic YARA Rule",
			"content": "rule testRuleStrelka // This identifier _must_ be unique\n{\n    meta:\n        description=\"Generic YARA Rule\"\n        author = \"@SecurityOnion\"\n        date = \"YYYY-MM-DD\"\n        reference = \"https://local.invalid\"\n    strings:\n        $my_text_string = \"text here\"\n        $my_hex_string = { E2 34 A1 C8 23 FB }\n    condition:\n        filesize < 3MB and ($my_text_string or $my_hex_string)\n}\n",
			"isEnabled": false,
			"isReporting": false,
			"isCommunity": false,
			"engine": "strelka",
			"language": "yara",
			"overrides": null,
			"tags": null,
			"ruleset": "__custom__",
			"license": "Apache-2.0"
		},
		{
			"id": "8tBbVpABn3BnwwVaAP5P",
			"createTime": "2024-06-26T17:01:07.363478251-04:00",
			"updateTime": "2024-06-26T17:02:02.362314808-04:00",
			"userId": "5ac4acbe-6299-463d-9449-9a728ec48ab8",
			"kind": "detection",
			"operation": "update",
			"publicId": "testRuleStrelka",
			"title": "testRuleStrelka",
			"severity": "unknown",
			"author": "matthew.wright@securityonionsolutions.com",
			"description": "Generic YARA Rule updated",
			"content": "rule testRuleStrelka // This identifier _must_ be unique\n{\n    meta:\n        description=\"Generic YARA Rule updated\"\n        author = \"@SecurityOnion\"\n        date = \"YYYY-MM-DD\"\n        reference = \"https://local.invalid\"\n    strings:\n        $my_text_string = \"text here\"\n        $my_hex_string = { E2 34 A1 C8 23 FB }\n    condition:\n        filesize < 3MB and ($my_text_string or $my_hex_string)\n}\n",
			"isEnabled": false,
			"isReporting": false,
			"isCommunity": false,
			"engine": "strelka",
			"language": "yara",
			"overrides": [],
			"tags": null,
			"ruleset": "__custom__",
			"license": "Apache-2.0"
		}
	];
	id = comp.history[1]['id'];
	comp.findHistoryChange(id);
	expect(comp.changedKeys[id]).toStrictEqual(['description']);
});

test('checkChangedKey', () => {
	expect(Object.keys(comp.changedKeys).length).toBe(0);
	let id = "BHypPJABXppUUuo3UnEl";
	comp.changedKeys[id] = ['title', 'content'];
	expect(comp.checkChangedKey(id, 'title')).toBe(true);
	expect(comp.checkChangedKey(id, 'content')).toBe(true);
	expect(comp.checkChangedKey(id, 'severity')).toBe(false);
});

test('findOverrideHistoryChange', () => {
	// elastalert
	comp.history = [
		{
			id: '1',
			overrides: [
				{
					type: "customFilter",
					isEnabled: true,
					createdAt: "2024-07-29T10:29:32.421321098-06:00",
					updatedAt: "2024-07-29T10:29:32.421321098-06:00",
					customFilter: "this:\n    that"
				},
				{
					type: "customFilter",
					isEnabled: false,
					createdAt: "2024-07-29T11:54:34.569557439-06:00",
					updatedAt: "2024-07-29T11:54:49.086205751-06:00",
					customFilter: "another:\n    one"
				}
			],
		},
		{
			id: '2',
			overrides: [
				{
					type: "customFilter",
					isEnabled: true,
					createdAt: "2024-07-29T10:29:32.421321098-06:00",
					updatedAt: "2024-07-29T10:29:32.421321098-06:00",
					customFilter: "this:\n    that"
				},
				{
					type: "customFilter",
					isEnabled: false,
					createdAt: "2024-07-29T11:54:34.569557439-06:00",
					updatedAt: "2024-07-29T13:55:29.197427405-06:00",
					customFilter: "another:\n    two"
				}
			],
		}
	];

	id = '2';
	comp.changedOverrideKeys = {};
	comp.findOverrideHistoryChange(id);
	expect(Object.keys(comp.changedOverrideKeys).length).toBe(1);

	let overrideKeys = comp.changedOverrideKeys[id];
	expect(overrideKeys.length).toBe(2);
	expect(overrideKeys[0].length).toBe(0);
	expect(overrideKeys[1].length).toBe(1);
	expect(overrideKeys[1][0]).toBe('customFilter');

	// suricata
	comp.history = [
		{
			id: '1',
			overrides: [
				{
					type: "modify",
					isEnabled: false,
					createdAt: "2024-07-29T14:39:09.544042454-06:00",
					updatedAt: "2024-07-29T14:39:21.947393163-06:00",
					regex: "rev: 2",
					value: "rev: 3"
				},
				{
					type: "suppress",
					isEnabled: false,
					createdAt: "2024-07-29T14:39:44.312946909-06:00",
					updatedAt: "2024-07-29T14:57:49.637548072-06:00",
					track: "by_either",
					ip: "0.0.0.0/0"
				},
				{
					type: "threshold",
					isEnabled: true,
					createdAt: "2024-07-29T14:40:17.043093339-06:00",
					updatedAt: "2024-07-29T14:40:17.043093339-06:00",
					thresholdType: "both",
					track: "by_src",
					count: 10,
					seconds: 60
				}
			]
		},
		{
			id: '2',
			overrides: [
				{
					type: "modify",
					isEnabled: true,
					createdAt: "2024-07-29T14:39:09.544042454-06:00",
					updatedAt: "2024-07-29T14:39:20.947393160-06:00",
					regex: "rev: 2",
					value: "rev: 3"
				},
				{
					type: "suppress",
					isEnabled: false,
					createdAt: "2024-07-29T14:39:44.312946909-06:00",
					updatedAt: "2024-07-29T14:57:50.637548070-06:00",
					track: "by_src",
					ip: "0.0.0.0/1"
				},
				{
					type: "threshold",
					isEnabled: true,
					createdAt: "2024-07-29T14:40:17.043093339-06:00",
					updatedAt: "2024-07-29T14:40:17.043093339-06:00",
					thresholdType: "both",
					track: "by_src",
					"count": 10,
					"seconds": 60
				}
			],
		}
	];

	id = '2';
	comp.changedOverrideKeys = {};
	comp.findOverrideHistoryChange(id);
	expect(Object.keys(comp.changedOverrideKeys).length).toBe(1);

	overrideKeys = comp.changedOverrideKeys[id];
	expect(overrideKeys.length).toBe(3);
	expect(overrideKeys[0].length).toBe(1);
	expect(overrideKeys[0][0]).toBe('isEnabled');
	expect(overrideKeys[1].length).toBe(2);
	expect(overrideKeys[1][0]).toBe('track');
	expect(overrideKeys[1][1]).toBe('ip');
	expect(overrideKeys[2].length).toBe(0);

	id = '1';
	comp.changedOverrideKeys = {};
	comp.findOverrideHistoryChange(id);
	expect(Object.keys(comp.changedOverrideKeys).length).toBe(0);

	// elastalert, nothing to diff
	comp.history = [
		{
			id: '1',
			overrides: [],
		},
		{
			id: '2',
			overrides: [
				{
					type: "customFilter",
					isEnabled: true,
					createdAt: "2024-07-29T10:29:32.421321098-06:00",
					updatedAt: "2024-07-29T10:29:32.421321098-06:00",
					customFilter: "this:\n    that"
				},
			],
		}
	];

	id = '2';
	comp.changedOverrideKeys = {};
	comp.findOverrideHistoryChange(id);
	expect(Object.keys(comp.changedOverrideKeys).length).toBe(0);
});

test('checkOverrideChangedKey', () => {
	expect(Object.keys(comp.changedKeys).length).toBe(0);
	let id = "BHypPJABXppUUuo3UnEl";
	comp.changedOverrideKeys[id] = [[], ['track', 'ip']];
	expect(comp.checkOverrideChangedKey(id, 0, 'track')).toBe(false);
	expect(comp.checkOverrideChangedKey(id, 1, 'track')).toBe(true);
	expect(comp.checkOverrideChangedKey(id, 0, 'ip')).toBe(false);
	expect(comp.checkOverrideChangedKey(id, 1, 'ip')).toBe(true);
	expect(comp.checkOverrideChangedKey(id, 0, 'seconds')).toBe(false);
	expect(comp.checkOverrideChangedKey(id, 1, 'seconds')).toBe(false);
});

test('loadUrlParameters', () => {
	let nextTickCalled = 0;
	comp.$nextTick = (f) => {
		// can't use jest.fn, need to actually call the arg passed in
		nextTickCalled++;
		f();
	};

	comp.$route.query = {
		tab: 'tab',
	};

	comp.loadUrlParameters();

	expect(comp.activeTab).toBe('tab');
	expect(nextTickCalled).toBe(1);
});

test('extractDetection', () => {
	let response = {
		data: {
			kind: 'kind',
			id: 'id',
		},
	};

	comp.tagOverrides = jest.fn();
	comp.loadAssociations = jest.fn();
	comp.$root.populateUserDetails = jest.fn();

	comp.extractDetection(response);

	expect(comp.detect).toStrictEqual({ id: 'id' });
	expect(comp.tagOverrides).toHaveBeenCalledTimes(1);
	expect(comp.loadAssociations).toHaveBeenCalledTimes(1);
	expect(comp.$root.populateUserDetails).toHaveBeenCalledTimes(1);
});

test('saveDetection - statusEffectedByFilter', async () => {
	resetPapi().mockPapi('put', {status:205}, null);
	comp.detect = { content: "", language: '' };
	comp.origDetect = { content: "" };
	comp.extractDetection = jest.fn();

	await comp.saveDetection(false, false);

	expect(comp.$root.warning).toBe(true);
	expect(comp.$root.warningMessage).toBe(comp.i18n.WARN_STATUS_EFFECTED_BY_FILTER);
	expect(comp.extractDetection).toHaveBeenCalledTimes(1);
});

test('validateElastAlert', () => {
	comp.detect = {
		language: 'sigma',
		content: ''
	};

	let msg = comp.validateElastAlert();
	expect(msg).toBe(comp.i18n.invalidDetectionElastAlertMissingID);

	comp.detect.content = 'id: 123\n';
	msg = comp.validateElastAlert();
	expect(msg).toBe(comp.i18n.invalidDetectionElastAlertMissingDetectionLogic);

	comp.detect.content += 'detection: {}'
	msg = comp.validateElastAlert();
	expect(msg).toBe(null);
});

test('validateSuricata', () => {
	comp.detect = {
		language: 'suricata',
		content: '\n',
		publicId: '123',
	};

	let msg = comp.validateSuricata();
	expect(msg).toBe(comp.i18n.invalidDetectionSuricataNewLine);

	comp.detect.content = '';
	msg = comp.validateSuricata();
	expect(msg).toBe(comp.i18n.invalidDetectionSuricataMissingSID);

	comp.detect.content = 'sid: 123;';
	msg = comp.validateSuricata();
	expect(msg).toBe(null);
});

test('validateStrelka', () => {
	comp.detect = {
		language: 'yara',
		content: 'rule {}',
	};

	let msg = comp.validateStrelka();
	expect(msg).toBe(comp.i18n.invalidDetectionStrelkaMissingRuleName);

	comp.detect.content = 'rule 5 {}';
	msg = comp.validateStrelka();
	expect(msg).toBe(comp.i18n.invalidDetectionStrelkaInvalidRuleName);

	comp.detect.content = 'rule X {}';
	msg = comp.validateStrelka();
	expect(msg).toBe(comp.i18n.invalidDetectionStrelkaMissingCondition);

	comp.detect.content = 'rule X { condition: }';
	msg = comp.validateStrelka();
	expect(msg).toBe(null);
});


test('validateElastAlert', () => {
	comp.detect = {
		publicId: 'A',
		content: 'id: B',
		language: 'sigma',
	};
	let msg = comp.validateElastAlert();
	expect(msg).toBe(comp.i18n.idMismatchErr);

	comp.detect.content = 'id: A';
	msg = comp.validateElastAlert();
	expect(msg).toBe(comp.i18n.invalidDetectionElastAlertMissingDetectionLogic);

	comp.detect.content += '\ndetection: {}'
	msg = comp.validateElastAlert();
	expect(msg).toBe(null);
});

test('validateSuricata', () => {
	comp.detect = {
		publicId: '100000',
		content: 'alert http any any <> any any (sid: 999999;)',
		language: 'suricata',
	};
	let msg = comp.validateSuricata();
	expect(msg).toBe(comp.i18n.invalidDetectionSuricataSIDMismatch);

	comp.detect.publicId = '999999';
	msg = comp.validateSuricata();
	expect(msg).toBe(null);
});

test('showAiSummary', () => {
	comp.detect = null;
	expect(comp.showAiSummary()).toBe(false);

	comp.detect = { engine: 'strelka' };
	expect(comp.showAiSummary()).toBe(false);

	comp.detect.aiSummary = 'aiSummary';
	expect(comp.showAiSummary()).toBe(false);

	comp.detect.aiSummaryReviewed = true;
	expect(comp.showAiSummary()).toBe(true);

	comp.detect.aiSummary = '';
	expect(comp.showAiSummary()).toBe(false);

	comp.showUnreviewedAiSummaries = true;

	comp.detect = null;
	expect(comp.showAiSummary()).toBe(false);

	comp.detect = { engine: 'elastalert' };
	expect(comp.showAiSummary()).toBe(false);

	comp.detect.aiSummary = 'aiSummary';
	expect(comp.showAiSummary()).toBe(true);

	comp.detect.aiSummaryReviewed = true;
	expect(comp.showAiSummary()).toBe(true);

	comp.detect.aiSummary = '';
	expect(comp.showAiSummary()).toBe(false);
});

test('isPresetCustomEnabled', () => {
	comp.presets = {
		"language": {
			"labels": ["suricata", "sigma", "yara"],
			"customEnabled": false
		},
		"license": {
			"labels": ["None", "Apache-2.0", "AGPL-3.0-only", "BSD-3-Clause", "DRL-1.1", "GPL-2.0-only", "GPL-3.0-only", "MIT"],
			"customEnabled": true
		}
	};

	let customEnabled = comp.isPresetCustomEnabled('language');
	expect(customEnabled).toBe(false);

	customEnabled = comp.isPresetCustomEnabled('license');
	expect(customEnabled).toBe(true);

	customEnabled = comp.isPresetCustomEnabled('severity');
	expect(customEnabled).toBe(false);
});

test('extractSuricataSeverity', () => {
	comp.severityTranslations = {
		major: "high",
		minor: "low"
	},
	comp.presets = {
		severity: {
			labels: ["unknown", "informational", "low", "medium", "high", "critical"],
			customEnabled: false
		}
	};
	comp.detect = {
		content: 'alert http any any <> any any (sid: 999999; rev: 1; metadata: signature_severity Major;)',
	};

	let sev = comp.extractSuricataSeverity();
	expect(sev).toBe('high');

	comp.detect = {
		content: 'alert http any any <> any any (sid: 999999; rev: 1; metadata: signature_severity Minor;)',
	};
	sev = comp.extractSuricataSeverity();
	expect(sev).toBe('low');

	comp.detect = {
		content: 'alert http any any <> any any (sid: 999999; rev: 1;)',
	};
	sev = comp.extractSuricataSeverity();
	expect(sev).toBe('unknown');
});

test('loadHistory', async () => {
	resetPapi().mockPapi("get", { data: [{}] }, null);
	comp.$root.populateUserDetails = jest.fn();
	await comp.loadHistory(true);

	expect(comp.$root.populateUserDetails).toHaveBeenCalledTimes(1);
	expect(comp.history).toStrictEqual([{overrides: []}]);
});

test('pickValue', () => {
	let opt = {
		value: 'value',
		altValues: ['alt1', 'alt2'],
	};
	let obj = {
		value: 'value',
		alt1: 'ALT1',
		alt2: 'ALT2',
	}

	let val = comp.pickValue(obj, opt);
	expect(val).toBe('value');

	delete obj.value;

	val = comp.pickValue(obj, opt);
	expect(val).toBe('ALT1');

	delete obj.alt1;

	val = comp.pickValue(obj, opt);
	expect(val).toBe('ALT2');

	delete obj.alt2;

	val = comp.pickValue(obj, opt);
	expect(val).toBe('');

	obj.value = 'track';
	opt.localize = true;

	val = comp.pickValue(obj, opt);
	expect(val).toBe('Track');
});

test('loadPlaybooks', async () => {
	const rawDocs = 'A\n---\nB\n---\nC';
	const mock = mockPapi('get', { data: rawDocs });

	comp.detect = { publicId: 'public' };
	
	await comp.loadPlaybooks();

	expect(comp.playbookCount).toBe(3);
	expect(comp.joinedPlaybookSource).toBe(rawDocs);
	expect(mock).toHaveBeenCalledTimes(1);
	expect(mock).toHaveBeenCalledWith('playbook/detection/public?raw=true');

	resetPapi();
});

	test('convertDetection and runQueryInDiscover', async () => {
		const mock = mockPapi('post', { data: { query: 'FROM logs-*', useEsql: true } });
		comp.detect = { language: 'sigma', engine: 'elastalert' };
		await comp.convertDetection();

		expect(comp.convertedRule).toBe('FROM logs-*');
		expect(comp.isEsql).toBe(true);
		expect(comp.showSigmaDialog).toBe(true);

		const originalOpen = window.open;
		window.open = jest.fn();

		const originalCompress = LZString.compressToEncodedURIComponent;
		LZString.compressToEncodedURIComponent = jest.fn().mockReturnValue('compressed_query');

		comp.runQueryInDiscover();

		expect(window.open).toHaveBeenCalledWith(
			'/kibana/app/dev_tools#/console?load_from=data:text/plain,compressed_query',
			'_blank'
		);

		const expectedQuery = `POST /_query
{
	"query": """
	FROM logs-*
	"""
}`;
		expect(LZString.compressToEncodedURIComponent).toHaveBeenCalledWith(expectedQuery);

		comp.isEsql = false;
		comp.convertedRule = 'some eql query';
		comp.runQueryInDiscover();

		const expectedEqlQuery = `GET /.ds-logs-*/_eql/search
{
	"query": """
	some eql query
	"""
}`;
		expect(LZString.compressToEncodedURIComponent).toHaveBeenCalledWith(expectedEqlQuery);

		window.open = originalOpen;
		LZString.compressToEncodedURIComponent = originalCompress;
		resetPapi();
	});

	test('extract elastalert with multi-doc YAML', () => {
		comp.detect = {
			engine: 'elastalert',
			content: `title: Multiple Failed SOC Logins From One Source IP In A Short Window
id: 1a4f6b22-9c07-4d3e-8b51-0e9a7d2c4f88
status: experimental
description: |
  Detects two or more failed SOC logins from
  the same client IP within 30 seconds.
references:
    - https://attack.mitre.org/techniques/T1110/
author: SOS
date: 2026-06-08
falsepositives:
    - TBD
level: medium
---
title: Failed SOC Console Login
id: 0b8e3f51-7a26-4c9d-9f10-3d5b8e6a1c72
name: failed_login
logsource:
    product: securityonion
    service: kratos
detection:
    selection:
        service_name: 'Ory Kratos'
        event.action: 'Encountered self-service login error.'
    condition: selection
`,
			title: 'Title',
		};
		comp.$route = { params: { id: '123' } };

		comp.extractSummary();
		comp.extractReferences();
		comp.extractLogic();

		expect(comp.extractedSummary).toBe('Detects two or more failed SOC logins from\nthe same client IP within 30 seconds.\n');
		expect(comp.extractedReferences).toEqual([
			{ type: 'url', text: 'https://attack.mitre.org/techniques/T1110/', link: 'https://attack.mitre.org/techniques/T1110/' },
		]);
		expect(comp.extractedLogic).toBe('{}');
		expect(comp.extractedLogicClass).toBe('language-yaml');
	});

	test('extract elastalert public ID from multi-doc YAML', () => {
		comp.detect = {
			engine: 'elastalert',
			content: `title: Test Rule
id: abc123-def456
status: experimental
description: Test description
level: medium
---
title: Sub Rule
name: sub_rule
logsource:
    product: test
detection:
    selection:
        field: value
    condition: selection
`,
		};

		const id = comp.extractElastAlertPublicID();
		expect(id).toBe('abc123-def456');
	});

	test('findHistoryChange with multi-doc elastalert content', () => {
		comp.history = [
			{
				"id": "hist1",
				"createTime": "2024-06-21T17:17:14.951585268-04:00",
				"updateTime": "2024-06-21T17:17:14.951616529-04:00",
				"userId": "5ac4acbe-6299-463d-9449-9a728ec48ab8",
				"kind": "detection",
				"operation": "create",
				"publicId": "multi-doc-test",
				"title": "multi-doc test",
				"severity": "high",
				"description": "Description",
				"content": "title: 'Original Title'\nid: abc123\nstatus: 'experimental'\ndescription: |\n    Original description\nlevel: 'high'\n---\ntitle: Sub Rule\nname: sub_rule\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n  selection:\n    Image: 'original.exe'\n  condition: selection\n",
				"isEnabled": false,
				"engine": "elastalert",
				"language": "sigma",
				"overrides": [],
			},
			{
				"id": "hist2",
				"createTime": "2024-06-21T17:17:14.951585268-04:00",
				"updateTime": "2024-06-21T17:17:27.563141416-04:00",
				"userId": "5ac4acbe-6299-463d-9449-9a728ec48ab8",
				"kind": "detection",
				"operation": "update",
				"publicId": "multi-doc-test",
				"title": "multi-doc test",
				"severity": "high",
				"description": "Description",
				"content": "title: 'Updated Title'\nid: abc123\nstatus: 'experimental'\ndescription: |\n    Updated description\nlevel: 'high'\n---\ntitle: Sub Rule\nname: sub_rule\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n  selection:\n    Image: 'updated.exe'\n  condition: selection\n",
				"isEnabled": false,
				"engine": "elastalert",
				"language": "sigma",
				"overrides": [],
			},
		];
		comp.changedKeys = {};
		const id = comp.history[1]['id'];
		comp.findHistoryChange(id);
		expect(comp.changedKeys[id]).toContain('content');

		comp.history = [
			{
				"id": "hist3",
				"createTime": "2024-06-21T17:17:14.951585268-04:00",
				"updateTime": "2024-06-21T17:17:14.951616529-04:00",
				"userId": "5ac4acbe-6299-463d-9449-9a728ec48ab8",
				"kind": "detection",
				"operation": "create",
				"publicId": "multi-doc-test",
				"title": "multi-doc test",
				"severity": "high",
				"description": "Description",
				"content": "title: 'Original Title'\nid: abc123\nstatus: 'experimental'\ndescription: |\n    Original description\nlevel: 'high'\n---\ntitle: Sub Rule\nname: sub_rule\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n  selection:\n    Image: 'same.exe'\n  condition: selection\n",
				"isEnabled": false,
				"engine": "elastalert",
				"language": "sigma",
				"overrides": [],
			},
			{
				"id": "hist4",
				"createTime": "2024-06-21T17:17:14.951585268-04:00",
				"updateTime": "2024-06-21T17:17:27.563141416-04:00",
				"userId": "5ac4acbe-6299-463d-9449-9a728ec48ab8",
				"kind": "detection",
				"operation": "update",
				"publicId": "multi-doc-test",
				"title": "multi-doc test",
				"severity": "high",
				"description": "Description",
				"content": "title: 'Updated Title'\nid: abc123\nstatus: 'experimental'\ndescription: |\n    Updated description\nlevel: 'high'\n---\ntitle: Sub Rule\nname: sub_rule\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n  selection:\n    Image: 'same.exe'\n  condition: selection\n",
				"isEnabled": false,
				"engine": "elastalert",
				"language": "sigma",
				"overrides": [],
			},
		];
		comp.changedKeys = {};
		const id2 = comp.history[1]['id'];
		comp.findHistoryChange(id2);
		expect(comp.changedKeys[id2]).not.toContain('content');
	});

	test('findHistoryChange with multi-doc elastalert - metadata only change', () => {
		comp.history = [
			{
				"id": "hist5",
				"createTime": "2024-06-21T17:17:14.951585268-04:00",
				"updateTime": "2024-06-21T17:17:14.951616529-04:00",
				"userId": "5ac4acbe-6299-463d-9449-9a728ec48ab8",
				"kind": "detection",
				"operation": "create",
				"publicId": "multi-doc-test",
				"title": "multi-doc test",
				"severity": "high",
				"description": "Description",
				"content": "title: 'Original Title'\nid: abc123\nstatus: 'experimental'\ndescription: |\n    Original description\nlevel: 'high'\n---\ntitle: Sub Rule\nname: sub_rule\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n  selection:\n    Image: 'same.exe'\n    service_name: 'Ory Kratos'\n    event.action: 'Encountered self-service login error.'\n  condition: selection\n",
				"isEnabled": false,
				"engine": "elastalert",
				"language": "sigma",
				"overrides": [],
			},
			{
				"id": "hist6",
				"createTime": "2024-06-21T17:17:14.951585268-04:00",
				"updateTime": "2024-06-21T17:17:27.563141416-04:00",
				"userId": "5ac4acbe-6299-463d-9449-9a728ec48ab8",
				"kind": "detection",
				"operation": "update",
				"publicId": "multi-doc-test",
				"title": "multi-doc test",
				"severity": "high",
				"description": "Description",
				"content": "title: 'Original Title'\nid: abc123\nstatus: 'experimental'\ndescription: |\n    Original description\nlevel: 'medium'\n---\ntitle: Sub Rule\nname: sub_rule\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n  selection:\n    Image: 'same.exe'\n    service_name: 'Ory Kratos'\n    event.action: 'Encountered self-service login error.'\n  condition: selection\n",
				"isEnabled": false,
				"engine": "elastalert",
				"language": "sigma",
				"overrides": [],
			},
		];
		comp.changedKeys = {};
		const id3 = comp.history[1]['id'];
		comp.findHistoryChange(id3);
		expect(comp.changedKeys[id3]).not.toContain('content');
	});

	test('findHistoryChange with multi-doc elastalert - status change detected', () => {
		comp.history = [
			{
				"id": "hist7",
				"createTime": "2024-06-21T17:17:14.951585268-04:00",
				"updateTime": "2024-06-21T17:17:14.951616529-04:00",
				"userId": "5ac4acbe-6299-463d-9449-9a728ec48ab8",
				"kind": "detection",
				"operation": "create",
				"publicId": "multi-doc-test",
				"title": "multi-doc test",
				"severity": "high",
				"description": "Description",
				"content": "title: 'Original Title'\nid: abc123\nstatus: 'experimental'\ndescription: |\n    Original description\nlevel: 'high'\n---\ntitle: Sub Rule\nname: sub_rule\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n  selection:\n    Image: 'same.exe'\n  condition: selection\n",
				"isEnabled": false,
				"engine": "elastalert",
				"language": "sigma",
				"overrides": [],
			},
			{
				"id": "hist8",
				"createTime": "2024-06-21T17:17:14.951585268-04:00",
				"updateTime": "2024-06-21T17:17:27.563141416-04:00",
				"userId": "5ac4acbe-6299-463d-9449-9a728ec48ab8",
				"kind": "detection",
				"operation": "update",
				"publicId": "multi-doc-test",
				"title": "multi-doc test",
				"severity": "high",
				"description": "Description",
				"content": "title: 'Original Title'\nid: abc123\nstatus: 'stable'\ndescription: |\n    Original description\nlevel: 'high'\n---\ntitle: Sub Rule\nname: sub_rule\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n  selection:\n    Image: 'same.exe'\n  condition: selection\n",
				"isEnabled": false,
				"engine": "elastalert",
				"language": "sigma",
				"overrides": [],
			},
		];
		comp.changedKeys = {};
		const id4 = comp.history[1]['id'];
		comp.findHistoryChange(id4);
		expect(comp.changedKeys[id4]).toContain('content');
	});

	test('extractElastAlertLogic with multi-doc YAML', () => {
		comp.detect = {
			engine: 'elastalert',
			content: `title: Multiple Failed SOC Logins From One Source IP In A Short Window
id: 1a4f6b22-9c07-4d3e-8b51-0e9a7d2c4f88
status: experimental
description: |
  Detects two or more failed SOC logins from
  the same client IP within 30 seconds.
logsource:
    product: securityonion
    service: kratos
detection:
    selection:
        service_name: 'Ory Kratos'
        event.action: 'Encountered self-service login error.'
    condition: selection
falsepositives:
    - TBD
level: medium
---
title: Failed SOC Console Login
id: 0b8e3f51-7a26-4c9d-9f10-3d5b8e6a1c72
name: failed_login
`,
		};

		comp.extractedLogic = '';
		comp.extractElastAlertLogic();

		expect(comp.extractedLogic).toContain('logsource:');
		expect(comp.extractedLogic).toContain('detection:');
		expect(comp.extractedLogic).toContain('product: securityonion');
		expect(comp.extractedLogic).toContain('service: kratos');
	});

	test('extractElastAlertLogic with correlation in first doc', () => {
		comp.detect = {
			engine: 'elastalert',
			content: `title: Multiple Failed SOC Logins From One Source IP In A Short Window
id: 1a4f6b22-9c07-4d3e-8b51-0e9a7d2c4f88
status: experimental
description: |
  Detects two or more failed SOC logins from
  the same client IP within 30 seconds.
correlation:
    type: event_count
    rules:
        - failed_login
    group-by:
        - http.request.headers.x-real-ip
    timespan: 30s
    condition:
        gte: 2
falsepositives:
    - TBD
level: medium
---
title: Failed SOC Console Login
id: 0b8e3f51-7a26-4c9d-9f10-3d5b8e6a1c72
name: failed_login
logsource:
    product: securityonion
    service: kratos
detection:
    selection:
        service_name: 'Ory Kratos'
        event.action: 'Encountered self-service login error.'
    condition: selection
`,
		};

		comp.extractedLogic = '';
		comp.extractElastAlertLogic();

		expect(comp.extractedLogic).not.toContain('correlation:');
		expect(comp.extractedLogic).toContain('type: event_count');
		expect(comp.extractedLogic).toContain('rules:');
		expect(comp.extractedLogic).toContain('failed_login');
		expect(comp.extractedLogic).not.toContain('logsource:');
	});

	test('extractElastAlertDetection with correlation in first doc', () => {
		comp.detect = {
			engine: 'elastalert',
			content: `title: Test Rule
id: abc123
correlation:
    type: event_count
    rules:
        - failed_login
    group-by:
        - http.request.headers.x-real-ip
    timespan: 30s
    condition:
        gte: 2
detection:
    selection:
        service_name: 'Ory Kratos'
    condition: selection
`,
		};

		const det = comp.extractElastAlertDetection();
		expect(det).toEqual({
			type: 'event_count',
			rules: ['failed_login'],
			'group-by': ['http.request.headers.x-real-ip'],
			timespan: '30s',
			condition: { gte: 2 },
		});
	});

	test('extractElastAlertDetection with detection in first doc', () => {
		comp.detect = {
			engine: 'elastalert',
			content: `title: Test Rule
id: abc123
detection:
    selection:
        service_name: 'Ory Kratos'
    condition: selection
`,
		};

		const det = comp.extractElastAlertDetection();
		expect(det).toEqual({
			selection: { service_name: 'Ory Kratos' },
			condition: 'selection',
		});
	});

	test('extractElastAlertDetection with no first doc', () => {
		comp.detect = {
			engine: 'elastalert',
			content: '',
		};

		const det = comp.extractElastAlertDetection();
		expect(det).toBeUndefined();
	});

