// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
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
	comp.extractDetails();
	expect(comp.extractedCreated).toBe('');
	expect(comp.extractedUpdated).toBe('');
	
	comp.detect = {
		engine: 'suricata',
		content: 'alert any any <> any any (classtype:Summary; reference:url,example.com; reference:text,Research; metadata: created_at 2020-01-01, updated_at 2020-01-02, author Bob;)',
	};
	comp.$route = { params: { id: '123' } };

	comp.extractSummary();
	comp.extractReferences();
	comp.extractLogic();
	comp.extractDetails();

	expect(comp.extractedSummary).toBe('Summary');
	expect(comp.extractedReferences).toEqual([
		{ type: 'url', text:'example.com', link: 'http://example.com' },
		{ type: 'text', text: 'Research' },
	]);
	expect(comp.extractedLogic).toBe('any any <> any any');
	expect(comp.extractedLogicClass).toBe('language-suricata-logic');
	expect(comp.extractedCreated).toBe('2020-01-01');
	expect(comp.extractedUpdated).toBe('2020-01-02');
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
		content: 'rule Test {\nmeta:\nreference1="example.com"\nreference2="example_text"\ndate = "2020-01-01";\nauthor = "Bob";\n condition:\n$a\n }',
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
	comp.extractDetails();

	expect(comp.extractedSummary).toBe('Example Rule');
	expect(comp.extractedReferences).toEqual([
		{ type: 'url', text: 'example.com', link: 'http://example.com' },
		{ type: 'text', text: 'example_text'},
	]);
	expect(comp.extractedLogic).toBe('strings:\n$a = "test"\ncondition:\n$a');
	expect(comp.extractedLogicClass).toBe('language-yara');
	expect(comp.extractedCreated).toBe('2020-01-01');
	expect(comp.extractedUpdated).toBe('');
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
	comp.extractDetails();

	expect(comp.extractedSummary).toBe('Detects indicators of APT 29 (Cozy Bear) phishing-campaign as reported by mandiant');
	expect(comp.extractedReferences).toEqual([
		{ type: 'url', text: 'https://twitter.com/DrunkBinary/status/1063075530180886529', link: 'https://twitter.com/DrunkBinary/status/1063075530180886529' },
		{ type: 'text', text: 'test_text' },
	]);
	expect(comp.extractedLogic).toBe('logsource:\n  product: windows\n  category: file_event\ndetection:\n  selection:\n    TargetFilename|contains:\n      - ds7002.lnk\n      - ds7002.pdf\n      - ds7002.zip\n    condition: selection');
	expect(comp.extractedLogicClass).toBe('language-yaml');
	expect(comp.extractedCreated).toBe('2018/11/20');
	expect(comp.extractedUpdated).toBe('2023/02/20');

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

test('deleteDetection', async () => {
	const mock = jest.fn().mockReturnValue(Promise.resolve({ data: [] }));
	const showErrorMock = mockShowError();
	comp.$root.papi['delete'] = mock;
	comp.$route.params.id = "testid"
	await comp.confirmDeleteDetection();
	expect(comp.confirmDeleteDialog).toBe(false);
	expect(mock).toHaveBeenCalledTimes(1);
	expect(mock).toHaveBeenCalledWith('/detection/testid');
	expect(comp.$root.loading).toBe(false);
	expect(showErrorMock).toHaveBeenCalledTimes(0);
	expect(comp.$router.length).toBe(1);
});

test('deleteDetectionCancel', () => {
	expect(comp.confirmDeleteDialog).toBe(false);
	comp.deleteDetection();
	expect(comp.confirmDeleteDialog).toBe(true);
	comp.cancelDeleteDetection();
	expect(comp.confirmDeleteDialog).toBe(false);
	comp.deleteDetection();
});

test('deleteDetectionFailure', async () => {
	resetPapi().mockPapi("delete", null, new Error("something bad"));
	const showErrorMock = mockShowError();
	comp.$root.papi['delete'] = mock;
	comp.$route.params.id = "testid"
	comp.deleteDetection();
	await comp.confirmDeleteDetection();
	expect(comp.confirmDeleteDialog).toBe(false);
	expect(mock).toHaveBeenCalledTimes(1);
	expect(mock).toHaveBeenCalledWith('/detection/testid');
	expect(comp.$root.loading).toBe(false);
	expect(showErrorMock).toHaveBeenCalledTimes(1);
	expect(comp.$router.length).toBe(0);
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

test('isFieldValid', () => {
	comp.$refs = {}
	expect(comp.isFieldValid('foo')).toBe(true)

	comp.$refs = { bar: { valid: false } }
	expect(comp.isFieldValid('foo')).toBe(true)
	expect(comp.isFieldValid('bar')).toBe(false)

	comp.$refs = { bar: { valid: true } }
	expect(comp.isFieldValid('bar')).toBe(true)
});

test('onNewDetectionLanguageChange', async () => {
	comp.ruleTemplates = {
		"suricata": 'a [publicId]',
		"strelka": 'b [publicId]',
		"elastalert": 'c [publicId]',
	}
	// no language means no engine means no request means no change
	comp.detect = { language: '', content: 'x' };
	await comp.onNewDetectionLanguageChange();
	expect(comp.detect.content).toBe('x');

	// yara, no publicId, results in template without publicId
	comp.detect = { language:'yara', content: 'x' };
	await comp.onNewDetectionLanguageChange();
	expect(comp.detect.content).toBe('b ');

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

test('cidrFormat', () => {
	const cidrFormat = comp.rules.cidrFormat;

	expect(cidrFormat('$HOME_NET')).toBe(true);
	expect(cidrFormat('$Home_Net')).toBe(true);
	expect(cidrFormat('!$DNS')).toBe(true);
	expect(cidrFormat('!$_')).toBe(true);
	expect(cidrFormat('0.0.0.0/16')).toBe(true);
	expect(cidrFormat('0::0/32')).toBe(true);
	expect(cidrFormat('2001:DB88:3333:4444:CCCC:DDDD:EEEE:FFFF/64')).toBe(true);
	expect(cidrFormat('2001:db88:3333:4444:cccc:dddd:eeee:ffff/64')).toBe(true);

	expect(cidrFormat('x')).toBe(comp.i18n.invalidCidrOrVar);
	expect(cidrFormat('#')).toBe(comp.i18n.invalidCidrOrVar);
	expect(cidrFormat('!#')).toBe(comp.i18n.invalidCidrOrVar);
	expect(cidrFormat('#1')).toBe(comp.i18n.invalidCidrOrVar);
	expect(cidrFormat('!#1')).toBe(comp.i18n.invalidCidrOrVar);
	expect(cidrFormat('_')).toBe(comp.i18n.invalidCidrOrVar);
	expect(cidrFormat('1.2.3.4')).toBe(comp.i18n.invalidCidrOrVar);
	expect(cidrFormat('0::0')).toBe(comp.i18n.invalidCidrOrVar);
	expect(cidrFormat('256.256.256.256/32')).toBe(comp.i18n.invalidCidrOrVar);
	expect(cidrFormat('0::0::0/16')).toBe(comp.i18n.invalidCidrOrVar);
	expect(cidrFormat('google.com')).toBe(comp.i18n.invalidCidrOrVar);
});

test('rule: required', () => {
	const required = comp.rules.required;

	expect(required('')).toBe(comp.$root.i18n.required);
	expect(required('a')).toBe(true);
});

test('rule: number', () => {
	const number = comp.rules.number;
	
	expect(number('a')).toBe(comp.$root.i18n.required);
	expect(number('1')).toBe(true);
	expect(number(1)).toBe(true);
	expect(number(1.0)).toBe(true);
	expect(number('1.0')).toBe(true);
	expect(number(1.1)).toBe(comp.$root.i18n.required);
	expect(number('1.1')).toBe(comp.$root.i18n.required);
});

test('rule: hours', () => {
	const hours = comp.rules.hours;

	expect(hours('a')).toBe(comp.$root.i18n.invalidHours);
	expect(hours('11111')).toBe(comp.$root.i18n.invalidHours);
	expect(hours('0.11111')).toBe(comp.$root.i18n.invalidHours);
	expect(hours('1.1.1')).toBe(comp.$root.i18n.invalidHours);
	expect(hours('1')).toBe(true);
	expect(hours('1111.1111')).toBe(true);
});

test('rule: minLength', () => {
	const minLength = comp.rules.minLength;
	const withLimit = minLength(1);

	expect(withLimit('')).toBe(comp.$root.i18n.ruleMinLen);
	expect(withLimit('a')).toBe(true);
	expect(withLimit('aa')).toBe(true);
});

test('rule: shortLengthLimit', () => {
	const shortLengthLimit = comp.rules.shortLengthLimit;
	const valLen99 = 'a'.repeat(99);
	const valLen100 = 'a'.repeat(100);

	expect(shortLengthLimit('a')).toBe(true);
	expect(shortLengthLimit(valLen99)).toBe(true);
	expect(shortLengthLimit(valLen100)).toBe(comp.$root.i18n.required);
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
});

test('checkChangedKey', () => {
	expect(Object.keys(comp.changedKeys).length).toBe(0);
	let id = "BHypPJABXppUUuo3UnEl";
	comp.changedKeys[id] = ['title', 'content'];
	expect(comp.checkChangedKey(id, 'title')).toBe(true);
	expect(comp.checkChangedKey(id, 'content')).toBe(true);
	expect(comp.checkChangedKey(id, 'severity')).toBe(false);
});