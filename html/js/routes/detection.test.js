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
	comp.created();
});

test('extract suricata', () => {
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
	expect(comp.extractedCreated).toBe('2020-01-01');
	expect(comp.extractedUpdated).toBe('2020-01-02');
});

test('extract strelka', () => {
	comp.detect = {
		engine: 'strelka',
		content: 'rule Test {\nmeta:\nreference1="example.com"\ndate = "2020-01-01";\nauthor = "Bob";\nstrings:\n$a = "test"\ncondition:\n$a\n}',
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
		{ type: 'url', text:'example.com', link: 'http://example.com' },
	]);
	expect(comp.extractedLogic).toBe('strings:\n$a = "test"\ncondition:\n$a');
	expect(comp.extractedCreated).toBe('2020-01-01');
	expect(comp.extractedUpdated).toBe('');
});

test('extract elastalert', () => {
	comp.detect = {
		engine: 'elastalert',
		content: `title: APT29 2018 Phishing Campaign File Indicators\nid: 3a3f81ca-652c-482b-adeb-b1c804727f74\nrelated:\n  - id: 7453575c-a747-40b9-839b-125a0aae324b # ProcessCreation\n    type: derived\nstatus: stable\ndescription: Detects indicators of APT 29 (Cozy Bear) phishing-campaign as reported by mandiant\nreferences:\n  - https://twitter.com/DrunkBinary/status/1063075530180886529\n  - https://www.mandiant.com/resources/blog/not-so-cozy-an-uncomfortable-examination-of-a-suspected-apt29-phishing-campaign\nauthor: '@41thexplorer'\ndate: 2018/11/20\nmodified: 2023/02/20\ntags:\n  - attack.defense_evasion\n  - attack.t1218.011\n  - detection.emerging_threats\nlogsource:\n  product: windows\n  category: file_event\ndetection:\n  selection:\n    TargetFilename|contains:\n      - 'ds7002.lnk'\n      - 'ds7002.pdf'\n      - 'ds7002.zip'\n    condition: selection\nfalsepositives:\n  - Unlikely\nlevel: critical`,
		title: 'Title',
	};
	comp.$route = { params: { id: '123' } };

	comp.extractSummary();
	comp.extractReferences();
	comp.extractLogic();
	comp.extractDetails();

	expect(comp.extractedSummary).toBe('Title');
	expect(comp.extractedReferences).toEqual([
		{ type: 'url', text: 'https://twitter.com/DrunkBinary/status/1063075530180886529', link: 'https://twitter.com/DrunkBinary/status/1063075530180886529' },
		{ type: 'url', text: 'https://www.mandiant.com/resources/blog/not-so-cozy-an-uncomfortable-examination-of-a-suspected-apt29-phishing-campaign', link: 'https://www.mandiant.com/resources/blog/not-so-cozy-an-uncomfortable-examination-of-a-suspected-apt29-phishing-campaign' },
	]);
	expect(comp.extractedLogic).toBe('logsource:\n  product: windows\n  category: file_event\ndetection:\n  selection:\n    TargetFilename|contains:\n      - ds7002.lnk\n      - ds7002.pdf\n      - ds7002.zip\n    condition: selection');
	expect(comp.extractedCreated).toBe('2018/11/20');
	expect(comp.extractedUpdated).toBe('2023/02/20');
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
})

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