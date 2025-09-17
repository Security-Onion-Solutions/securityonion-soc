// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js')
require('./jobs.js')

const comp = getComponent('jobs');

test('isKind', () => {
	comp.kind = '';
	expect(comp.isKind('pcap')).toBe(true);
	expect(comp.isKind('foo')).toBe(false);
	comp.kind = 'pcap';
	expect(comp.isKind('pcap')).toBe(true);
	expect(comp.isKind('foo')).toBe(false);
	comp.kind = 'foo';
	expect(comp.isKind('pcap')).toBe(false);
	expect(comp.isKind('foo')).toBe(true);
	comp.kind = 'jobs';
	expect(comp.isKind('pcap')).toBe(true);
});

test('addJob', async () => {
	resetPapi();
	const mock = mockPapi('post', { data: 'addJobResponse' });
	comp.jobs = [];

	await comp.addJob('manager', 'importId', 'TCP', '1.1.1.1', '10000', '2.2.2.2', '20000', '2025/02/26 12:00:00 AM - 2025/02/28 11:59:59 PM');

	expect(mock).toHaveBeenCalledTimes(1);
	expect(mock).toHaveBeenCalledWith('job/', {
		nodeId: 'manager',
		filter: {
			importId: 'importId',
			protocol: 'tcp',
			srcIp: '1.1.1.1',
			srcPort: 10000,
			dstIp: '2.2.2.2',
			dstPort: 20000,
			beginTime: '2025-02-26T00:00:00Z',
			endTime: '2025-02-28T23:59:59Z',
		}
	});

	expect(comp.jobs).toEqual(['addJobResponse']);
});

test('deleteJob', async () => {
	resetPapi();
	const mock = mockPapi('delete');
	const jobToDelete = { id: 'job123', name: 'Test Job' };
	const otherJob = { id: 'job456', name: 'Another Job' };
	comp.jobs = [jobToDelete, otherJob];

	await comp.deleteJob(jobToDelete);

	expect(mock).toHaveBeenCalledTimes(1);
	expect(mock).toHaveBeenCalledWith('job/job123');
	expect(comp.jobs).toEqual([otherJob]); // Only the other job should remain
	expect(comp.jobs).not.toContain(jobToDelete);
});

test('addJob - minimal', async () => {
	resetPapi();
	const mock = mockPapi('post', { data: 'addJobResponse' });
	comp.jobs = [];

	await comp.addJob('manager');

	expect(mock).toHaveBeenCalledTimes(1);
	expect(mock).toHaveBeenCalledWith('job/', {
		nodeId: 'manager',
		filter: {
			importId: undefined,
			protocol: undefined,
			srcIp: undefined,
			srcPort: NaN,
			dstIp: undefined,
			dstPort: NaN,
		}
	});

	expect(comp.jobs).toEqual(['addJobResponse']);
});

test('isComplete', () => {
	// Test with JobStatusCompleted
	expect(comp.isComplete({ status: 1 })).toBe(true);

	// Test with other statuses
	expect(comp.isComplete({ status: 0 })).toBe(false);
	expect(comp.isComplete({ status: 2 })).toBe(false);
	expect(comp.isComplete({ status: 3 })).toBe(false);
	expect(comp.isComplete({ status: 99 })).toBe(false);
	expect(comp.isComplete({})).toBe(false);
});

test('downloadUrl', () => {
	comp.$root. apiUrl = 'http://localhost:8000/';
	const job = { id: 'testJob123' };
	expect(comp.downloadUrl(job)).toBe('http://localhost:8000/stream?jobId=testJob123');

	const anotherJob = { id: 'anotherJob456' };
	expect(comp.downloadUrl(anotherJob)).toBe('http://localhost:8000/stream?jobId=anotherJob456');
});

test('isViewable', () => {
	comp.kind = '';
	expect(comp.isViewable()).toBe(true);
	comp.kind = 'pcap';
	expect(comp.isViewable()).toBe(true);
	comp.kind = 'reports';
	expect(comp.isViewable()).toBe(false);
});

test('isDownloadable', () => {
	comp.kind = '';
	expect(comp.isDownloadable()).toBe(false);
	comp.kind = 'pcap';
	expect(comp.isDownloadable()).toBe(false);
	comp.kind = 'reports';
	expect(comp.isDownloadable()).toBe(true);
});

test('isDownloadReady', () => {
	// Test when job is complete and size > 0
	expect(comp.isDownloadReady({ status: 1, size: 100 })).toBe(true);

	// Test when job is complete but size is 0
	expect(comp.isDownloadReady({ status: 1, size: 0 })).toBe(false);

	// Test when job is not complete but size > 0
	expect(comp.isDownloadReady({ status: 0, size: 100 })).toBe(false);

	// Test when job is not complete and size is 0
	expect(comp.isDownloadReady({ status: 0, size: 0 })).toBe(false);
});

test('canCreate', () => {
	comp.kind = '';
	expect(comp.canCreate()).toBe(true);
	comp.kind = 'pcap';
	expect(comp.canCreate()).toBe(true);
	comp.kind = 'reports';
	expect(comp.canCreate()).toBe(false); // no license
});

test('isSensorJob', () => {
	comp.kind = '';
	expect(comp.isSensorJob()).toBe(true);
	comp.kind = 'pcap';
	expect(comp.isSensorJob()).toBe(true);
	comp.kind = 'reports';
	expect(comp.isSensorJob()).toBe(false);
});

test('getHeaders', () => {
	const originalHeaders = [{ title: 'ID', value: 'id' }];
	const originalReportHeaders = [{ title: 'Report ID', value: 'id' }];

	comp.headers = originalHeaders;
	comp.reportHeaders = originalReportHeaders;

	comp.kind = '';
	expect(comp.getHeaders()).toEqual(originalHeaders);

	comp.kind = 'pcap';
	expect(comp.getHeaders()).toEqual(originalHeaders);

	comp.kind = 'reports';
	expect(comp.getHeaders()).toEqual(originalReportHeaders);
});

test('getDescription', () => {
	comp.i18n = {
		"pcap": "PCAP",
		"zeek": "Zeek"
	};

	// Test for kind != 'reports'
	comp.kind = '';
	let job1 = { filter: { parameters: { someParam: 'value' } } };
	expect(comp.getDescription(job1)).toEqual('{"someParam":"value"}');

	comp.kind = 'pcap';
	let job2 = { filter: { parameters: { anotherParam: 'anotherValue' } } };
	expect(comp.getDescription(job2)).toEqual('{"anotherParam":"anotherValue"}');

	// Test for kind == 'reports'
	comp.kind = 'reports';
	let job3 = { filter: { parameters: { type: 'pcap', id: '123' } }, fileExtension: 'pcap' };
	expect(comp.getDescription(job3)).toBe('PCAP 123 [PCAP]');

	let job4 = { filter: { parameters: { type: 'zeek', id: '456' } }, fileExtension: 'log' };
	expect(comp.getDescription(job4)).toBe('zeek 456 [log]');
});

describe('saveAddJobForm', () => {
	let localStorageMock;
	let localStorageDescriptor;

	beforeEach(() => {
		const dataStore = {};
		localStorageMock = new Proxy({
			setItem: jest.fn((key, value) => { dataStore[key] = value; }),
			getItem: jest.fn((key) => dataStore[key]),
			removeItem: jest.fn((key) => { delete dataStore[key]; }),
			clear: jest.fn(() => { Object.keys(dataStore).forEach(key => delete dataStore[key]); })
		}, {
			set: (target, property, value) => {
				if (typeof property === 'string') {
					dataStore[property] = value;
				}
				return true;
			},
			get: (target, property) => {
				if (property in target) {
					return target[property];
				}
				return dataStore[property];
			},
			deleteProperty: (target, property) => {
				if (typeof property === 'string') {
					delete dataStore[property];
				}
				return true;
			}
		});
		localStorageDescriptor = Object.getOwnPropertyDescriptor(global, 'localStorage');
		Object.defineProperty(global, 'localStorage', {
			value: localStorageMock,
			writable: true,
			configurable: true,
		});
		comp.form = {
			sensorId: null,
			importId: null,
			protocol: null,
			srcIp: null,
			srcPort: null,
			dstIp: null,
			dstPort: null,
			type: null,
			timeframe: '',
		};
		comp.kind = '';
	});

	afterEach(() => {
		if (localStorageDescriptor) {
			Object.defineProperty(global, 'localStorage', localStorageDescriptor);
		} else {
			delete global.localStorage;
		}
	});

	test('should save all form fields to localStorage when they have values', () => {
		comp.form = {
			sensorId: 'sensor1',
			importId: 'import1',
			protocol: 'TCP',
			srcIp: '192.168.1.1',
			srcPort: 80,
			dstIp: '192.168.1.2',
			dstPort: 443,
			timeframe: '2025/01/01 12:00:00 AM - 2025/01/01 11:59:59 PM',
		};
		comp.kind = 'pcap';

		comp.saveAddJobForm();

		expect(localStorageMock.getItem('settings.jobs.addJobForm.sensorId')).toBe('sensor1');
		expect(localStorageMock.getItem('settings.jobs.addJobForm.importId')).toBe('import1');
		expect(localStorageMock.getItem('settings.jobs.addJobForm.protocol')).toBe('TCP');
		expect(localStorageMock.getItem('settings.jobs.addJobForm.srcIp')).toBe('192.168.1.1');
		expect(localStorageMock.getItem('settings.jobs.addJobForm.srcPort')).toBe(80);
		expect(localStorageMock.getItem('settings.jobs.addJobForm.dstIp')).toBe('192.168.1.2');
		expect(localStorageMock.getItem('settings.jobs.addJobForm.dstPort')).toBe(443);
		expect(localStorageMock.getItem('settings.jobs.addJobForm.pcap.timeframe')).toBe('2025/01/01 12:00:00 AM - 2025/01/01 11:59:59 PM');
	});

	test('should not save form fields to localStorage if they are null or empty', () => {
		comp.form = {
			sensorId: null,
			importId: '',
			protocol: null,
			srcIp: '',
			srcPort: null,
			dstIp: '',
			dstPort: null,
			timeframe: '',
		};
		comp.kind = 'reports';

		comp.saveAddJobForm();

		expect(localStorageMock.getItem('settings.jobs.addJobForm.sensorId')).toBeUndefined();
		expect(localStorageMock.getItem('settings.jobs.addJobForm.importId')).toBeUndefined();
		expect(localStorageMock.getItem('settings.jobs.addJobForm.protocol')).toBeUndefined();
		expect(localStorageMock.getItem('settings.jobs.addJobForm.srcIp')).toBeUndefined();
		expect(localStorageMock.getItem('settings.jobs.addJobForm.srcPort')).toBeUndefined();
		expect(localStorageMock.getItem('settings.jobs.addJobForm.dstIp')).toBeUndefined();
		expect(localStorageMock.getItem('settings.jobs.addJobForm.dstPort')).toBeUndefined();
		expect(localStorageMock.getItem('settings.jobs.addJobForm.reports.timeframe')).toBeUndefined();
	});
});
describe('submitAddJob', () => {
	let originalAddExportJob, originalAddJob, originalSaveAddJobForm, originalLoadData;
	let setTimeoutSpy;

	beforeEach(() => {
		originalAddExportJob = comp.addExportJob;
		originalAddJob = comp.addJob;
		originalSaveAddJobForm = comp.saveAddJobForm;
		originalLoadData = comp.loadData;

		comp.addExportJob = jest.fn();
		comp.addJob = jest.fn();
		comp.saveAddJobForm = jest.fn();
		comp.loadData = jest.fn();
		setTimeoutSpy = jest.spyOn(global, 'setTimeout').mockImplementation((fn) => fn());

		comp.dialog = true;
		comp.form = {
			sensorId: 'sensor1',
			importId: 'import1',
			protocol: 'TCP',
			srcIp: '192.168.1.1',
			srcPort: 80,
			dstIp: '192.168.1.2',
			dstPort: 443,
			timeframe: '2025/01/01 12:00:00 AM - 2025/01/01 11:59:59 PM',
		};
	});

	afterEach(() => {
		comp.addExportJob = originalAddExportJob;
		comp.addJob = originalAddJob;
		comp.saveAddJobForm = originalSaveAddJobForm;
		comp.loadData = originalLoadData;
		setTimeoutSpy.mockRestore();
	});

	test('calls addExportJob when kind is reports', () => {
		comp.kind = 'reports';
		comp.submitAddJob();
		expect(comp.addExportJob).toHaveBeenCalled();
		expect(comp.addJob).not.toHaveBeenCalled();
		expect(comp.dialog).toBe(false);
		expect(comp.saveAddJobForm).toHaveBeenCalled();
		expect(comp.loadData).toHaveBeenCalled();
	});

	test('calls addJob when kind is not reports', () => {
		comp.kind = 'pcap';
		comp.submitAddJob();
		expect(comp.addJob).toHaveBeenCalledWith(
			'sensor1', 'import1', 'TCP', '192.168.1.1', 80, '192.168.1.2', 443, '2025/01/01 12:00:00 AM - 2025/01/01 11:59:59 PM'
		);
		expect(comp.addExportJob).not.toHaveBeenCalled();
		expect(comp.dialog).toBe(false);
		expect(comp.saveAddJobForm).toHaveBeenCalled();
		expect(comp.loadData).toHaveBeenCalled();
	});
});
describe('addExportJob', () => {
	let originalExport;
	let originalMoment;
	let mockExport;
	let mockMoment;
	let mockFormat;

	beforeEach(() => {
		// Mock $root.export
		mockExport = jest.fn();
		originalExport = comp.$root.export;
		comp.$root.export = mockExport;

		// Mock moment
		mockFormat = jest.fn().mockReturnValue('2025-07-24T12:00:00Z');
		mockMoment = jest.fn(() => ({ format: mockFormat }));
		originalMoment = global.moment;
		global.moment = mockMoment;

		comp.form = {
			type: 'productivity',
			timeframe: '',
		};
		comp.i18n = { timePickerFormat: 'YYYY/MM/DD hh:mm:ss A' };
	});

	afterEach(() => {
		comp.$root.export = originalExport;
		global.moment = originalMoment;
	});

	test('calls export with type only when no timeframe', () => {
		comp.form.type = 'productivity';
		comp.form.timeframe = '';
		comp.addExportJob();
		expect(mockExport).toHaveBeenCalledWith(
			{ description: 'Productivity Report', type: 'productivity' },
			undefined,
			undefined
		);
	});

	test('calls export with parsed begin and end dates when timeframe is set', () => {
		comp.form.type = 'productivity';
		comp.form.timeframe = '2025/07/24 12:00:00 AM - 2025/07/25 11:59:59 PM';
		comp.addExportJob();
		expect(mockMoment).toHaveBeenCalledWith('2025/07/24 12:00:00 AM', 'YYYY/MM/DD hh:mm:ss A');
		expect(mockMoment).toHaveBeenCalledWith('2025/07/25 11:59:59 PM', 'YYYY/MM/DD hh:mm:ss A');
		expect(mockExport).toHaveBeenCalledWith(
			{ description: 'Productivity Report', type: 'productivity' },
			'2025-07-24T12:00:00Z',
			'2025-07-24T12:00:00Z'
		);
	});
});

describe('clearAddJobForm', () => {
	let localStorageMock;
	let localStorageDescriptor;
	let original$ = global.$;
	let mockJQueryVal;

	beforeEach(() => {
		const dataStore = {};
		localStorageMock = new Proxy({
			setItem: jest.fn((key, value) => { dataStore[key] = value; }),
			getItem: jest.fn((key) => dataStore[key]),
			removeItem: jest.fn((key) => { delete dataStore[key]; }),
			clear: jest.fn(() => { Object.keys(dataStore).forEach(key => delete dataStore[key]); })
		}, {
			set: (target, property, value) => {
				if (typeof property === 'string') {
					dataStore[property] = value;
				}
				return true;
			},
			get: (target, property) => {
				if (property in target) {
					return target[property];
				}
				return dataStore[property];
			},
			deleteProperty: (target, property) => {
				if (typeof property === 'string') {
					delete dataStore[property];
				}
				return true;
			}
		});
		localStorageDescriptor = Object.getOwnPropertyDescriptor(global, 'localStorage');
		Object.defineProperty(global, 'localStorage', {
			value: localStorageMock,
			writable: true,
			configurable: true,
		});
		mockJQueryVal = jest.fn();
		global.$ = jest.fn(() => ({
			val: mockJQueryVal
		}));
		comp.form = {
			sensorId: 'sensor1',
			importId: 'import1',
			protocol: 'TCP',
			srcIp: '192.168.1.1',
			srcPort: 80,
			dstIp: '192.168.1.2',
			dstPort: 443,
			type: 'productivity',
			timeframe: '2025/01/01 12:00:00 AM - 2025/01/01 11:59:59 PM',
		};
		comp.kind = 'pcap';
		comp.isKind = jest.fn((kind) => kind === comp.kind);
	});

	afterEach(() => {
		if (localStorageDescriptor) {
			Object.defineProperty(global, 'localStorage', localStorageDescriptor);
		} else {
			delete global.localStorage;
		}
		global.$ = original$;
	});

	test('should clear all form fields and remove pcap related items from localStorage when kind is pcap', () => {
		comp.clearAddJobForm();

		expect(comp.form.sensorId).toBeNull();
		expect(comp.form.importId).toBeNull();
		expect(comp.form.protocol).toBeNull();
		expect(comp.form.srcIp).toBeNull();
		expect(comp.form.srcPort).toBeNull();
		expect(comp.form.dstIp).toBeNull();
		expect(comp.form.dstPort).toBeNull();
		expect(comp.form.timeframe).toBe('');
		expect(mockJQueryVal).toHaveBeenCalledWith('');

		expect(localStorageMock.removeItem).toHaveBeenCalledWith('settings.jobs.addJobForm.sensorId');
		expect(localStorageMock.removeItem).toHaveBeenCalledWith('settings.jobs.addJobForm.importId');
		expect(localStorageMock.removeItem).toHaveBeenCalledWith('settings.jobs.addJobForm.protocol');
		expect(localStorageMock.removeItem).toHaveBeenCalledWith('settings.jobs.addJobForm.srcIp');
		expect(localStorageMock.removeItem).toHaveBeenCalledWith('settings.jobs.addJobForm.srcPort');
		expect(localStorageMock.removeItem).toHaveBeenCalledWith('settings.jobs.addJobForm.dstIp');
		expect(localStorageMock.removeItem).toHaveBeenCalledWith('settings.jobs.addJobForm.dstPort');
		expect(localStorageMock.removeItem).toHaveBeenCalledWith('settings.jobs.addJobForm.pcap.timeframe');
	});

	test('should clear all form fields and only remove timeframe from localStorage when kind is not pcap', () => {
		comp.kind = 'reports';
		comp.clearAddJobForm();

		expect(comp.form.sensorId).toBeNull();
		expect(comp.form.importId).toBeNull();
		expect(comp.form.protocol).toBeNull();
		expect(comp.form.srcIp).toBeNull();
		expect(comp.form.srcPort).toBeNull();
		expect(comp.form.dstIp).toBeNull();
		expect(comp.form.dstPort).toBeNull();
		expect(comp.form.timeframe).toBe('');
		expect(mockJQueryVal).toHaveBeenCalledWith('');

		expect(localStorageMock.removeItem).not.toHaveBeenCalledWith('settings.jobs.addJobForm.sensorId');
		expect(localStorageMock.removeItem).not.toHaveBeenCalledWith('settings.jobs.addJobForm.importId');
		expect(localStorageMock.removeItem).not.toHaveBeenCalledWith('settings.jobs.addJobForm.protocol');
		expect(localStorageMock.removeItem).not.toHaveBeenCalledWith('settings.jobs.addJobForm.srcIp');
		expect(localStorageMock.removeItem).not.toHaveBeenCalledWith('settings.jobs.addJobForm.srcPort');
		expect(localStorageMock.removeItem).not.toHaveBeenCalledWith('settings.jobs.addJobForm.dstIp');
		expect(localStorageMock.removeItem).not.toHaveBeenCalledWith('settings.jobs.addJobForm.dstPort');
		expect(localStorageMock.removeItem).toHaveBeenCalledWith('settings.jobs.addJobForm.reports.timeframe');
	});
});

test('getReportTypes', () => {
	// Mock the standardReportTypes
	comp.standardReportTypes = [
		{ title: 'Productivity Report', value: 'productivity' }
	];

	// Test with no custom reports
	comp.$root.getCustomReports = jest.fn(() => ({}));
	
	let result = comp.getReportTypes();
	expect(result).toEqual([
		{ title: 'Productivity Report', value: 'productivity' }
	]);
	expect(comp.$root.getCustomReports).toHaveBeenCalled();

	// Test with custom reports
	comp.$root.getCustomReports = jest.fn(() => ({
		'custom_report1.md': 'Security Incident Report',
		'monthly_summary.md': 'Monthly Analysis Summary',
		'threat_intel.md': 'Threat Intelligence Report'
	}));

	result = comp.getReportTypes();
	expect(result).toEqual([
		{ title: 'Productivity Report', value: 'productivity' },
		{ title: 'Security Incident Report', value: 'custom_report1.md' },
		{ title: 'Monthly Analysis Summary', value: 'monthly_summary.md' },
		{ title: 'Threat Intelligence Report', value: 'threat_intel.md' }
	]);
	expect(comp.$root.getCustomReports).toHaveBeenCalled();

	// Test with empty standard reports and custom reports
	comp.standardReportTypes = [];
	comp.$root.getCustomReports = jest.fn(() => ({
		'single_custom.md': 'Single Custom Report'
	}));

	result = comp.getReportTypes();
	expect(result).toEqual([
		{ title: 'Single Custom Report', value: 'single_custom.md' }
	]);

	// Test with multiple standard reports and custom reports
	comp.standardReportTypes = [
		{ title: 'Productivity Report', value: 'productivity' },
		{ title: 'Case Report', value: 'case' }
	];
	comp.$root.getCustomReports = jest.fn(() => ({
		'weekly_report.md': 'Weekly Status Report'
	}));

	result = comp.getReportTypes();
	expect(result).toEqual([
		{ title: 'Productivity Report', value: 'productivity' },
		{ title: 'Case Report', value: 'case' },
		{ title: 'Weekly Status Report', value: 'weekly_report.md' }
	]);
});
