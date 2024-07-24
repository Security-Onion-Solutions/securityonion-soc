// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('./test_common.js');
require('./test_common.js');

const app = global.getApp();

test('escape', () => {
  expect(app.escape('')).toBe('');
  expect(app.escape('hello')).toBe('hello');
  expect(app.escape('hello "bob" the builder\\bricklayer')).toBe('hello \\\"bob\\\" the builder\\\\bricklayer');
  expect(app.escape(1234)).toBe(1234);
});

test('base64encode', () => {
  expect(app.base64encode('')).toBe('');
  expect(app.base64encode('hello')).toBe('aGVsbG8=');
});

test('processAncestors', () => {
  expect(app.processAncestors([])).toBe('');
  expect(app.processAncestors(['asdf1'])).toBe('asdf1');
  expect(app.processAncestors(['asdf1','asdf2','asdf3'])).toBe('asdf1\" OR process.entity_id:\"asdf2\" OR process.entity_id:\"asdf3');
});

test('replaceActionVar', () => {
  expect(app.replaceActionVar('test here', 'foo', 'bar', true)).toBe('test here');
  expect(app.replaceActionVar('test {bar} here', 'foo', 'bar', true)).toBe('test {bar} here');
  expect(app.replaceActionVar('test {foo} here', 'foo', 'bar', true)).toBe('test bar here');
  expect(app.replaceActionVar('test {foo} here', 'foo', 'sand bar', true)).toBe('test sand%20bar here');
  expect(app.replaceActionVar('test {foo|base64} here', 'foo', 'sand bar', true)).toBe('test c2FuZCBiYXI%3D here');
  expect(app.replaceActionVar('test {foo|escape} here', 'foo', 'sand "bar\\bad"', false)).toBe('test sand \\\"bar\\\\bad\\\" here');
  expect(app.replaceActionVar('test {foo|escape} here', 'foo', 'sand "bar\\bad"', true)).toBe('test sand%20%5C%22bar%5C%5Cbad%5C%22 here');
  expect(app.replaceActionVar('test {foo|escape|base64} here', 'foo', 'sand "bar\\bad"', false)).toBe('test c2FuZCBcImJhclxcYmFkXCI= here');
  expect(app.replaceActionVar('test {foo|escape|base64} here', 'foo', 'sand "bar\\bad"', true)).toBe('test c2FuZCBcImJhclxcYmFkXCI%3D here');
  expect(app.replaceActionVar('test {foo|processAncestors} here', 'foo', '', true)).toBe('test  here');
  expect(app.replaceActionVar('test {foo|processAncestors} here', 'foo', 'bar', true)).toBe('test bar here');
  expect(app.replaceActionVar('test {foo|processAncestors} here', 'foo', ['asdf1','asdf2','asdf3'], true)).toBe('test asdf1%22%20OR%20process.entity_id%3A%22asdf2%22%20OR%20process.entity_id%3A%22asdf3 here');
  expect(app.replaceActionVar('test {foo} here', 'foo', null, true)).toBe('test {foo} here');
  expect(app.replaceActionVar('test {foo} here', 'foo', undefined, true)).toBe('test {foo} here');
});

test('formatMarkdown', () => {
  expect(app.formatMarkdown('```code```')).toBe('<p><code>code</code></p>\n');
  expect(app.formatMarkdown('<scripts src="https://somebad.place"></script>bad')).toBe('<p>bad</p>\n');
});

test('formatHours', () => {
  expect(app.formatHours(null)).toBe("0.00");
  expect(app.formatHours(undefined)).toBe("0.00");
  expect(app.formatHours("")).toBe("0.00");
  expect(app.formatHours(0)).toBe("0.00");
  expect(app.formatHours(false)).toBe("0.00");
  expect(app.formatHours(1)).toBe("1.00");
  expect(app.formatHours(1.0)).toBe("1.00");
  expect(app.formatHours(10.14)).toBe("10.14");
});

test('formatDecimals', () => {
  expect(app.formatDecimal1(null)).toBe("0.0");
  expect(app.formatDecimal2(null)).toBe("0.00");
  expect(app.formatDecimal1(undefined)).toBe("0.0");
  expect(app.formatDecimal2(undefined)).toBe("0.00");
  expect(app.formatDecimal1("")).toBe("0.0");
  expect(app.formatDecimal2("")).toBe("0.00");
  expect(app.formatDecimal1(0)).toBe("0.0");
  expect(app.formatDecimal2(0)).toBe("0.00");
  expect(app.formatDecimal1(10.1445)).toBe("10.1");
  expect(app.formatDecimal2(10.1445)).toBe("10.14");
});

test('formatCount', () => {
  expect(app.formatCount(null)).toBe("0");
  expect(app.formatCount(123)).toBe("123");
  expect(app.formatCount(1234)).toBe("1,234");
});

test('formatStringArray', () => {
  expect(app.formatStringArray(['hi','there','foo'])).toBe('hi, there, foo');
  expect(app.formatStringArray(['hi','there'])).toBe('hi, there');
  expect(app.formatStringArray(['hi'])).toBe('hi');
  expect(app.formatStringArray([])).toBe('');
});

test('generateDatePickerPreselects', () => {
  const preselects = app.generateDatePickerPreselects();
  expect(preselects[app.i18n.datePreselectToday].length).toBe(2);
  expect(preselects[app.i18n.datePreselectYesterday].length).toBe(2);
  expect(preselects[app.i18n.datePreselectThisWeek].length).toBe(2);
  expect(preselects[app.i18n.datePreselectLastWeek].length).toBe(2);
  expect(preselects[app.i18n.datePreselectThisMonth].length).toBe(2);
  expect(preselects[app.i18n.datePreselectLastMonth].length).toBe(2);
  expect(preselects[app.i18n.datePreselectPrevious3d].length).toBe(2);
  expect(preselects[app.i18n.datePreselectPrevious4d].length).toBe(2);
  expect(preselects[app.i18n.datePreselectPrevious7d].length).toBe(2);
  expect(preselects[app.i18n.datePreselectPrevious30d].length).toBe(2);
  expect(preselects[app.i18n.datePreselect3dToNow].length).toBe(2);
  expect(preselects[app.i18n.datePreselect4dToNow].length).toBe(2);
  expect(preselects[app.i18n.datePreselect7dToNow].length).toBe(2);
  expect(preselects[app.i18n.datePreselect30dToNow].length).toBe(2);
});

test('populateUserDetailsEmpty', async () => {
  const obj = {};
  await app.populateUserDetails(obj, "userId", "owner")
  expect(obj.owner).toBe(undefined);
});

test('populateUserDetailsNonEmptyNoUser', async () => {
  const obj = {userId:'123'}
  app.users = [{id:'111',email:'hi@there.net'}];
  app.usersLoadedTime = new Date().time;
  await app.populateUserDetails(obj, "userId", "owner")
  expect(obj.owner).toBe(undefined);
});

test('populateUserDetails', async () => {
  const obj = {userId:'123'};
  app.users = [{id:'123',email:'hi@there.net'}];
  app.usersLoadedTime = new Date().time;
  await app.populateUserDetails(obj, "userId", "owner")
  expect(obj.owner).toBe('hi@there.net');
});

test('populateUserDetailsSystem', async () => {
  const obj = {userId:'00000000-0000-0000-0000-000000000000'};
  app.users = [{id:'123',email:'hi@there.net'}];
  app.usersLoadedTime = new Date().time;
  await app.populateUserDetails(obj, "userId", "owner")
  expect(obj.owner).toBe(app.i18n.systemUser);
});

test('populateUserDetailsAgent', async () => {
  const obj = {userId:'agent'};
  app.users = [{id:'123',email:'hi@there.net'}];
  app.usersLoadedTime = new Date().time;
  await app.populateUserDetails(obj, "userId", "owner")
  expect(obj.owner).toBe(app.i18n.systemUser);
});

test('isUserAdmin', async () => {
  var user = {id:'123',email:'hi@there.net',roles:['nope', 'peon']};
  app.user = user;
  expect(app.isUserAdmin(user)).toBe(false);
  expect(app.isUserAdmin()).toBe(false);

  user.roles.push("superuser");
  expect(app.isUserAdmin(user)).toBe(true);
  expect(app.isUserAdmin()).toBe(true);
});

test('isMyUser', () => {
  app.user = null;
  expect(app.isMyUser()).toBe(false);
  var user = {id:'123',email:'hi@there.net',roles:['nope', 'peon']};
  expect(app.isMyUser(user)).toBe(false);
  app.user = user;
  expect(app.isMyUser(user)).toBe(true);
  expect(app.isMyUser()).toBe(false);
});

test('loadServerSettings', async () => {
  const fakeInfo = {
    srvToken: 'xyz',
    version: 'myVersion',
    license: 'myLicense',
    parameters: {
      webSocketTimeoutMs: 456,
      apiTimeoutMs: 123,
      cacheExpirationMs: 789,
      tipTimeoutMs: 222,
      tools: [{"name": "tool1"},{"name": "tool2"}],
      inactiveTools: ['tool2'],
      casesEnabled: true,
      detectionsEnabled: true,
    },
    elasticVersion: 'myElasticVersion',
    timezones: ['UTC'],
    userId: 'myUserId'
  };

  expect(app.casesEnabled).toBe(false);
  expect(app.detectionsEnabled).toBe(false);
  const getElementByIdMock = global.document.getElementById = jest.fn().mockReturnValueOnce(true);
  resetPapi();
  const mock = mockPapi("get", {data: fakeInfo});
  const showErrorMock = mockShowError(true);
  await app.loadServerSettings();
  expect(mock).toHaveBeenCalledWith('info');
  expect(showErrorMock).toHaveBeenCalledTimes(0);
  expect(app.version).toBe('myVersion');
  expect(app.license).toBe('myLicense');
  expect(app.elasticVersion).toBe('myElasticVersion');
  expect(app.timezones[0]).toBe('UTC');
  expect(app.wsConnectionTimeout).toBe(456);
  expect(app.connectionTimeout).toBe(123);
  expect(app.cacheRefreshIntervalMs).toBe(789);
  expect(app.tipTimeout).toBe(222);
  expect(app.tools[0].name).toBe('tool1');
  expect(app.tools[0].enabled).toBe(true);
  expect(app.tools[1].name).toBe('tool2');
  expect(app.tools[1].enabled).toBe(false);
  expect(app.casesEnabled).toBe(true);
  expect(app.detectionsEnabled).toBe(true);
  expect(app.papi.defaults.headers.common['X-Srv-Token']).toBe('xyz');
});

test('localizeMessage', () => {
  expect(app.localizeMessage(null)).toBe("");
  expect(app.localizeMessage('create')).toBe("Create");
});

test('truncate', () => {
  expect(app.truncate("short", 10)).toBe("short");
  expect(app.truncate("atthelimit!", 10)).toBe("atthelimit!");
  expect(app.truncate("atthelimit!!", 10)).toBe("atthelimit!!");
  expect(app.truncate("atthelimit!!!", 10)).toBe("atthelimit!!!");
  expect(app.truncate("much longer value", 10)).toBe("much...value");
});

test('localSettings', () => {
	app.toolbar = true;
	app.saveLocalSettings();
	app.toolbar = null;
	app.loadLocalSettings();
	expect(app.toolbar).toBe(true);
});

test('maximize', () => {
	const element = document.createElement('div');
	element.style.width = '12px';
	element.style.height = '13px';

	const cancelMock = jest.fn();
	expect(app.isMaximized()).toBe(false);

	app.maximize(element, cancelMock);

	expect(app.isMaximized()).toBe(true);
	expect(app.maximizedOrigWidth).toBe("12px");
	expect(app.maximizedOrigHeight).toBe("13px");
	expect(element.classList).toContain('maximized');
	expect(document.documentElement.classList).toContain('maximized-bg');

	app.unmaximize(true);

	expect(app.isMaximized()).toBe(false);
	expect(app.maximizedCancelFn).toBeNull();
	expect(cancelMock).toHaveBeenCalledTimes(1);
	expect(element.classList).not.toContain('maximized');
	expect(document.documentElement.classList).not.toContain('maximized-bg');

	// Maximize again
	app.maximize(element);

	expect(app.isMaximized()).toBe(true);

	app.unmaximize(false);

	expect(app.isMaximized()).toBe(false);

	// should still only have been called once
	expect(cancelMock).toHaveBeenCalledTimes(1);

	expect(app.maximizedCancelFn).toBeNull();
	expect(element.classList).not.toContain('maximized');
	expect(document.documentElement.classList).not.toContain('maximized-bg');
});

test('getUsers', async () => {
	const fakeUsers = [{ status: ''}, {status: 'locked'}];
	var mock = mockPapi("get", {data: fakeUsers});
  const showErrorMock = mockShowError(true);

  const users = await app.getUsers();

  expect(mock).toHaveBeenCalledWith('users/');
  expect(showErrorMock).toHaveBeenCalledTimes(0);
  expect(users.length).toBe(2);

	mock = mockPapi("get", {data: fakeUsers});
  const activeUsers = await app.getActiveUsers();

  expect(mock).toHaveBeenCalledTimes(2);
  expect(showErrorMock).toHaveBeenCalledTimes(0);
  expect(activeUsers.length).toBe(1);
});

test('setFavicon', () => {
  var svg_icon = {};
  var png_icon = {};
  svg_icon.href = "https://somehost.com/so.svg";
  png_icon.href = "https://somehost.com/so.png";

  var mock = jest.fn();
  mock.mockImplementation((path) => {
    if (path.indexOf("png") != -1) {
      return png_icon;
    }
    return svg_icon;
  });
  global.document.querySelector = mock;

  // Should be no change
  app.connected = true;
  app.setFavicon();
  expect(svg_icon.href).toBe("https://somehost.com/so.svg");
  expect(png_icon.href).toBe("https://somehost.com/so.png");

  // Needs attention
  app.connected = false;
  app.setFavicon();
  expect(svg_icon.href).toBe("https://somehost.com/so-attention.svg");
  expect(png_icon.href).toBe("https://somehost.com/so-attention.png");

  // Repeat the tests but with a hyphen in the hostname.
  svg_icon.href = "https://some-host.com/so.svg";
  png_icon.href = "https://some-host.com/so.png";

  // Should be no change
  app.connected = true;
  app.setFavicon();
  expect(svg_icon.href).toBe("https://some-host.com/so.svg");
  expect(png_icon.href).toBe("https://some-host.com/so.png");

  // Needs attention and host has hyphen
  app.connected = false;
  app.setFavicon();
  expect(svg_icon.href).toBe("https://some-host.com/so-attention.svg");
  expect(png_icon.href).toBe("https://some-host.com/so-attention.png");

  // Repeat the tests but with a hyphen in the hostname AND dark mode
  var darkMock = jest.fn();
  darkMock.mockImplementation((pattern) => { return { matches: true }; });
  global.window.matchMedia = darkMock;
  svg_icon.href = "https://some-host.com/so.svg";
  png_icon.href = "https://some-host.com/so.png";

  // Should be no change
  app.connected = true;
  app.setFavicon();
  expect(svg_icon.href).toBe("https://some-host.com/so-dark.svg");
  expect(png_icon.href).toBe("https://some-host.com/so-dark.png");

  // Needs attention and host has hyphen
  app.connected = false;
  app.setFavicon();
  expect(svg_icon.href).toBe("https://some-host.com/so-dark-attention.svg");
  expect(png_icon.href).toBe("https://some-host.com/so-dark-attention.png");
});

test('isLicenseUnprovisioned', () => {
  app.licenseStatus = null;
  expect(app.isLicenseUnprovisioned()).toBe(true);

  app.licenseStatus = "unprovisioned";
  expect(app.isLicenseUnprovisioned()).toBe(true);

  app.licenseStatus = "active";
  expect(app.isLicenseUnprovisioned()).toBe(false);
});

test('isLicensed', () => {
  app.licenseKey = null;
  app.licenseStatus = null;
  expect(app.isLicensed('foo')).toBe(false);

  app.licenseKey = { features: [] };
  app.licenseStatus = "unprovisioned";
  expect(app.isLicensed('foo')).toBe(false);

  app.licenseKey = { features: [] };
  app.licenseStatus = "active";
  expect(app.isLicensed('foo')).toBe(true);

  app.licenseKey = { features: ['bar'] };
  app.licenseStatus = "active";
  expect(app.isLicensed('foo')).toBe(false);

  app.licenseKey = { features: ['bar','foo'] };
  app.licenseStatus = "active";
  expect(app.isLicensed('foo')).toBe(true);
});

test('colorLicenseStatus', () => {
  expect(app.colorLicenseStatus('foo')).toBe('info');
  expect(app.colorLicenseStatus(null)).toBe('info');
  expect(app.colorLicenseStatus("active")).toBe('success');
  expect(app.colorLicenseStatus("exceeded")).toBe('error');
  expect(app.colorLicenseStatus("expired")).toBe('warning');
  expect(app.colorLicenseStatus("invalid")).toBe('error');
  expect(app.colorLicenseStatus("pending")).toBe('warning');
});

test('isIPv4', () => {
  expect(app.isIPv4('')).toBe(false);
  expect(app.isIPv4(null)).toBe(false);
  expect(app.isIPv4('foo')).toBe(false);
  expect(app.isIPv4(10)).toBe(false);
  expect(app.isIPv4('1.2.3')).toBe(false);
  expect(app.isIPv4('1.2.3.4.5')).toBe(false);
  expect(app.isIPv4('256.256.256.256')).toBe(false);
  expect(app.isIPv4('¹.¹.¹.¹')).toBe(false);
  expect(app.isIPv4('١.١.١.١')).toBe(false);
  expect(app.isIPv4('𝟣.𝟣.𝟣.𝟣')).toBe(false); // punycode
  expect(app.isIPv4('①.①.①.①')).toBe(false);
  expect(app.isIPv4('1:2:3:4:5:6:7:8')).toBe(false);
  expect(app.isIPv4('1::')).toBe(false);

  expect(app.isIPv4('0.0.0.0')).toBe(true);
  expect(app.isIPv4('127.0.0.1')).toBe(true);
  expect(app.isIPv4('255.255.255.255')).toBe(true);
});

test('isIPv6', () => {
  expect(app.isIPv6('')).toBe(false);
  expect(app.isIPv6(null)).toBe(false);
  expect(app.isIPv6('foo')).toBe(false);
  expect(app.isIPv6(10)).toBe(false);
  expect(app.isIPv6('1.2.3')).toBe(false);
  expect(app.isIPv6('1.2.3.4.5')).toBe(false);
  expect(app.isIPv6('256.256.256.256')).toBe(false);
  expect(app.isIPv6('¹.¹.¹.¹')).toBe(false);
  expect(app.isIPv6('١.١.١.١')).toBe(false);
  expect(app.isIPv6('𝟣.𝟣.𝟣.𝟣')).toBe(false); // punycode
  expect(app.isIPv6('①.①.①.①')).toBe(false);
  expect(app.isIPv6('0.0.0.0')).toBe(false);
  expect(app.isIPv6('127.0.0.1')).toBe(false);
  expect(app.isIPv6('255.255.255.255')).toBe(false);

  expect(app.isIPv6('1:2:3:4:5:6:7:8')).toBe(true);
  expect(app.isIPv6('1::')).toBe(true);
  expect(app.isIPv6('1:2:3:4:5:6:7::')).toBe(true);
  expect(app.isIPv6('1::8')).toBe(true);
  expect(app.isIPv6('1:2:3:4:5:6::8')).toBe(true);
  expect(app.isIPv6('1:2:3:4:5:6::8')).toBe(true);
  expect(app.isIPv6('1::7:8')).toBe(true);
  expect(app.isIPv6('1:2:3:4:5::7:8')).toBe(true);
  expect(app.isIPv6('1:2:3:4:5::8')).toBe(true);
  expect(app.isIPv6('1::6:7:8')).toBe(true);
  expect(app.isIPv6('1:2:3:4::6:7:8')).toBe(true);
  expect(app.isIPv6('1:2:3:4::8')).toBe(true);
  expect(app.isIPv6('1::5:6:7:8')).toBe(true);
  expect(app.isIPv6('1:2:3::5:6:7:8')).toBe(true);
  expect(app.isIPv6('1:2:3::8')).toBe(true);
  expect(app.isIPv6('1::4:5:6:7:8')).toBe(true);
  expect(app.isIPv6('1:2::4:5:6:7:8')).toBe(true);
  expect(app.isIPv6('1:2::8')).toBe(true);
  expect(app.isIPv6('1::3:4:5:6:7:8')).toBe(true);
  expect(app.isIPv6('1::3:4:5:6:7:8')).toBe(true);
  expect(app.isIPv6('1::8')).toBe(true);
  expect(app.isIPv6('::2:3:4:5:6:7:8')).toBe(true);
  expect(app.isIPv6('::2:3:4:5:6:7:8')).toBe(true);
  expect(app.isIPv6('::8')).toBe(true);
  expect(app.isIPv6('::')).toBe(true);
});

function testCheckForUnauthorized(url, response, authRedirectCookie, unauthorized) {
  app.showLogin = jest.fn();
  app.getCookie = jest.fn(cookie => authRedirectCookie);
  app.deleteCookie = jest.fn();

  response.request = {responseURL: url};
  var result = app.checkForUnauthorized(response);
  if (unauthorized) {
    expect(result).toBe(null);
    expect(app.showLogin).toHaveBeenCalled();
    expect(app.deleteCookie).toHaveBeenCalledWith('AUTH_REDIRECT');
  } else {
    expect(result).toBe(response);
  }
}

test('checkForUnauthorized', () => {
  testCheckForUnauthorized('/foo/', {headers: {'content-type': 'text/html'}}, null, true);
  testCheckForUnauthorized('/foo/', {headers: {'content-type': 'application/json'}}, null, false);
  testCheckForUnauthorized('/foo/', {status: 401}, null, true);
  testCheckForUnauthorized('/foo/', {status: 200}, null, false);
  testCheckForUnauthorized('/api/', {status: 401}, null, false);
  testCheckForUnauthorized('/foo/', {}, '/blah', true);
  testCheckForUnauthorized('/foo/', {}, null, false);
  testCheckForUnauthorized('/login/banner.md', {}, '/blah', false);
  testCheckForUnauthorized('/auth/self-service/login/browser', {}, '/blah', true);
});

test('correctCasing', () => {
  expect(app.correctCasing('')).toBe('');
  expect(app.correctCasing('foo')).toBe('foo');
  expect(app.correctCasing('FOO')).toBe('FOO');
  expect(app.correctCasing('yara')).toBe('YARA');
  expect(app.correctCasing('Yara')).toBe('YARA');
  expect(app.correctCasing('yArA')).toBe('YARA');
});

function verifyEngineFailureStates(e1f1, e1f2, e1f3, e2f1, e2f2, e2f3, e3f1, e3f2, e3f3, expected) {
  app.currentStatus = { detections: {
    elastalert: {
      integrityFailure: e1f1,
      syncFailure: e1f2,
      migrationFailure: e1f3,
    },
    strelka: {
      integrityFailure: e2f1,
      syncFailure: e2f2,
      migrationFailure: e2f3,
    },
    suricata: {
      integrityFailure: e3f1,
      syncFailure: e3f2,
      migrationFailure: e3f3,
    },
  }}
  expect(app.isDetectionsUnhealthy()).toBe(expected);
}

test('isDetectionsUnhealthy', () => {
  // Unhealthy
  verifyEngineFailureStates(true, false, false, true, false, false, true, false, false, true);
  verifyEngineFailureStates(false, true, false, false, true, false, false, true, false, true);
  verifyEngineFailureStates(false, false, true, false, false, true, false, false, true, true);
  verifyEngineFailureStates(true, true, false, true, true, false, true, true, false, true);
  verifyEngineFailureStates(false, true, true, false, true, true, false, true, true, true);
  verifyEngineFailureStates(true, false, true, true, false, true, true, false, true, true);
  verifyEngineFailureStates(true, true, true, true, true, true, true, true, true, true);
  verifyEngineFailureStates(true, true, true, true, true, true, true, true, true, true);
  verifyEngineFailureStates(false, false, true, true, true, true, true, true, true, true);
  verifyEngineFailureStates(false, false, false, true, true, true, true, true, true, true);
  verifyEngineFailureStates(false, false, false, false, true, true, true, true, true, true);
  verifyEngineFailureStates(false, false, false, false, false, true, true, true, true, true);
  verifyEngineFailureStates(false, false, false, false, false, false, true, true, true, true);
  verifyEngineFailureStates(false, false, false, false, false, false, false, true, true, true);
  verifyEngineFailureStates(false, false, false, false, false, false, false, false, true, true);

  // Healthy
  verifyEngineFailureStates(false, false, false, false, false, false, false, false, false, false);

  // Neither Unhealthy nor Healthy
  app.currentStatus.detections.elastalert.migrating = true
  app.currentStatus.detections.strelka.importing = true
  app.currentStatus.detections.suricata.syncing = true
  expect(app.isDetectionsUnhealthy()).toBe(false);
});

test('isDetectionsUpdating', () => {
  // Unhealthy
  app.currentStatus = { detections: {
    elastalert: {
      integrityFailure: true,
    },
    strelka: {
      integrityFailure: true,
    },
    suricata: {
      integrityFailure: true,
    },
  }};
  expect(app.isDetectionsUpdating()).toBe(false);

  // All healthy
  app.currentStatus.detections.elastalert.integrityFailure = false;
  expect(app.isDetectionsUpdating()).toBe(false);
  app.currentStatus.detections.strelka.integrityFailure = false;
  expect(app.isDetectionsUpdating()).toBe(false);
  app.currentStatus.detections.suricata.integrityFailure = false;
  expect(app.isDetectionsUpdating()).toBe(false);

  // Suricata migrating
  app.currentStatus.detections.suricata.migrating = true;
  expect(app.isDetectionsUpdating()).toBe(true);
  app.currentStatus.detections.suricata.migrating = false;

  // Strelka migrating
  app.currentStatus.detections.strelka.migrating = true;
  expect(app.isDetectionsUpdating()).toBe(true);
  app.currentStatus.detections.strelka.migrating = false;

  // ElastAlert migrating
  app.currentStatus.detections.elastalert.migrating = true;
  expect(app.isDetectionsUpdating()).toBe(true);
  app.currentStatus.detections.elastalert.migrating = false;

  // Suricata importing
  app.currentStatus.detections.suricata.importing = true;
  expect(app.isDetectionsUpdating()).toBe(true);
  app.currentStatus.detections.suricata.importing = false;

  // Strelka importing
  app.currentStatus.detections.strelka.importing = true;
  expect(app.isDetectionsUpdating()).toBe(true);
  app.currentStatus.detections.strelka.importing = false;

  // ElastAlert importing
  app.currentStatus.detections.elastalert.importing = true;
  expect(app.isDetectionsUpdating()).toBe(true);
  app.currentStatus.detections.elastalert.importing = false;

  // Suricata syncing
  app.currentStatus.detections.suricata.syncing = true;
  expect(app.isDetectionsUpdating()).toBe(true);
  app.currentStatus.detections.suricata.syncing = false;

  // Strelka syncing
  app.currentStatus.detections.strelka.syncing = true;
  expect(app.isDetectionsUpdating()).toBe(true);
  app.currentStatus.detections.strelka.syncing = false;

  // ElastAlert syncing
  app.currentStatus.detections.elastalert.syncing = true;
  expect(app.isDetectionsUpdating()).toBe(true);
  app.currentStatus.detections.elastalert.syncing = false;
});

test('getDetectionEngines', () => {
  expect(app.getDetectionEngines()).toStrictEqual(['elastalert', 'strelka', 'suricata']);
});

test('getDetectionEngineStatusClass', () => {
  expect(app.getDetectionEngineStatusClass('unknown')).toBe('normal--text');
  app.currentStatus = { detections: { strelka: { syncing: true }}};
  expect(app.getDetectionEngineStatusClass('strelka')).toBe('normal--text');
  app.currentStatus = { detections: { strelka: { migrationFailure: true, syncFailure: true }}};
  expect(app.getDetectionEngineStatusClass('strelka')).toBe('warning--text');
  app.currentStatus = { detections: { strelka: { syncFailure: true, integrityFailure: true }}};
  expect(app.getDetectionEngineStatusClass('strelka')).toBe('warning--text');
  app.currentStatus = { detections: { strelka: { integrityFailure: true, syncing: true }}};
  expect(app.getDetectionEngineStatusClass('strelka')).toBe('warning--text');
  app.currentStatus = { detections: { strelka: { migrating: true, integrityFailure: true }}};
  expect(app.getDetectionEngineStatusClass('strelka')).toBe('normal--text');
  app.currentStatus = { detections: { strelka: { importing: true, migrating: true }}};
  expect(app.getDetectionEngineStatusClass('strelka')).toBe('normal--text');
  app.currentStatus = { detections: { strelka: { importing: false }}};
  expect(app.getDetectionEngineStatusClass('strelka')).toBe('success--text');
});

test('getDetectionEngineStatus', () => {
  expect(app.getDetectionEngineStatus('unknown')).toBe('Unknown');
  app.currentStatus = { detections: { strelka: { syncing: true }}};
  expect(app.getDetectionEngineStatus('strelka')).toBe('Syncing');
  app.currentStatus = { detections: { strelka: { migrationFailure: true, syncFailure: true }}};
  expect(app.getDetectionEngineStatus('strelka')).toBe('MigrationFailure');
  app.currentStatus = { detections: { strelka: { syncFailure: true, integrityFailure: true }}};
  expect(app.getDetectionEngineStatus('strelka')).toBe('IntegrityFailure');
  app.currentStatus = { detections: { strelka: { syncFailure: true, integrityFailure: false }}};
  expect(app.getDetectionEngineStatus('strelka')).toBe('SyncFailure');
  app.currentStatus = { detections: { strelka: { migrating: true, importing: true, syncing: true, integrityFailure: true }}};
  expect(app.getDetectionEngineStatus('strelka')).toBe('Migrating');
  app.currentStatus = { detections: { strelka: { importing: true, migrating: false, syncing: true }}};
  expect(app.getDetectionEngineStatus('strelka')).toBe('Importing');
  app.currentStatus = { detections: { strelka: { importing: true, migrating: false, syncing: false }}};
  expect(app.getDetectionEngineStatus('strelka')).toBe('ImportPending');
  app.currentStatus = { detections: { strelka: { importing: false }}};
  expect(app.getDetectionEngineStatus('strelka')).toBe('Healthy');
});

test('isAttentionNeeded', () => {
  app.connected =  true;
  app.currentStatus = {
    detections: {
      elastalert: {
        integrityFailure: false,
        syncFailure: false,
        migrationFailure: false,
      },
      strelka: {
        integrityFailure: false,
        syncFailure: false,
        migrationFailure: false,
      },
      suricata: {
        integrityFailure: false,
        syncFailure: false,
        migrationFailure: false,
      },
    },
    alerts: {
      newCount: 0,
    },
    grid: {
      unhealthyNodeCount: 0,
    },
  };
  expect(app.isAttentionNeeded()).toBe(false);

  // Attention when unable to connect to server
  app.connected = false;
  expect(app.isAttentionNeeded()).toBe(true);
  app.connected = true;

  // Attention when unhealthy grid count > 0
  app.currentStatus.grid.unhealthyNodeCount = 1
  expect(app.isAttentionNeeded()).toBe(true);
  app.currentStatus.grid.unhealthyNodeCount = 0

  // Attention when new alert count > 0
  app.currentStatus.alerts.newCount = 1
  expect(app.isAttentionNeeded()).toBe(true);
  app.currentStatus.alerts.newCount = 0

  // Attention when detections engines unhealthy
  app.currentStatus.detections.elastalert.syncFailure = true;
  expect(app.isAttentionNeeded()).toBe(true);
  app.currentStatus.detections.elastalert.syncFailure = false;

  // Back to normal
  expect(app.isAttentionNeeded()).toBe(false);
})

test('dateAwareSort', () => {
  let items = [
    { string: 'May 28, 2024 10:00:00 AM', createTime: 'May 28, 2024 10:00:00 AM', strOrder: 1, dateOrder: 0 },
    { string: 'May 28, 2024 11:00:00 AM', createTime: 'May 28, 2024 11:00:00 AM', strOrder: 2, dateOrder: 1 },
    { string: 'May 28, 2024 12:00:00 PM', createTime: 'May 28, 2024 12:00:00 PM', strOrder: 3, dateOrder: 2 },
    { string: 'May 28, 2024 1:00:00 PM', createTime: 'May 28, 2024 1:00:00 PM', strOrder: 0, dateOrder: 3 },
    { string: 'May 28, 2024 2:00:00 PM', createTime: 'May 28, 2024 2:00:00 PM', strOrder: 4, dateOrder: 4 },
  ];
  let index = ["string"];
  let isDesc = [false];

  app.dateAwareSort(items, index, isDesc);

  for (let i = 0; i < items.length; i++) {
    expect(items[i].strOrder).toBe(i);
  }

  // Reverse the sort
  isDesc = [true];

  app.dateAwareSort(items, index, isDesc);

  for (let i = 0; i < items.length; i++) {
    expect(items[i].strOrder).toBe(items.length - i - 1);
  }

  // revert order, change sortby
  index = ["createTime"];
  isDesc = [false];

  app.dateAwareSort(items, index, isDesc);

  for (let i = 0; i < items.length; i++) {
    expect(items[i].dateOrder).toBe(i);
  }

  // Reverse the sort
  isDesc = [true];

  app.dateAwareSort(items, index, isDesc);

  for (let i = 0; i < items.length; i++) {
    expect(items[i].dateOrder).toBe(items.length - i - 1);
  }
});

test('licenseExpiringSoon', () => {
  const date = new Date();
  app.licenseKey = { expiration: date.toISOString() };
  expect(app.isLicenseExpiringSoon()).toBe(true);
  
  app.licenseKey = { expiration: "2024-01-01T01:01:01Z" };
  expect(app.isLicenseExpiringSoon()).toBe(true);

  app.licenseKey = { expiration: "2054-01-01T01:01:01Z" };
  expect(app.isLicenseExpiringSoon()).toBe(false);
});

test('checkUserSecuritySettings', () => {
  app.securitySettingsAlreadyChecked = false;
  app.forceUserOtp = false;
  const data = { forceUserOtp: false };
  app.checkUserSecuritySettings(data);
  expect(app.securitySettingsAlreadyChecked).toBe(true);
  expect(app.forceUserOtp).toBe(false);
  expect(location.hash).toBe("");

  data.forceUserOtp = true;
  app.checkUserSecuritySettings(data);
  expect(app.securitySettingsAlreadyChecked).toBe(true);
  expect(app.forceUserOtp).toBe(false);
  expect(location.hash).toBe("");

  app.securitySettingsAlreadyChecked = false;
  app.checkUserSecuritySettings(data);
  expect(app.securitySettingsAlreadyChecked).toBe(false);
  expect(app.forceUserOtp).toBe(true);
  expect(location.hash).toBe("#/settings?tab=security");

  location.hash = "#/settings?alreadyhere";
  app.securitySettingsAlreadyChecked = false;
  app.checkUserSecuritySettings(data);
  expect(app.securitySettingsAlreadyChecked).toBe(false);
  expect(app.forceUserOtp).toBe(true);
  expect(location.hash).toBe("#/settings?alreadyhere");
});