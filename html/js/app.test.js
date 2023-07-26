// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

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
  expect(app.replaceActionVar('test {foo} here', 'foo', null, true)).toBe('test {foo} here');
  expect(app.replaceActionVar('test {foo} here', 'foo', undefined, true)).toBe('test {foo} here');
});

test('base64encode', () => {
  expect(app.base64encode('')).toBe('');
  expect(app.base64encode('hello')).toBe('aGVsbG8=');
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
      casesEnabled: true
    },
    elasticVersion: 'myElasticVersion',
    wazuhVersion: 'myWazuhVersion',
    timezones: ['UTC'],
    userId: 'myUserId'
  };

  expect(app.casesEnabled).toBe(false);
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
  expect(app.wazuhVersion).toBe('myWazuhVersion');
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
  expect(app.colorLicenseStatus("exceeded")).toBe('warning');
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
