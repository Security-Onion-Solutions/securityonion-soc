// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js');
require('./destinations-manager.js');

let comp;

beforeEach(() => {
  comp = getComponent('destinations-manager');
  resetPapi();
});

test('getDestinations success', async () => {
  const mockData = [
    {
      id: 'soc-bell',
      name: 'SOC Bell',
      type: 'soc',
      enabled: true,
      scheduleIds: ['work-hours'],
      severities: ['high', 'critical'],
      params: {},
    },
  ];
  const mock = mockPapi('get', mockData);
  await comp.getDestinations();
  expect(mock).toHaveBeenCalledWith('notifications/destinations');
  expect(comp.destinations).toEqual(mockData);
});

test('getDestinations error handling', async () => {
  mockPapi('get', null, 'Failed to fetch destinations');
  await comp.getDestinations();
  expect(comp.$root.error).toBe(true);
  expect(comp.$root.errorMessage).toBe('Failed to fetch destinations');
});

test('getSchedules success', async () => {
  const mockSchedules = [
    { id: 'sch-1', name: 'Work Hours', enabled: true },
    { id: 'sch-2', name: 'Off Hours', enabled: false },
  ];
  const mock = mockPapi('get', mockSchedules);
  await comp.getSchedules();
  expect(mock).toHaveBeenCalledWith('schedules/');
  expect(comp.schedules).toEqual(mockSchedules);
  const opts = typeof comp.scheduleOptions === 'function' ? comp.scheduleOptions() : comp.scheduleOptions;
  expect(opts.length).toBe(2);
  expect(opts[0].title).toBe('Work Hours (Enabled)');
  expect(opts[1].title).toBe('Off Hours (Disabled)');
});

test('showAddDestination initializes default form', () => {
  comp.showAddDestination();
  expect(comp.destinationDialog).toBe(true);
  expect(comp.form.isEdit).toBe(false);
  expect(comp.form.id).toBe('');
  expect(comp.form.name).toBe('');
  expect(comp.form.type).toBe('soc');
  expect(comp.form.enabled).toBe(true);
  expect(comp.form.enableRecipients).toBe(true);
  expect(comp.form.skipIfRecipients).toBe(false);
  expect(comp.form.scheduleIds).toEqual([]);
  expect(comp.form.severities).toEqual([]);
  expect(comp.form.params).toEqual({});
});

test('showEditDestination populates form', () => {
  const dest = {
    id: 'soc-bell',
    name: 'SOC Alert Bell',
    type: 'soc',
    enabled: false,
    recipientsSupported: true,
    enableRecipients: false,
    skipIfRecipients: true,
    scheduleIds: ['sch-1'],
    severities: ['critical'],
    params: {},
  };
  comp.showEditDestination(dest);
  expect(comp.destinationDialog).toBe(true);
  expect(comp.form.isEdit).toBe(true);
  expect(comp.form.id).toBe('soc-bell');
  expect(comp.form.name).toBe('SOC Alert Bell');
  expect(comp.form.type).toBe('soc');
  expect(comp.form.enabled).toBe(false);
  expect(comp.form.recipientsSupported).toBe(true);
  expect(comp.form.enableRecipients).toBe(false);
  expect(comp.form.skipIfRecipients).toBe(true);
  expect(comp.form.scheduleIds).toEqual(['sch-1']);
  expect(comp.form.severities).toEqual(['critical']);
  expect(comp.form.params).toEqual({});
});

test('showEditDestination auto populates default name when blank', () => {
  const dest = {
    id: 'soc-bell',
    name: '',
    type: 'soc',
    enabled: true,
    recipientsSupported: true,
    enableRecipients: true,
    skipIfRecipients: false,
  };
  comp.showEditDestination(dest);
  expect(comp.destinationDialog).toBe(true);
  expect(comp.form.isEdit).toBe(true);
  expect(comp.form.id).toBe('soc-bell');
  expect(comp.form.name).toBe('Built-in SOC Notifications');
});

test('saveDestination creates new destination', async () => {
  comp.showAddDestination();
  comp.form.name = 'New Slack';
  comp.form.type = 'soc';
  comp.form.enableRecipients = true;
  comp.form.skipIfRecipients = false;
  comp.form.scheduleIds = ['sch-1'];
  comp.form.severities = ['high', 'critical'];

  const postMock = mockPapi('post', { success: true });
  mockPapi('get', []); // loadData destinations
  await comp.saveDestination();

  expect(postMock).toHaveBeenCalledWith('notifications/destinations', {
    id: undefined,
    name: 'New Slack',
    type: 'soc',
    enabled: true,
    enableRecipients: true,
    skipIfRecipients: false,
    scheduleIds: ['sch-1'],
    severities: ['high', 'critical'],
    params: {},
  });
  expect(comp.destinationDialog).toBe(false);
});

test('saveDestination updates existing destination', async () => {
  comp.showEditDestination({
    id: 'soc-bell',
    name: 'SOC Bell',
    type: 'soc',
    enabled: true,
    recipientsSupported: true,
    enableRecipients: false,
    skipIfRecipients: true,
    scheduleIds: ['sch-1'],
    severities: ['critical'],
    params: {},
  });
  comp.form.name = 'Renamed SOC Bell';
  comp.form.enabled = false;
  comp.form.enableRecipients = false;
  comp.form.skipIfRecipients = true;
  comp.form.scheduleIds = ['sch-1', 'sch-2'];

  const putMock = mockPapi('put', { success: true });
  mockPapi('get', []); // loadData destinations
  await comp.saveDestination();

  expect(putMock).toHaveBeenCalledWith('notifications/destinations/soc-bell', {
    id: 'soc-bell',
    name: 'Renamed SOC Bell',
    type: 'soc',
    enabled: false,
    enableRecipients: false,
    skipIfRecipients: true,
    scheduleIds: ['sch-1', 'sch-2'],
    severities: ['critical'],
    params: {},
  });
  expect(comp.destinationDialog).toBe(false);
});

test('channelTypeOptions contains soc, smtp, slack_webhook, matrix_hookshot_webhook, and generic_webhook', () => {
  const opts = typeof comp.channelTypeOptions === 'function' ? comp.channelTypeOptions() : comp.channelTypeOptions;
  expect(opts.map(opt => opt.value)).toEqual(['soc', 'smtp', 'slack_webhook', 'matrix_hookshot_webhook', 'generic_webhook']);
});

test('onChannelTypeChange updates recipientsSupported', () => {
  comp.form.type = 'generic_webhook';
  comp.onChannelTypeChange('generic_webhook');
  expect(comp.form.recipientsSupported).toBe(false);

  comp.onChannelTypeChange('slack_webhook');
  expect(comp.form.recipientsSupported).toBe(false);

  comp.onChannelTypeChange('matrix_hookshot_webhook');
  expect(comp.form.recipientsSupported).toBe(false);

  comp.onChannelTypeChange('smtp');
  expect(comp.form.recipientsSupported).toBe(true);

  comp.onChannelTypeChange('soc');
  expect(comp.form.recipientsSupported).toBe(true);
});

test('showEditDestination populates slack destination', () => {
  const dest = {
    id: 'slack-alerts',
    name: 'Slack Alerts',
    type: 'slack_webhook',
    enabled: true,
    params: {
      webhookUrl: 'https://hooks.slack.com/services/123',
    },
  };
  comp.showEditDestination(dest);
  expect(comp.form.type).toBe('slack_webhook');
  expect(comp.form.params.webhookUrl).toBe('https://hooks.slack.com/services/123');
});

test('showEditDestination populates matrix destination', () => {
  const dest = {
    id: 'matrix-alerts',
    name: 'Matrix Alerts',
    type: 'matrix_hookshot_webhook',
    enabled: true,
    params: {
      webhookUrl: 'https://matrix.example.com/hookshot/123',
    },
  };
  comp.showEditDestination(dest);
  expect(comp.form.type).toBe('matrix_hookshot_webhook');
  expect(comp.form.params.webhookUrl).toBe('https://matrix.example.com/hookshot/123');
});

test('saveDestination creates slack destination with options', async () => {
  comp.showAddDestination();
  comp.form.name = 'Slack Alerts Channel';
  comp.form.type = 'slack_webhook';
  comp.form.params = {
    webhookUrl: 'https://hooks.slack.com/services/ABC',
    insecureSkipVerify: true,
  };

  const postMock = mockPapi('post', { success: true });
  mockPapi('get', []);
  await comp.saveDestination();

  expect(postMock).toHaveBeenCalledWith('notifications/destinations', {
    id: undefined,
    name: 'Slack Alerts Channel',
    type: 'slack_webhook',
    enabled: true,
    enableRecipients: undefined,
    skipIfRecipients: false,
    scheduleIds: [],
    severities: [],
    params: {
      webhookUrl: 'https://hooks.slack.com/services/ABC',
      insecureSkipVerify: true,
    },
  });
});

test('saveDestination creates matrix destination with options', async () => {
  comp.showAddDestination();
  comp.form.name = 'Matrix Hookshot Channel';
  comp.form.type = 'matrix_hookshot_webhook';
  comp.form.params = {
    webhookUrl: 'https://matrix.example.com/hook',
    insecureSkipVerify: false,
  };

  const postMock = mockPapi('post', { success: true });
  mockPapi('get', []);
  await comp.saveDestination();

  expect(postMock).toHaveBeenCalledWith('notifications/destinations', {
    id: undefined,
    name: 'Matrix Hookshot Channel',
    type: 'matrix_hookshot_webhook',
    enabled: true,
    enableRecipients: undefined,
    skipIfRecipients: false,
    scheduleIds: [],
    severities: [],
    params: {
      webhookUrl: 'https://matrix.example.com/hook',
      insecureSkipVerify: false,
    },
  });
});

test('saveDestination creates generic webhook destination', async () => {
  comp.showAddDestination();
  comp.form.name = 'Generic Webhook Channel';
  comp.form.type = 'generic_webhook';
  comp.form.params = {
    webhookUrl: 'https://webhook.example.com/api',
    insecureSkipVerify: true,
  };

  const postMock = mockPapi('post', { success: true });
  mockPapi('get', []);
  await comp.saveDestination();

  expect(postMock).toHaveBeenCalledWith('notifications/destinations', {
    id: undefined,
    name: 'Generic Webhook Channel',
    type: 'generic_webhook',
    enabled: true,
    enableRecipients: undefined,
    skipIfRecipients: false,
    scheduleIds: [],
    severities: [],
    params: {
      webhookUrl: 'https://webhook.example.com/api',
      insecureSkipVerify: true,
    },
  });
});


test('saveDestination creates smtp destination with all options and comma-separated recipients', async () => {
  comp.showAddDestination();
  comp.form.name = 'SMTP Alerts';
  comp.form.type = 'smtp';
  comp.form.enableRecipients = true;
  comp.form.skipIfRecipients = true;
  comp.form.scheduleIds = ['sch-1'];
  comp.form.severities = ['high', 'critical'];
  comp.form.params = {
    host: 'smtp.example.com',
    port: '465',
    from: 'alerts@example.com',
    to: 'secops@example.com, oncall@example.com',
    username: 'socuser',
    password: 'secretpassword',
    useTls: true,
    insecureSkipVerify: true,
    attachmentMode: 'attach',
  };

  const postMock = mockPapi('post', { success: true });
  mockPapi('get', []);
  await comp.saveDestination();

  expect(postMock).toHaveBeenCalledWith('notifications/destinations', {
    id: undefined,
    name: 'SMTP Alerts',
    type: 'smtp',
    enabled: true,
    enableRecipients: true,
    skipIfRecipients: true,
    scheduleIds: ['sch-1'],
    severities: ['high', 'critical'],
    params: {
      host: 'smtp.example.com',
      port: 465,
      from: 'alerts@example.com',
      to: ['secops@example.com', 'oncall@example.com'],
      username: 'socuser',
      password: 'secretpassword',
      useTls: true,
      insecureSkipVerify: true,
      attachmentMode: 'attach',
    },
  });
});

test('saveDestination ignores empty name', async () => {
  comp.showAddDestination();
  comp.form.name = '';
  const postMock = mockPapi('post', { success: true });
  await comp.saveDestination();
  expect(postMock).not.toHaveBeenCalled();
});

test('isDefaultDestination checks default id', () => {
  expect(comp.isDefaultDestination({ id: 'soc-bell' })).toBe(true);
  expect(comp.isDefaultDestination({ id: 'custom-dest' })).toBe(false);
  expect(comp.isDefaultDestination(null)).toBe(false);
});

test('deleteDestination flow for custom destination', async () => {
  const defaultDest = { id: 'soc-bell', name: 'SOC Bell' };
  comp.showDeleteDestination(defaultDest);
  expect(comp.deleteDestinationDialog).toBe(false);
  expect(comp.destinationToDelete).toBeNull();

  const customDest = { id: 'custom-dest', name: 'Custom Channel' };
  comp.showDeleteDestination(customDest);
  expect(comp.deleteDestinationDialog).toBe(true);
  expect(comp.destinationToDelete).toEqual(customDest);

  const deleteMock = mockPapi('delete', { success: true });
  mockPapi('get', []); // loadData destinations
  await comp.deleteDestination();

  expect(deleteMock).toHaveBeenCalledWith('notifications/destinations/custom-dest');
  expect(comp.deleteDestinationDialog).toBe(false);
  expect(comp.destinationToDelete).toBeNull();
});

test('hideDeleteDestination resets state', () => {
  comp.showDeleteDestination({ id: 'custom-dest', name: 'Custom Channel' });
  comp.hideDeleteDestination();
  expect(comp.deleteDestinationDialog).toBe(false);
  expect(comp.destinationToDelete).toBeNull();
});

test('showSendDialog with destination initializes form with destination defaults', () => {
  comp.users = [{ id: 'u1', email: 'alice@soc.local' }, { id: 'u2', email: 'bob@soc.local' }];
  comp.showSendDialog({ id: 'soc-bell', name: 'SOC Bell', type: 'soc' });
  expect(comp.sendDialog).toBe(true);
  expect(comp.sendTargetDestination).toEqual({ id: 'soc-bell', name: 'SOC Bell', type: 'soc' });
  expect(comp.sendForm.title).toBe('Test: SOC Bell');
  expect(comp.sendForm.summary).toBe('This is a test notification summary.');
  expect(comp.sendForm.severity).toBe('info');
  expect(comp.sendForm.recipients).toEqual([]);
  expect(comp.sendForm.bypassSchedules).toBe(false);
  expect(comp.getSendDialogTitle()).toBe('Send Notification to SOC Bell');
});

test('showSendDialog without destination initializes form with global defaults', () => {
  comp.showSendDialog(null);
  expect(comp.sendDialog).toBe(true);
  expect(comp.sendTargetDestination).toBeNull();
  expect(comp.sendForm.title).toBe('Test Notification');
  expect(comp.sendForm.summary).toBe('This is a test notification summary.');
  expect(comp.sendForm.severity).toBe('info');
  expect(comp.sendForm.recipients).toEqual([]);
  expect(comp.sendForm.bypassSchedules).toBe(false);
  expect(comp.getSendDialogTitle()).toBe('Send Notification');
});

test('submitSendNotification dispatches destination-targeted notification', async () => {
  comp.showSendDialog({ id: 'soc-bell', name: 'SOC Bell' });
  comp.sendForm.title = 'Custom Title';
  comp.sendForm.summary = 'Custom Summary';
  comp.sendForm.severity = 'high';
  comp.sendForm.recipients = ['u1'];
  comp.sendForm.bypassSchedules = true;

  const postMock = mockPapi('post', { count: 1 });
  await comp.submitSendNotification();

  expect(postMock).toHaveBeenCalledWith('notifications/destinations/soc-bell/send', {
    title: 'Custom Title',
    summary: 'Custom Summary',
    severity: 'high',
    recipients: ['u1'],
    bypassSchedules: true,
  });
  expect(comp.sendDialog).toBe(false);
  expect(comp.$root.notification).toBe(true);
  expect(comp.$root.notificationMessage).toBe('Notification sent successfully!');
});

test('submitSendNotification dispatches global notification when destination is null', async () => {
  comp.showSendDialog(null);
  comp.sendForm.title = 'Broadcast Alert';
  comp.sendForm.summary = 'To everyone';
  comp.sendForm.severity = 'critical';
  comp.sendForm.recipients = [];
  comp.sendForm.bypassSchedules = false;

  const postMock = mockPapi('post', { count: 1 });
  await comp.submitSendNotification();

  expect(postMock).toHaveBeenCalledWith('notifications/send', {
    title: 'Broadcast Alert',
    summary: 'To everyone',
    severity: 'critical',
    recipients: [],
    bypassSchedules: false,
  });
  expect(comp.sendDialog).toBe(false);
  expect(comp.$root.notification).toBe(true);
  expect(comp.$root.notificationMessage).toBe('Notification sent successfully!');
});

test('submitSendNotification shows warning when count is 0', async () => {
  comp.showSendDialog({ id: 'soc-bell', name: 'SOC Bell' });
  comp.sendForm.title = 'Filtered Out Title';

  mockPapi('post', { count: 0 });
  const showWarningMock = jest.fn();
  comp.$root.showWarning = showWarningMock;

  await comp.submitSendNotification();

  expect(comp.sendDialog).toBe(false);
  expect(showWarningMock).toHaveBeenCalledWith('No notification destinations were eligible.');
});

test('submitSendNotification ignores submission without title', async () => {
  comp.showSendDialog(null);
  comp.sendForm.title = '   ';
  const postMock = mockPapi('post', { success: true });
  await comp.submitSendNotification();
  expect(postMock).not.toHaveBeenCalled();
});

test('userOptions correctly maps users', () => {
  comp.users = [
    { id: 'u1', email: 'alice@soc.local' },
    { id: 'u2', name: 'Bob Smith' },
    { id: 'u3' },
  ];
  const opts = typeof comp.userOptions === 'function' ? comp.userOptions() : comp.userOptions;
  expect(opts).toEqual([
    { title: 'alice@soc.local', value: 'u1' },
    { title: 'Bob Smith', value: 'u2' },
    { title: 'u3', value: 'u3' },
  ]);
});

test('helpers for channel and severity formatting', () => {
  expect(comp.getChannelIcon('soc')).toBe('fa-envelope');
  expect(comp.getChannelIcon('smtp')).toBe('fa-at');
  expect(comp.getChannelIcon('slack_webhook')).toBe('fab fa-slack');
  expect(comp.getChannelIcon('matrix_hookshot_webhook')).toBe('fa-comments');
  expect(comp.getChannelIcon('generic_webhook')).toBe('fa-globe');
  expect(comp.getChannelIcon('other')).toBe('fa-envelope');

  expect(comp.getChannelLabel('slack_webhook')).toBe('Slack Webhook');
  expect(comp.getChannelLabel('matrix_hookshot_webhook')).toBe('Matrix Hookshot Webhook');
  expect(comp.getChannelLabel('generic_webhook')).toBe('Generic Webhook');

  comp.$root = {
    colorSeverity: (sev) => {
      if (sev === 'critical') return 'red-darken-4';
      if (sev === 'high') return 'red-lighten-1';
      return 'grey';
    },
  };
  expect(comp.colorSeverity('critical')).toBe('red-darken-4');
  expect(comp.colorSeverity('high')).toBe('red-lighten-1');
  expect(comp.colorSeverity('info')).toBe('grey');

  expect(comp.getSeverityLabel('critical')).toBe('Critical');
  expect(comp.getSeverityLabel('high')).toBe('High');

  // getDestinationName tests
  expect(comp.getDestinationName({ name: 'Custom Name', type: 'soc' })).toBe('Custom Name');
  expect(comp.getDestinationName({ name: '', type: 'soc', id: 'soc-bell' })).toBe('Built-in SOC Notifications');
  expect(comp.getDestinationName({ name: '   ', type: 'soc', id: 'soc-bell' })).toBe('Built-in SOC Notifications');
  expect(comp.getDestinationName({ name: '', type: 'smtp', id: 'smtp-1' })).toBe('smtp-1');
  expect(comp.getDestinationName(null)).toBe('');
});

test('isDestinationScheduleActive and getDestinationScheduleNames evaluations', () => {
  // No schedule -> always active
  expect(comp.isDestinationScheduleActive({ scheduleIds: [] })).toBe(true);
  expect(comp.isDestinationScheduleActive(null)).toBe(true);

  // Missing schedule -> fails open to true
  comp.schedules = [{ id: 'sch-1', name: 'Work', enabled: true, definitions: [{ type: 'daily', allDay: true }] }];
  expect(comp.isDestinationScheduleActive({ scheduleIds: ['missing'] })).toBe(true);

  // Active schedule
  expect(comp.isDestinationScheduleActive({ scheduleIds: ['sch-1'] })).toBe(true);

  // Disabled schedule -> false
  comp.schedules = [{ id: 'sch-2', name: 'Disabled', enabled: false, definitions: [{ type: 'daily', allDay: true }] }];
  expect(comp.isDestinationScheduleActive({ scheduleIds: ['sch-2'] })).toBe(false);

  // Multiple schedules: active if any is active
  comp.schedules = [
    { id: 'sch-1', name: 'Work', enabled: true, definitions: [{ type: 'daily', allDay: true }] },
    { id: 'sch-2', name: 'Disabled', enabled: false, definitions: [{ type: 'daily', allDay: true }] },
  ];
  expect(comp.isDestinationScheduleActive({ scheduleIds: ['sch-1', 'sch-2'] })).toBe(true);

  // Names helper
  expect(comp.getDestinationScheduleNames({ scheduleIds: ['sch-1'] })).toEqual(['Work']);
  expect(comp.getDestinationScheduleNames({ scheduleIds: ['sch-1', 'sch-2'] })).toEqual(['Work', 'Disabled']);
  expect(comp.getDestinationScheduleNames(null)).toEqual([]);
});

test('showPassword defaults to false and resets when opening add/edit destination dialog', () => {
  expect(comp.showPassword).toBe(false);

  comp.showPassword = true;
  comp.showAddDestination();
  expect(comp.showPassword).toBe(false);

  comp.showPassword = true;
  comp.showEditDestination({ id: 'smtp-1', name: 'SMTP Dest', type: 'smtp' });
  expect(comp.showPassword).toBe(false);
});

test('destinations-manager template includes show/hide password toggle for smtp password field', () => {
  const fs = require('fs');
  const path = require('path');
  const tmplPath = path.resolve(__dirname, '../../pages/destinations-manager.html');
  const tmpl = fs.readFileSync(tmplPath, 'utf8');

  expect(tmpl).toContain('data-aid="destination_form_smtp_password"');
  expect(tmpl).toMatch(/:type="showPassword\s*\?\s*'text'\s*:\s*'password'"/);
  expect(tmpl).toMatch(/:append-inner-icon="showPassword\s*\?\s*'fa-eye-slash'\s*:\s*'fa-eye'"/);
  expect(tmpl).toMatch(/@click:append-inner="showPassword\s*=\s*!showPassword"/);
});
