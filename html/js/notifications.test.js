// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('./test_common.js');
require('./notifications.js');

const app = global.getApp();

describe('notifications.js', () => {
  describe('getSeverityColorClass', () => {
    it('returns expected class for critical severity', () => {
      expect(app.getSeverityColorClass('critical', false)).toBe('text-red-accent-4 font-weight-black');
      expect(app.getSeverityColorClass('CRITICAL', false)).toBe('text-red-accent-4 font-weight-black');
      expect(app.getSeverityColorClass('critical', true)).toBe('text-red-accent-4');
    });

    it('returns expected class for high severity', () => {
      expect(app.getSeverityColorClass('high', false)).toBe('text-red-darken-1 font-weight-bold');
      expect(app.getSeverityColorClass('HIGH', false)).toBe('text-red-darken-1 font-weight-bold');
      expect(app.getSeverityColorClass('high', true)).toBe('text-red-darken-1');
    });

    it('returns expected class for medium severity', () => {
      expect(app.getSeverityColorClass('medium', false)).toBe('text-orange-darken-1 font-weight-bold');
      expect(app.getSeverityColorClass('MEDIUM', false)).toBe('text-orange-darken-1 font-weight-bold');
      expect(app.getSeverityColorClass('medium', true)).toBe('text-orange-darken-1');
    });

    it('returns expected class for low severity', () => {
      expect(app.getSeverityColorClass('low', false)).toBe('text-yellow-darken-2 font-weight-bold');
      expect(app.getSeverityColorClass('LOW', false)).toBe('text-yellow-darken-2 font-weight-bold');
      expect(app.getSeverityColorClass('low', true)).toBe('text-yellow-darken-2');
    });

    it('returns default class for info or unknown severity', () => {
      expect(app.getSeverityColorClass('info', false)).toBe('text-blue-darken-1 font-weight-bold');
      expect(app.getSeverityColorClass('info', true)).toBe('text-blue-darken-1');
      expect(app.getSeverityColorClass('', true)).toBe('text-blue-darken-1');
      expect(app.getSeverityColorClass(null, true)).toBe('text-blue-darken-1');
      expect(app.getSeverityColorClass(undefined, true)).toBe('text-blue-darken-1');
    });
  });

  describe('formatTimeAgo', () => {
    it('returns empty string when timestamp is empty or nil', () => {
      expect(app.formatTimeAgo('')).toBe('');
      expect(app.formatTimeAgo(null)).toBe('');
      expect(app.formatTimeAgo(undefined)).toBe('');
    });

    it('formats valid timestamp using moment', () => {
      global.moment = jest.fn(() => ({
        fromNow: () => '2 minutes ago'
      }));
      const res = app.formatTimeAgo('2026-08-20T12:00:00Z');
      expect(res).toBe('2 minutes ago');
    });
  });

  describe('sanitizeDeepLink', () => {
    it('returns # for empty, null, or undefined url', () => {
      expect(app.sanitizeDeepLink('')).toBe('#');
      expect(app.sanitizeDeepLink(null)).toBe('#');
      expect(app.sanitizeDeepLink(undefined)).toBe('#');
      expect(app.sanitizeDeepLink(123)).toBe('#');
    });

    it('sanitizes and blocks javascript:, data:, and vbscript: URIs', () => {
      expect(app.sanitizeDeepLink('javascript:alert(1)')).toBe('#');
      expect(app.sanitizeDeepLink('JavaScript:alert(1)')).toBe('#');
      expect(app.sanitizeDeepLink('  javascript:void(0)')).toBe('#');
      expect(app.sanitizeDeepLink('data:text/html,<script>alert(1)</script>')).toBe('#');
      expect(app.sanitizeDeepLink('vbscript:msgbox("hello")')).toBe('#');
    });

    it('allows valid http, https, relative, and hash links', () => {
      expect(app.sanitizeDeepLink('https://soc.example.com/#/alerts/123')).toBe('https://soc.example.com/#/alerts/123');
      expect(app.sanitizeDeepLink('http://soc.example.com/')).toBe('http://soc.example.com/');
      expect(app.sanitizeDeepLink('/#/alerts/123')).toBe('/#/alerts/123');
      expect(app.sanitizeDeepLink('#/alerts/123')).toBe('#/alerts/123');
      expect(app.sanitizeDeepLink('alerts/123')).toBe('alerts/123');
    });

    it('blocks custom schemes with colon that are not http/https', () => {
      expect(app.sanitizeDeepLink('ftp://files.example.com')).toBe('#');
      expect(app.sanitizeDeepLink('file:///etc/passwd')).toBe('#');
    });
  });

  describe('deepLinkTitle', () => {
    it('names the emoji links the server sends, and leaves other labels as-is', () => {
      expect(app.deepLinkTitle('🔔')).toBe('AI Investigation');
      expect(app.deepLinkTitle('💬')).toBe('Open in Onion AI');
      expect(app.deepLinkTitle('🌐')).toBe('View');
      expect(app.deepLinkTitle('⬇')).toBe('Download');
      expect(app.deepLinkTitle('SOC')).toBe('SOC');
    });
  });

  describe('loadNotifications', () => {
    it('skips loading when username is missing or unlicensed or notifications not started', async () => {
      const mockPapiGet = jest.fn();
      const ctx = {
        username: '',
        FEAT_NTF: 'ntf',
        notificationsStarted: true,
        isLicensed: jest.fn(() => true),
        papi: { get: mockPapiGet }
      };

      await app.loadNotifications.call(ctx);
      expect(mockPapiGet).not.toHaveBeenCalled();

      ctx.username = 'admin';
      ctx.isLicensed = jest.fn(() => false);
      await app.loadNotifications.call(ctx);
      expect(mockPapiGet).not.toHaveBeenCalled();

      ctx.isLicensed = jest.fn(() => true);
      ctx.notificationsStarted = false;
      await app.loadNotifications.call(ctx);
      expect(mockPapiGet).not.toHaveBeenCalled();
    });

    it('fetches notifications with active filter by default and sets notifications list and unread count', async () => {
      const mockData = [
        { id: 'notif-1', title: 'Alert 1', isRead: false, isDismissed: false },
        { id: 'notif-2', title: 'Alert 2', isRead: true, isDismissed: false }
      ];
      const mockPapiGet = jest.fn().mockResolvedValue({ data: mockData });
      const ctx = {
        username: 'admin',
        FEAT_NTF: 'ntf',
        notificationsStarted: true,
        isLicensed: jest.fn(() => true),
        notificationShowDismissed: false,
        notifications: [],
        unreadCount: 0,
        papi: { get: mockPapiGet }
      };

      await app.loadNotifications.call(ctx);
      expect(mockPapiGet).toHaveBeenCalledWith('notifications?filter=active');
      expect(ctx.notifications).toEqual(mockData);
      expect(ctx.unreadCount).toBe(1);
      expect(ctx.notificationsTruncated).toBe(false);
    });

    it('handles truncated response format correctly', async () => {
      const mockRecords = [
        { id: 'notif-1', title: 'Alert 1', isRead: false, isDismissed: false },
      ];
      const mockResponse = {
        notifications: mockRecords,
        truncated: true,
        count: 1
      };
      const mockPapiGet = jest.fn().mockResolvedValue({ data: mockResponse });
      const ctx = {
        username: 'admin',
        FEAT_NTF: 'ntf',
        notificationsStarted: true,
        isLicensed: jest.fn(() => true),
        notificationShowDismissed: false,
        notifications: [],
        unreadCount: 0,
        notificationsTruncated: false,
        papi: { get: mockPapiGet }
      };

      await app.loadNotifications.call(ctx);
      expect(mockPapiGet).toHaveBeenCalledWith('notifications?filter=active');
      expect(ctx.notifications).toEqual(mockRecords);
      expect(ctx.notificationsTruncated).toBe(true);
      expect(ctx.unreadCount).toBe(1);
    });

    it('fetches notifications with all filter when notificationShowDismissed is true', async () => {
      const mockData = [
        { id: 'notif-1', title: 'Alert 1', isRead: false, isDismissed: false },
        { id: 'notif-2', title: 'Alert 2', isRead: true, isDismissed: true }
      ];
      const mockPapiGet = jest.fn().mockResolvedValue({ data: mockData });
      const ctx = {
        username: 'admin',
        FEAT_NTF: 'ntf',
        notificationsStarted: true,
        isLicensed: jest.fn(() => true),
        notificationShowDismissed: true,
        notifications: [],
        unreadCount: 0,
        papi: { get: mockPapiGet }
      };

      await app.loadNotifications.call(ctx);
      expect(mockPapiGet).toHaveBeenCalledWith('notifications?filter=all');
      expect(ctx.notifications).toEqual(mockData);
      expect(ctx.unreadCount).toBe(1);
    });

    it('handles errors gracefully during loadNotifications', async () => {
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
      const mockPapiGet = jest.fn().mockRejectedValue(new Error('Network error'));
      const ctx = {
        username: 'admin',
        FEAT_NTF: 'ntf',
        notificationsStarted: true,
        isLicensed: jest.fn(() => true),
        notificationShowDismissed: false,
        notifications: [],
        papi: { get: mockPapiGet }
      };

      await app.loadNotifications.call(ctx);
      expect(consoleErrorSpy).toHaveBeenCalledWith('Failed to load notifications', expect.any(Error));
      consoleErrorSpy.mockRestore();
    });
  });

  describe('loadUnreadCount', () => {
    it('skips loading unread count when username is missing or unlicensed or notifications not started', async () => {
      const mockPapiGet = jest.fn();
      const ctx = {
        username: '',
        FEAT_NTF: 'ntf',
        notificationsStarted: true,
        isLicensed: jest.fn(() => true),
        papi: { get: mockPapiGet }
      };

      await app.loadUnreadCount.call(ctx);
      expect(mockPapiGet).not.toHaveBeenCalled();

      ctx.username = 'admin';
      ctx.isLicensed = jest.fn(() => false);
      await app.loadUnreadCount.call(ctx);
      expect(mockPapiGet).not.toHaveBeenCalled();

      ctx.isLicensed = jest.fn(() => true);
      ctx.notificationsStarted = false;
      await app.loadUnreadCount.call(ctx);
      expect(mockPapiGet).not.toHaveBeenCalled();
    });

    it('fetches unread count and updates unreadCount state', async () => {
      const mockData = [{ id: '1' }, { id: '2' }, { id: '3' }];
      const mockPapiGet = jest.fn().mockResolvedValue({ data: mockData });
      const ctx = {
        username: 'admin',
        FEAT_NTF: 'ntf',
        notificationsStarted: true,
        isLicensed: jest.fn(() => true),
        unreadCount: 0,
        papi: { get: mockPapiGet }
      };

      await app.loadUnreadCount.call(ctx);
      expect(mockPapiGet).toHaveBeenCalledWith('notifications?filter=unread');
      expect(ctx.unreadCount).toBe(3);
    });
  });

  describe('toggleNotificationExpand', () => {
    it('expands collapsed unread notification and automatically marks it as read', () => {
      const mockMarkAsRead = jest.fn();
      const ctx = {
        expandedNotifications: {},
        markAsRead: mockMarkAsRead
      };

      const notif = { id: 'notif-100', isRead: false };
      app.toggleNotificationExpand.call(ctx, notif);

      expect(ctx.expandedNotifications['notif-100']).toBe(true);
      expect(mockMarkAsRead).toHaveBeenCalledWith('notif-100', true);
    });

    it('expands collapsed already-read notification without calling markAsRead', () => {
      const mockMarkAsRead = jest.fn();
      const ctx = {
        expandedNotifications: {},
        markAsRead: mockMarkAsRead
      };

      const notif = { id: 'notif-101', isRead: true };
      app.toggleNotificationExpand.call(ctx, notif);

      expect(ctx.expandedNotifications['notif-101']).toBe(true);
      expect(mockMarkAsRead).not.toHaveBeenCalled();
    });

    it('collapses an already expanded notification', () => {
      const mockMarkAsRead = jest.fn();
      const ctx = {
        expandedNotifications: { 'notif-100': true },
        markAsRead: mockMarkAsRead
      };

      const notif = { id: 'notif-100', isRead: true };
      app.toggleNotificationExpand.call(ctx, notif);

      expect(ctx.expandedNotifications['notif-100']).toBe(false);
      expect(mockMarkAsRead).not.toHaveBeenCalled();
    });
  });

  describe('markAsRead', () => {
    it('updates read status and reloads notifications', async () => {
      const mockPapiPut = jest.fn().mockResolvedValue({ data: { success: true } });
      const mockLoadNotifications = jest.fn();

      const ctx = {
        papi: { put: mockPapiPut },
        loadNotifications: mockLoadNotifications
      };

      await app.markAsRead.call(ctx, 'notif-1', true);
      expect(mockPapiPut).toHaveBeenCalledWith('notifications/notif-1/read', { isRead: true });
      expect(mockLoadNotifications).toHaveBeenCalled();
    });
  });

  describe('markAllAsRead', () => {
    it('sends bulk read request and reloads notifications and unread count', async () => {
      const mockPapiPut = jest.fn().mockResolvedValue({ data: { success: true } });
      const mockLoadNotifications = jest.fn();
      const mockLoadUnreadCount = jest.fn();

      const ctx = {
        papi: { put: mockPapiPut },
        loadNotifications: mockLoadNotifications,
        loadUnreadCount: mockLoadUnreadCount
      };

      await app.markAllAsRead.call(ctx, true);
      expect(mockPapiPut).toHaveBeenCalledWith('notifications/read/all', { isRead: true });
      expect(mockLoadNotifications).toHaveBeenCalled();
      expect(mockLoadUnreadCount).toHaveBeenCalled();
    });
  });

  describe('dismissNotification', () => {
    it('updates dismissal status and reloads notifications', async () => {
      const mockPapiPut = jest.fn().mockResolvedValue({ data: { success: true } });
      const mockLoadNotifications = jest.fn();

      const ctx = {
        papi: { put: mockPapiPut },
        loadNotifications: mockLoadNotifications
      };

      await app.dismissNotification.call(ctx, 'notif-1', true);
      expect(mockPapiPut).toHaveBeenCalledWith('notifications/notif-1/dismiss', { isDismissed: true });
      expect(mockLoadNotifications).toHaveBeenCalled();
    });
  });

  describe('dismissAll', () => {
    it('sends bulk dismiss request and reloads notifications and unread count', async () => {
      const mockPapiPut = jest.fn().mockResolvedValue({ data: { success: true } });
      const mockLoadNotifications = jest.fn();
      const mockLoadUnreadCount = jest.fn();

      const ctx = {
        papi: { put: mockPapiPut },
        loadNotifications: mockLoadNotifications,
        loadUnreadCount: mockLoadUnreadCount
      };

      await app.dismissAll.call(ctx, true);
      expect(mockPapiPut).toHaveBeenCalledWith('notifications/dismiss/all', { isDismissed: true });
      expect(mockLoadNotifications).toHaveBeenCalled();
      expect(mockLoadUnreadCount).toHaveBeenCalled();
    });
  });

  describe('toggleNotificationShowDismissed', () => {
    it('toggles notificationShowDismissed boolean and reloads notifications', async () => {
      const mockLoadNotifications = jest.fn();
      const ctx = {
        notificationShowDismissed: false,
        loadNotifications: mockLoadNotifications
      };

      await app.toggleNotificationShowDismissed.call(ctx);
      expect(ctx.notificationShowDismissed).toBe(true);
      expect(mockLoadNotifications).toHaveBeenCalled();

      await app.toggleNotificationShowDismissed.call(ctx);
      expect(ctx.notificationShowDismissed).toBe(false);
    });
  });

  describe('loadNotificationAudit', () => {
    it('fetches audit logs and populates notificationAudits map for the given notification ID', async () => {
      const mockAuditData = [{ userId: 'user1', isRead: true, isDismissed: false }];
      const mockPapiGet = jest.fn().mockResolvedValue({ data: mockAuditData });
      const ctx = {
        notificationAudits: {},
        papi: { get: mockPapiGet }
      };

      await app.loadNotificationAudit.call(ctx, 'notif-1');
      expect(mockPapiGet).toHaveBeenCalledWith('notifications/notif-1/audit');
      expect(ctx.notificationAudits['notif-1']).toEqual(mockAuditData);
    });
  });

  describe('refreshNotifications', () => {
    it('calls loadNotifications directly without duplicate count queries', () => {
      const mockLoadNotifications = jest.fn();

      const ctx = {
        loadNotifications: mockLoadNotifications
      };

      app.refreshNotifications.call(ctx);
      expect(mockLoadNotifications).toHaveBeenCalled();
    });
  });

  describe('handleServerInfoNotifications', () => {
    it('triggers auto-refresh when lastUnreadNotificationTime changes and notificationsStarted is true', () => {
      const mockLoadUnreadCount = jest.fn();
      const mockLoadNotifications = jest.fn();

      const ctx = {
        FEAT_NTF: 'ntf',
        isLicensed: jest.fn(() => true),
        notificationsStarted: false,
        lastUnreadNotificationTime: null,
        notificationMenu: true,
        loadUnreadCount: mockLoadUnreadCount,
        loadNotifications: mockLoadNotifications
      };

      app.handleServerInfoNotifications.call(ctx, {
        notificationsStarted: true,
        lastUnreadNotificationTime: '2026-08-20T17:00:00Z'
      });

      expect(ctx.notificationsStarted).toBe(true);
      expect(ctx.lastUnreadNotificationTime).toBe('2026-08-20T17:00:00Z');
      expect(mockLoadUnreadCount).toHaveBeenCalled();
      expect(mockLoadNotifications).toHaveBeenCalled();
    });

    it('does not trigger reload when lastUnreadNotificationTime is unchanged', () => {
      const mockLoadUnreadCount = jest.fn();
      const mockLoadNotifications = jest.fn();

      const ctx = {
        FEAT_NTF: 'ntf',
        isLicensed: jest.fn(() => true),
        notificationsStarted: true,
        lastUnreadNotificationTime: '2026-08-20T17:00:00Z',
        notificationMenu: true,
        loadUnreadCount: mockLoadUnreadCount,
        loadNotifications: mockLoadNotifications
      };

      app.handleServerInfoNotifications.call(ctx, {
        notificationsStarted: true,
        lastUnreadNotificationTime: '2026-08-20T17:00:00Z'
      });

      expect(mockLoadUnreadCount).not.toHaveBeenCalled();
      expect(mockLoadNotifications).not.toHaveBeenCalled();
    });

    it('skips loading when notificationsStarted is false in server info', () => {
      const mockLoadUnreadCount = jest.fn();
      const mockLoadNotifications = jest.fn();

      const ctx = {
        FEAT_NTF: 'ntf',
        isLicensed: jest.fn(() => true),
        notificationsStarted: true,
        lastUnreadNotificationTime: null,
        notificationMenu: true,
        loadUnreadCount: mockLoadUnreadCount,
        loadNotifications: mockLoadNotifications
      };

      app.handleServerInfoNotifications.call(ctx, {
        notificationsStarted: false,
        lastUnreadNotificationTime: '2026-08-20T17:00:00Z'
      });

      expect(ctx.notificationsStarted).toBe(false);
      expect(mockLoadUnreadCount).not.toHaveBeenCalled();
      expect(mockLoadNotifications).not.toHaveBeenCalled();
    });
  });

  describe('handleIncomingNotification', () => {
    it('increments unreadCount and refreshes open panel on incoming websocket payload', () => {
      const mockLoadNotifications = jest.fn();

      const ctx = {
        FEAT_NTF: 'ntf',
        isLicensed: jest.fn(() => true),
        notificationsStarted: true,
        unreadCount: 2,
        lastUnreadNotificationTime: null,
        notificationMenu: true,
        loadNotifications: mockLoadNotifications
      };

      app.handleIncomingNotification.call(ctx, {
        id: 'notif-999',
        title: 'Realtime Alert',
        timestamp: '2026-08-20T17:15:00Z'
      });

      expect(ctx.unreadCount).toBe(3);
      expect(ctx.lastUnreadNotificationTime).toBe('2026-08-20T17:15:00Z');
      expect(mockLoadNotifications).toHaveBeenCalled();
    });

    it('increments unreadCount without refreshing list if menu is closed', () => {
      const mockLoadNotifications = jest.fn();

      const ctx = {
        FEAT_NTF: 'ntf',
        isLicensed: jest.fn(() => true),
        notificationsStarted: true,
        unreadCount: 0,
        lastUnreadNotificationTime: null,
        notificationMenu: false,
        loadNotifications: mockLoadNotifications
      };

      app.handleIncomingNotification.call(ctx, {
        id: 'notif-999',
        title: 'Realtime Alert',
        timestamp: '2026-08-20T17:15:00Z'
      });

      expect(ctx.unreadCount).toBe(1);
      expect(ctx.lastUnreadNotificationTime).toBe('2026-08-20T17:15:00Z');
      expect(mockLoadNotifications).not.toHaveBeenCalled();
    });

    it('does nothing if notifications not started', () => {
      const mockLoadNotifications = jest.fn();

      const ctx = {
        FEAT_NTF: 'ntf',
        isLicensed: jest.fn(() => true),
        notificationsStarted: false,
        unreadCount: 0,
        loadNotifications: mockLoadNotifications
      };

      app.handleIncomingNotification.call(ctx, {
        id: 'notif-999'
      });

      expect(ctx.unreadCount).toBe(0);
      expect(mockLoadNotifications).not.toHaveBeenCalled();
    });

    it('triggers toast notification on incoming payload with title', () => {
      const mockLoadNotifications = jest.fn();

      const ctx = {
        FEAT_NTF: 'ntf',
        isLicensed: jest.fn(() => true),
        notificationsStarted: true,
        unreadCount: 0,
        lastUnreadNotificationTime: null,
        notificationMenu: false,
        notificationToast: false,
        notificationToastTitle: '',
        notificationToastSeverity: 'info',
        loadNotifications: mockLoadNotifications,
        showNotificationToast: app.showNotificationToast
      };

      app.handleIncomingNotification.call(ctx, {
        id: 'notif-999',
        title: 'New High Severity Alert',
        severity: 'high',
        timestamp: '2026-08-20T17:15:00Z'
      });

      expect(ctx.notificationToast).toBe(true);
      expect(ctx.notificationToastTitle).toBe('New High Severity Alert');
      expect(ctx.notificationToastSeverity).toBe('high');
    });

    it('does nothing if unlicensed for notifications', () => {
      const mockLoadNotifications = jest.fn();

      const ctx = {
        FEAT_NTF: 'ntf',
        isLicensed: jest.fn(() => false),
        unreadCount: 0,
        loadNotifications: mockLoadNotifications
      };

      app.handleIncomingNotification.call(ctx, {
        id: 'notif-999'
      });

      expect(ctx.unreadCount).toBe(0);
      expect(mockLoadNotifications).not.toHaveBeenCalled();
    });
  });

  describe('toast helpers', () => {
    it('maps severity to toast colors correctly', () => {
      expect(app.getNotificationToastColor('critical')).toBe('red-darken-4');
      expect(app.getNotificationToastColor('high')).toBe('deep-orange-darken-3');
      expect(app.getNotificationToastColor('medium')).toBe('amber-darken-4');
      expect(app.getNotificationToastColor('low')).toBe('blue-darken-3');
      expect(app.getNotificationToastColor('info')).toBe('grey-darken-3');
      expect(app.getNotificationToastColor(null)).toBe('grey-darken-3');
    });

    it('opens notification panel when clicking toast', () => {
      const mockLoadNotifications = jest.fn();
      const ctx = {
        notificationToast: true,
        notificationMenu: false,
        loadNotifications: mockLoadNotifications
      };

      app.openNotificationFromToast.call(ctx);
      expect(ctx.notificationToast).toBe(false);
      expect(ctx.notificationMenu).toBe(true);
      expect(mockLoadNotifications).toHaveBeenCalled();
    });
  });
});
