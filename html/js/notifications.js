// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

globalThis.socNotifications = {
  loadNotifications() {
    if (!this.username || !this.isLicensed(this.FEAT_NTF) || !this.notificationsStarted) return Promise.resolve();
    const filter = this.notificationShowDismissed ? 'all' : 'active';
    return this.papi.get('notifications?filter=' + filter)
      .then(response => {
        this.notifications = response.data || [];
        this.unreadCount = this.notifications.filter(n => !n.isRead && !n.isDismissed).length;
        return this.notifications;
      })
      .catch(err => {
        console.error('Failed to load notifications', err);
      });
  },

  loadUnreadCount() {
    if (!this.username || !this.isLicensed(this.FEAT_NTF) || !this.notificationsStarted) return Promise.resolve();
    return this.papi.get('notifications?filter=unread')
      .then(response => {
        this.unreadCount = (response.data || []).length;
        return this.unreadCount;
      })
      .catch(err => {
        console.error('Failed to load unread count', err);
      });
  },

  markAsRead(id, isRead) {
    return this.papi.put('notifications/' + id + '/read', { isRead })
      .then(() => {
        return this.loadNotifications();
      })
      .catch(err => {
        console.error('Failed to update read state', err);
      });
  },

  dismissNotification(id, isDismissed) {
    return this.papi.put('notifications/' + id + '/dismiss', { isDismissed })
      .then(() => {
        return this.loadNotifications();
      })
      .catch(err => {
        console.error('Failed to update dismiss state', err);
      });
  },

  loadNotificationAudit(id) {
    return this.papi.get('notifications/' + id + '/audit')
      .then(response => {
        this.notificationAudits[id] = response.data || [];
        return this.notificationAudits[id];
      })
      .catch(err => {
        console.error('Failed to load notification audit', err);
      });
  },

  getSeverityColorClass(severity, isRead) {
    const s = severity?.toLowerCase();
    if (isRead) {
      switch (s) {
        case 'critical': return 'text-red-accent-4';
        case 'high': return 'text-red-darken-1';
        case 'medium': return 'text-orange-darken-1';
        case 'low': return 'text-yellow-darken-2';
        default: return 'text-blue-darken-1';
      }
    }
    switch (s) {
      case 'critical': return 'text-red-accent-4 font-weight-black';
      case 'high': return 'text-red-darken-1 font-weight-bold';
      case 'medium': return 'text-orange-darken-1 font-weight-bold';
      case 'low': return 'text-yellow-darken-2 font-weight-bold';
      default: return 'text-blue-darken-1 font-weight-bold';
    }
  },

  formatTimeAgo(timestamp) {
    if (!timestamp) return '';
    return moment(timestamp).fromNow();
  },

  sanitizeDeepLink(url) {
    if (!url || typeof url !== 'string') return '#';
    const trimmed = url.trim();
    if (/^(javascript|data|vbscript):/i.test(trimmed)) {
      return '#';
    }
    if (trimmed.startsWith('http://') || trimmed.startsWith('https://') || trimmed.startsWith('/') || trimmed.startsWith('#')) {
      return trimmed;
    }
    if (!trimmed.includes(':')) {
      return trimmed;
    }
    return '#';
  },

  toggleNotificationExpand(notif) {
    if (!notif || !notif.id) return;
    if (!this.expandedNotifications) {
      this.expandedNotifications = {};
    }
    const isExpanded = !!this.expandedNotifications[notif.id];
    this.expandedNotifications[notif.id] = !isExpanded;
    if (!isExpanded && !notif.isRead) {
      this.markAsRead(notif.id, true);
    }
  },

  refreshNotifications() {
    return this.loadNotifications();
  },

  handleServerInfoNotifications(infoData) {
    if (!infoData) return;
    this.notificationsStarted = !!infoData.notificationsStarted;
    if (!this.isLicensed(this.FEAT_NTF) || !this.notificationsStarted) return;
    const newLastUnread = infoData.lastUnreadNotificationTime || null;
    const prevLastUnread = this.lastUnreadNotificationTime || null;
    this.lastUnreadNotificationTime = newLastUnread;
    if (newLastUnread !== prevLastUnread) {
      this.loadUnreadCount();
      if (this.notificationMenu) {
        this.loadNotifications();
      }
    }
  },

  handleIncomingNotification(payload) {
    if (!this.isLicensed(this.FEAT_NTF) || !this.notificationsStarted) return;
    this.unreadCount = (this.unreadCount || 0) + 1;
    if (payload && payload.timestamp) {
      this.lastUnreadNotificationTime = payload.timestamp;
    }
    if (this.notificationMenu) {
      this.loadNotifications();
    }
  }
};

var socNotifications = globalThis.socNotifications;

if (typeof window !== 'undefined') {
  window.socNotifications = socNotifications;
}
if (typeof global !== 'undefined') {
  global.socNotifications = socNotifications;
}
if (typeof module !== 'undefined' && module.exports) {
  module.exports = socNotifications;
}
