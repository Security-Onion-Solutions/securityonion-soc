// Copyright 2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

// Simple Alerts Interface - Hidden by default
// To enable Simple Alerts:
// 1. Navigate to the app with ?simple-alerts=true in the URL (one-time enable)
// 2. Press Ctrl+Shift+S keyboard shortcut to toggle on/off
// 3. Once enabled, it will persist in localStorage

loadPageTemplate('page-simple-alerts', 'pages/alerts.html');
const simpleAlertsComponent = {
  template: '#page-simple-alerts',
  props: [],
  data() {
    return {
      alerts: [],
      loading: false,
      loadingMore: false,
      totalAlerts: 0,
      hasMore: false,
      eventLimit: 100,  // Increased from 20
      currentPage: 0,
      
      // Statistics
      totalActiveAlerts: 0,
      totalHighSeverity: 0,
      totalMediumSeverity: 0,
      totalLowSeverity: 0,
      
      // Filter states
      filterSeverity: 'all',
      filterStatus: 'active',
      filterTimeRange: '24h',
      
      // Action dialog
      actionDialog: false,
      actionType: '',
      actionTitle: '',
      actionLoading: false,
      selectedAlert: null,
      selectedGroup: null,
      selectedSubGroup: null,
      caseTitle: '',
      caseDescription: '',
      
      // Details dialog
      detailsDialog: false,
      selectedAlertDetails: null,
      expandedQuestions: [],
      
      // PCAP
      pcapLoading: false,
      pcapJobId: null,
      pcapJobStatus: null,
      pcapData: null,
      pcapError: null,
      pcapMonitorInterval: null,
      pcapPackets: [],
      pcapPacketsLoading: false,
      expandedPackets: [],
      
      // Grouping
      groupAlerts: true,  // Default to grouped view
      alertGroups: [],
      expandedGroups: [],
      expandedSubGroups: {},  // Track expanded state of sub-groups
      subGroupDisplayLimit: 50, // Limit alerts shown per sub-group for performance
      subGroupLoadMore: {}, // Track which sub-groups have "load more" active
      
      // Selection state
      selectedAlerts: new Set(), // Individual alert IDs
      selectedSubGroups: new Set(), // Sub-group keys (source->dest combinations)
      selectedGroups: new Set(), // Top-level group keys (rule names)
      selectionMode: false, // Toggle selection mode
      
      // Rule management
      disablingRules: {}, // Track which rules are being disabled
      suppressLoading: {}, // Track which suppressions are in progress
      
      // Filter options
      severityOptions: [
        { value: 'all', title: 'All Severities' },
        { value: 'high', title: 'High' },
        { value: 'medium', title: 'Medium' },
        { value: 'low', title: 'Low' }
      ],
      statusOptions: [
        { value: 'all', title: 'All Statuses' },
        { value: 'active', title: 'Active' },
        { value: 'acknowledged', title: 'Acknowledged' },
        { value: 'escalated', title: 'Escalated' }
      ],
      timeRangeOptions: [
        { value: '1h', title: 'Last Hour' },
        { value: '24h', title: 'Last 24 Hours' },
        { value: '7d', title: 'Last 7 Days' },
        { value: '30d', title: 'Last 30 Days' }
      ]
    };
  },
  computed: {
    // These are now just getters for the total counts
    unacknowledgedAlerts() {
      return { length: this.totalActiveAlerts };
    },
    highSeverityCount() {
      return this.totalHighSeverity;
    },
    mediumSeverityCount() {
      return this.totalMediumSeverity;
    },
    lowSeverityCount() {
      return this.totalLowSeverity;
    },
    selectedCount() {
      // Calculate total selected alerts
      let count = this.selectedAlerts.size;
      
      // Add alerts from selected subgroups
      this.alertGroups.forEach(group => {
        const subGroups = this.getSubGroups(group);
        subGroups.forEach(subGroup => {
          if (this.selectedSubGroups.has(subGroup.key)) {
            count += subGroup.alerts.filter(a => !this.selectedAlerts.has(a.id)).length;
          }
        });
      });
      
      // Add alerts from selected groups
      this.selectedGroups.forEach(groupKey => {
        const group = this.alertGroups.find(g => g.key === groupKey);
        if (group) {
          count += group.alerts.filter(a => !this.isAlertSelected(a.id)).length;
        }
      });
      
      return count;
    },
    hasSelection() {
      return this.selectedAlerts.size > 0 || this.selectedSubGroups.size > 0 || this.selectedGroups.size > 0;
    },
    processedAlerts() {
      if (!this.groupAlerts) {
        return this.alerts;
      }
      
      // Group alerts by rule name only at the top level
      const groups = new Map();
      
      this.alerts.forEach(alert => {
        const groupKey = alert.ruleName;
        
        if (!groups.has(groupKey)) {
          groups.set(groupKey, {
            key: groupKey,
            ruleName: alert.ruleName,
            module: alert.module,
            severityLabel: alert.severityLabel,
            category: alert.category,
            firstSeen: alert.timestamp,
            lastSeen: alert.timestamp,
            alerts: [],
            count: 0,
            subGroups: new Map() // Track IP-based subgroups
          });
        }
        
        const group = groups.get(groupKey);
        group.alerts.push(alert);
        group.count++;
        
        // Update first and last seen timestamps
        if (alert.timestamp < group.firstSeen) {
          group.firstSeen = alert.timestamp;
        }
        if (alert.timestamp > group.lastSeen) {
          group.lastSeen = alert.timestamp;
        }
        
        // Use highest severity in group
        if (this.getSeverityLevel(alert) === 'high' && group.severityLabel !== 'high') {
          group.severityLabel = alert.severityLabel;
        } else if (this.getSeverityLevel(alert) === 'medium' && group.severityLabel === 'low') {
          group.severityLabel = alert.severityLabel;
        }
      });
      
      // Convert to array, filter out empty groups, and sort by count
      this.alertGroups = Array.from(groups.values())
        .filter(group => group.count > 0)  // Remove groups with no alerts
        .sort((a, b) => b.count - a.count);
      
      return this.alertGroups;
    }
  },
  mounted() {
    this.loadAlerts();
  },
  watch: {
    detailsDialog(newVal) {
      if (!newVal) {
        // Clear PCAP data when dialog closes
        this.clearPcapData();
      }
    }
  },
  methods: {
    async loadAlerts() {
      this.loading = true;
      this.currentPage = 0;
      
      try {
        const query = this.buildQuery();
        const dateRange = this.getDateRange();
        
        // Debug log
        console.log('Loading alerts with time range:', this.filterTimeRange, 'Date range:', dateRange);
        console.log('All filter values:', {
          severity: this.filterSeverity,
          status: this.filterStatus,
          timeRange: this.filterTimeRange
        });
        
        // When grouping is enabled, fetch more alerts to ensure proper grouping
        // Otherwise use the default limit for performance
        const effectiveLimit = this.groupAlerts ? '10000' : this.eventLimit.toString();
        
        const params = new URLSearchParams({
          query: query,
          range: dateRange,
          format: '2006/01/02 3:04:05 PM',
          zone: Intl.DateTimeFormat().resolvedOptions().timeZone,
          metricLimit: '10',
          eventLimit: effectiveLimit,
          view: 'simple' // Use simplified view
        });
        
        const response = await this.$root.papi.get('events/?' + params.toString());
        
        if (response && response.data) {
          this.alerts = this.processAlerts(response.data.events || []);
          this.totalAlerts = response.data.totalEvents || 0;
          this.hasMore = this.totalAlerts > this.alerts.length;
          
          // Update statistics - we need to make a separate call to get all active alerts stats
          await this.loadStatistics();
        }
      } catch (error) {
        this.$root.showError(error);
      } finally {
        this.loading = false;
      }
    },
    
    async loadMore() {
      this.loadingMore = true;
      
      try {
        const query = this.buildQuery();
        const dateRange = this.getDateRange();
        
        // Get the last alert's sort value for pagination
        const lastAlert = this.alerts[this.alerts.length - 1];
        const searchAfter = lastAlert ? [lastAlert.timestamp] : null;
        
        const params = new URLSearchParams({
          query: query,
          range: dateRange,
          format: '2006/01/02 3:04:05 PM',
          zone: Intl.DateTimeFormat().resolvedOptions().timeZone,
          metricLimit: '10',
          eventLimit: this.eventLimit.toString(),
          view: 'simple'
        });
        
        if (searchAfter) {
          params.append('searchAfter', JSON.stringify(searchAfter));
        }
        
        const response = await this.$root.papi.get('events/?' + params.toString());
        
        if (response && response.data) {
          const newAlerts = this.processAlerts(response.data.events || []);
          this.alerts.push(...newAlerts);
          this.hasMore = this.totalAlerts > this.alerts.length;
        }
      } catch (error) {
        this.$root.showError(error);
      } finally {
        this.loadingMore = false;
      }
    },
    
    buildQuery() {
      let query = 'tags:alert';
      
      // Status filter
      if (this.filterStatus === 'active') {
        query += ' AND NOT event.acknowledged:true AND NOT event.escalated:true';
      } else if (this.filterStatus === 'acknowledged') {
        query += ' AND event.acknowledged:true';
      } else if (this.filterStatus === 'escalated') {
        query += ' AND event.escalated:true';
      }
      
      // Severity filter
      if (this.filterSeverity !== 'all') {
        query += ` AND event.severity_label:${this.filterSeverity}`;
      }
      
      return query;
    },
    
    getDateRange() {
      const now = new Date();
      const format = (date) => {
        // Format date to match the expected format: "2006/01/02 3:04:05 PM"
        // This is Go's reference time format
        const year = date.getFullYear();
        const month = String(date.getMonth() + 1).padStart(2, '0');
        const day = String(date.getDate()).padStart(2, '0');
        let hours = date.getHours();
        const minutes = String(date.getMinutes()).padStart(2, '0');
        const seconds = String(date.getSeconds()).padStart(2, '0');
        const ampm = hours >= 12 ? 'PM' : 'AM';
        hours = hours % 12 || 12; // Convert to 12-hour format
        
        return `${year}/${month}/${day} ${hours}:${minutes}:${seconds} ${ampm}`;
      };
      
      let startDate;
      switch (this.filterTimeRange) {
        case '1h':
          startDate = new Date(now.getTime() - 60 * 60 * 1000);
          break;
        case '24h':
          startDate = new Date(now.getTime() - 24 * 60 * 60 * 1000);
          break;
        case '7d':
          startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
          break;
        case '30d':
          startDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
          break;
        default:
          startDate = new Date(now.getTime() - 24 * 60 * 60 * 1000);
      }
      
      return `${format(startDate)} - ${format(now)}`;
    },
    
    processAlerts(events) {
      return events.map(event => ({
        id: event.id,
        timestamp: event.timestamp,
        ruleName: event.payload['rule.name'] || 'Unknown Rule',
        ruleUuid: event.payload['rule.uuid'],
        severity: event.payload['event.severity'],
        severityLabel: event.payload['event.severity_label'] || 'unknown',
        sourceIp: event.payload['source.ip'],
        sourcePort: event.payload['source.port'],
        destIp: event.payload['destination.ip'],
        destPort: event.payload['destination.port'],
        module: event.payload['event.module'],
        category: event.payload['event.category'],
        acknowledged: event.payload['event.acknowledged'] || false,
        escalated: event.payload['event.escalated'] || false,
        dismissed: event.payload['event.dismissed'] || false,
        // Store the entire payload for potential AI summary extraction
        payload: event.payload
      }));
    },
    
    getSeverityLevel(alert) {
      const label = (alert.severityLabel || '').toLowerCase();
      if (label.includes('high') || label.includes('critical')) return 'high';
      if (label.includes('medium')) return 'medium';
      return 'low';
    },
    
    async acknowledgeAlert(alert) {
      // Directly acknowledge single alert without dialog
      try {
        await this.updateAlertStatuses([alert.id], 'acknowledged');
        this.$root.showTip('Alert acknowledged');
        await this.loadAlerts();
      } catch (error) {
        this.$root.showError(`Failed to acknowledge alert: ${error.message}`);
      }
    },
    
    escalateAlert(alert) {
      this.selectedAlert = alert;
      this.actionType = 'escalate';
      this.actionTitle = 'Escalate to Case';
      this.caseTitle = `Alert: ${alert.ruleName}`;
      this.caseDescription = `Alert from ${alert.sourceIp} to ${alert.destIp}`;
      this.actionDialog = true;
    },
    
    
    async confirmAction() {
      if (!this.selectedAlert) return;
      
      this.actionLoading = true;
      
      try {
        if (this.actionType === 'acknowledge-group') {
          // Group acknowledge
          const group = this.selectedGroup;
          
          // For group acknowledgment, use rule name filter instead of individual IDs
          // This ensures we get ALL alerts matching the rule, not just the loaded ones
          const searchFilter = `tags:alert AND rule.name:"${group.ruleName}" AND NOT event.acknowledged:true AND NOT event.escalated:true`;
          const eventFilter = { 'tags': 'alert' };
          
          const response = await this.$root.papi.post('events/ack', {
            searchFilter: searchFilter,
            eventFilter: eventFilter,
            dateRange: this.getDateRange(),
            dateRangeFormat: '2006/01/02 3:04:05 PM',
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            acknowledge: true,
            escalate: false
          });
          
          this.$root.showTip(`All alerts acknowledged for "${group.ruleName}"`);
          // Don't clear selectedGroup here - we need it for expansion restoration below
        } else if (this.actionType === 'acknowledge-subgroup') {
          // SubGroup acknowledge
          const group = this.selectedGroup;
          const subGroup = this.selectedSubGroup;
          
          // For subgroup acknowledgment, use rule name + IP filter instead of individual IDs
          let searchFilter = `tags:alert AND rule.name:"${group.ruleName}" AND NOT event.acknowledged:true AND NOT event.escalated:true`;
          
          // Add source IP filter if present
          if (subGroup.sourceIp && subGroup.sourceIp !== 'unknown') {
            searchFilter += ` AND source.ip:"${subGroup.sourceIp}"`;
          }
          
          // Add dest IP filter if present  
          if (subGroup.destIp && subGroup.destIp !== 'unknown') {
            searchFilter += ` AND destination.ip:"${subGroup.destIp}"`;
          }
          
          const eventFilter = { 'tags': 'alert' };
          
          const response = await this.$root.papi.post('events/ack', {
            searchFilter: searchFilter,
            eventFilter: eventFilter,
            dateRange: this.getDateRange(),
            dateRangeFormat: '2006/01/02 3:04:05 PM',
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            acknowledge: true,
            escalate: false
          });
          
          this.$root.showTip(`All "${group.ruleName}" alerts acknowledged for ${subGroup.sourceIp} → ${subGroup.destIp}`);
          // Don't clear selectedGroup here - we need it for expansion restoration below
        } else if (this.actionType === 'escalate-subgroup') {
          // SubGroup escalate
          const alertIds = this.selectedSubGroup.alerts.map(a => a.id);
          
          // Create a case with all subgroup alerts
          const caseData = {
            title: this.caseTitle,
            description: this.caseDescription,
            severity: this.selectedAlert.severityLabel || 'high',
            status: 'new',
            events: alertIds
          };
          
          await this.$root.papi.post('case', caseData);
          
          // Update all alert statuses using bulk API
          await this.updateAlertStatuses(alertIds, 'escalated');
          
          this.$root.showTip(`${alertIds.length} "${group.ruleName}" alerts escalated to case for ${this.selectedSubGroup.sourceIp} → ${this.selectedSubGroup.destIp}`);
          // Don't clear selectedSubGroup here - cleared later
        } else if (this.actionType === 'escalate-group') {
          // Group escalate
          const alertIds = this.selectedGroup.alerts.map(a => a.id);
          
          // Create a case with all group alerts
          const caseData = {
            title: this.caseTitle,
            description: this.caseDescription,
            severity: this.selectedGroup.severityLabel || 'high',
            status: 'new',
            events: alertIds
          };
          
          await this.$root.papi.post('case', caseData);
          
          // Update all alert statuses using bulk API
          await this.updateAlertStatuses(alertIds, 'escalated');
          
          this.$root.showTip(`${alertIds.length} alerts escalated to case for "${this.selectedGroup.ruleName}"`);
          // Don't clear selectedGroup here - cleared later
        } else if (this.actionType === 'escalate-bulk') {
          // Bulk escalate
          const alertIds = this.getSelectedAlertIds();
          
          // Create a case with multiple alerts
          const caseData = {
            title: this.caseTitle,
            description: this.caseDescription,
            severity: 'high', // Default to high for bulk escalations
            status: 'new',
            events: alertIds
          };
          
          await this.$root.papi.post('case', caseData);
          
          // Update all alert statuses using bulk API
          await this.updateAlertStatuses(alertIds, 'escalated');
          
          this.$root.showTip(`${alertIds.length} alert${alertIds.length > 1 ? 's' : ''} escalated to case`);
          this.clearSelection();
        } else if (this.actionType === 'escalate') {
          // Single escalate
          const caseData = {
            title: this.caseTitle,
            description: this.caseDescription,
            severity: this.selectedAlert.severityLabel,
            status: 'new',
            events: [this.selectedAlert.id]
          };
          
          await this.$root.papi.post('case', caseData);
          
          // Update alert status
          await this.updateAlertStatuses([this.selectedAlert.id], 'escalated');
          this.$root.showTip(`Alert escalated successfully`);
        } else if (this.actionType === 'acknowledge') {
          // Update alert status
          await this.updateAlertStatuses([this.selectedAlert.id], 'acknowledged');
          this.$root.showTip(`Alert acknowledged successfully`);
        }
        
        // Store expansion states before reload (only for subgroup operations)
        // MUST do this BEFORE clearing selections
        let expandedGroupKey = null;
        let expandedSubGroupIndices = [];
        
        // Store which group was expanded for any operation that has context
        if (this.selectedGroup) {
          expandedGroupKey = this.selectedGroup.key;
          
          // Get currently expanded subgroup indices
          if (this.expandedSubGroups[this.selectedGroup.key] && Array.isArray(this.expandedSubGroups[this.selectedGroup.key])) {
            // Store the current expanded indices
            expandedSubGroupIndices = [...this.expandedSubGroups[this.selectedGroup.key]];
          }
        } else if (this.actionType === 'acknowledge' || this.actionType === 'escalate') {
          // For individual alert actions, find which group/subgroup it belongs to
          // by looking at the currently expanded panels
          if (this.expandedGroups.length > 0) {
            const expandedGroupIndex = this.expandedGroups[this.expandedGroups.length - 1]; // Get the last expanded group
            if (this.alertGroups[expandedGroupIndex]) {
              expandedGroupKey = this.alertGroups[expandedGroupIndex].key;
              
              // Get currently expanded subgroup indices
              if (this.expandedSubGroups[expandedGroupKey] && Array.isArray(this.expandedSubGroups[expandedGroupKey])) {
                expandedSubGroupIndices = [...this.expandedSubGroups[expandedGroupKey]];
              }
            }
          }
        }
        
        // Clear selections and refresh the list
        this.selectedGroup = null;
        this.selectedSubGroup = null;
        this.selectedAlert = null;
        
        // Close dialog first to give visual feedback
        this.actionDialog = false;
        
        // Clear expansion states to prevent wrong panels from being expanded
        this.expandedGroups = [];
        this.expandedSubGroups = {};
        this.subGroupLoadMore = {};
        
        // Force a fresh reload of alerts
        this.alerts = [];  // Clear current alerts to force UI update
        await this.loadAlerts();
        
        // Re-expand the group and subgroups if they still exist
        if (expandedGroupKey) {
          // Wait for Vue to update the DOM
          await this.$nextTick();
          
          // Find the group by key in the new data
          const groupIndex = this.alertGroups.findIndex(g => g.key === expandedGroupKey);
          
          if (groupIndex !== -1) {
            // Re-expand the group if it still exists
            this.expandedGroups.push(groupIndex);
            
            // Get the new subgroups for this group
            const newGroup = this.alertGroups[groupIndex];
            const newSubGroups = this.getSubGroups(newGroup);
            
            // Restore previously expanded subgroups if any
            // Don't auto-expand all subgroups, just restore what was expanded before
            if (expandedSubGroupIndices.length > 0) {
              // Only restore the indices that were previously expanded
              // These indices might have shifted if we removed a subgroup
              // In Vue 3, use direct assignment instead of $set
              this.expandedSubGroups[expandedGroupKey] = expandedSubGroupIndices;
              
              // Force update to ensure Vue picks up the change
              await this.$nextTick();
            }
            // If no subgroups were expanded before, leave them all collapsed
            // The user can see the list of IP pairs and expand them as needed
          }
          // If groupIndex is -1, the group no longer exists (all alerts acknowledged)
          // so we don't need to do anything - it will simply not appear in the UI
        }
      } catch (error) {
        this.$root.showError(error);
      } finally {
        this.actionLoading = false;
      }
    },
    
    async updateAlertStatuses(alertIds, status) {
      // Use the bulk acknowledge endpoint for updating statuses
      if (!alertIds || alertIds.length === 0) return;
      
      const acknowledge = (status === 'acknowledged');
      const escalate = (status === 'escalated');
      
      let searchFilter;
      let eventFilter = {};
      
      if (alertIds.length === 1) {
        // Single ID - use eventFilter with wildcard search
        searchFilter = '*';
        eventFilter['_id'] = alertIds[0];
      } else {
        // Multiple IDs - use OR logic in search filter
        // But we still need a minimal eventFilter (API requirement)
        searchFilter = alertIds.map(id => `_id:"${id}"`).join(' OR ');
        eventFilter = { 'tags': 'alert' }; // Minimal filter to satisfy API requirement
      }
      
      const response = await this.$root.papi.post('events/ack', {
        searchFilter: searchFilter,
        eventFilter: eventFilter,
        dateRange: this.getDateRange(),
        dateRangeFormat: '2006/01/02 3:04:05 PM',
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        acknowledge: acknowledge,
        escalate: escalate
      });
      
      return response;
    },
    
    async loadStatistics() {
      try {
        // Build the base query
        let baseQuery = 'tags:alert';
        
        // Apply the same status filter as the main query
        if (this.filterStatus === 'active') {
          baseQuery += ' AND NOT event.acknowledged:true AND NOT event.escalated:true';
        } else if (this.filterStatus === 'acknowledged') {
          baseQuery += ' AND event.acknowledged:true';
        } else if (this.filterStatus === 'escalated') {
          baseQuery += ' AND event.escalated:true';
        }
        
        const dateRange = this.getDateRange();
        const baseParams = {
          range: dateRange,
          format: '2006/01/02 3:04:05 PM',
          zone: Intl.DateTimeFormat().resolvedOptions().timeZone,
          metricLimit: '10',
          eventLimit: '0'  // We only want the count, not the events
        };
        
        // If a specific severity is selected, just get that count
        if (this.filterSeverity !== 'all') {
          const query = baseQuery + ` AND event.severity_label:${this.filterSeverity}`;
          const params = new URLSearchParams({ ...baseParams, query });
          const response = await this.$root.papi.get('events/?' + params.toString());
          
          if (response && response.data) {
            this.totalActiveAlerts = response.data.totalEvents || 0;
            // Reset all counts
            this.totalHighSeverity = 0;
            this.totalMediumSeverity = 0;
            this.totalLowSeverity = 0;
            
            // Set the count for the selected severity
            if (this.filterSeverity === 'high') {
              this.totalHighSeverity = this.totalActiveAlerts;
            } else if (this.filterSeverity === 'medium') {
              this.totalMediumSeverity = this.totalActiveAlerts;
            } else if (this.filterSeverity === 'low') {
              this.totalLowSeverity = this.totalActiveAlerts;
            }
          }
        } else {
          // Get counts for each severity level
          const severityQueries = [
            { severity: 'high', query: baseQuery + ' AND (event.severity_label:high OR event.severity_label:critical)' },
            { severity: 'medium', query: baseQuery + ' AND event.severity_label:medium' },
            { severity: 'low', query: baseQuery + ' AND event.severity_label:low' }
          ];
          
          const requests = severityQueries.map(sq => {
            const params = new URLSearchParams({ ...baseParams, query: sq.query });
            return this.$root.papi.get('events/?' + params.toString());
          });
          
          const responses = await Promise.all(requests);
          
          // Process responses
          this.totalHighSeverity = responses[0]?.data?.totalEvents || 0;
          this.totalMediumSeverity = responses[1]?.data?.totalEvents || 0;
          this.totalLowSeverity = responses[2]?.data?.totalEvents || 0;
          
          // Total active alerts (get from main query)
          const totalParams = new URLSearchParams({ ...baseParams, query: baseQuery });
          const totalResponse = await this.$root.papi.get('events/?' + totalParams.toString());
          this.totalActiveAlerts = totalResponse?.data?.totalEvents || 0;
        }
        
        console.log('Statistics loaded:', {
          total: this.totalActiveAlerts,
          high: this.totalHighSeverity,
          medium: this.totalMediumSeverity,
          low: this.totalLowSeverity
        });
      } catch (error) {
        console.error('Failed to load statistics:', error);
        // Don't show error to user as this is supplementary data
      }
    },
    
    switchToExpertMode() {
      // Switch to the alerts page (which uses the hunt component)
      this.$router.push({
        name: 'alerts',
        query: {
          q: this.buildQuery(),
          rt: this.filterTimeRange === '1h' ? 1 : this.filterTimeRange === '24h' ? 24 : this.filterTimeRange === '7d' ? 7 * 24 : 30 * 24,
          rtu: 'hours'
        }
      });
    },
    
    updateTimeRange(value) {
      console.log('updateTimeRange called with:', value);
      this.filterTimeRange = value;
      this.loadAlerts();
    },
    
    updateSeverity(value) {
      this.filterSeverity = value;
      this.loadAlerts();
    },
    
    updateStatus(value) {
      this.filterStatus = value;
      this.loadAlerts();
    },
    
    getStatusLabel() {
      switch (this.filterStatus) {
        case 'active': return 'Active Alerts';
        case 'acknowledged': return 'Acknowledged Alerts';
        case 'escalated': return 'Escalated Alerts';
        case 'all': return 'Total Alerts';
        default: return 'Alerts';
      }
    },
    
    async showAlertDetails(alert) {
      // First, set the selected alert details
      this.selectedAlertDetails = alert;
      
      try {
        // Fetch the full alert with all fields using the regular view (not simple)
        const params = new URLSearchParams({
          query: `_id:"${alert.id}"`,
          range: this.getDateRange(),
          format: '2006/01/02 3:04:05 PM',
          zone: Intl.DateTimeFormat().resolvedOptions().timeZone,
          metricLimit: '0',
          eventLimit: '1'
          // Note: NOT using view=simple here to get all fields
        });
        
        const response = await this.$root.papi.get('events/?' + params.toString());
        
        if (response && response.data && response.data.events && response.data.events.length > 0) {
          const fullEvent = response.data.events[0];
          // Merge the full data with our simplified alert
          this.selectedAlertDetails = {
            ...alert,
            rawData: fullEvent.payload || {},
            aiSummary: null,
            playbooks: null,
            playbookLoading: false,
            playbookError: false
          };
          
          // Check for AI summary in the full event payload (usually not present)
          if (fullEvent.payload) {
            // Check various possible field names for AI summary
            const aiSummary = fullEvent.payload['ai.summary'] || 
                             fullEvent.payload['detection.ai_summary'] ||
                             fullEvent.payload['rule.ai_summary'] ||
                             fullEvent.payload['ai_summary'];
            
            if (aiSummary) {
              this.selectedAlertDetails.aiSummary = aiSummary;
            }
          }
          
          // If no AI summary in payload, fetch from detection API using the public endpoint
          // For Suricata rules, the ruleUuid is the signature ID (sid) which serves as the PublicId
          if (!this.selectedAlertDetails.aiSummary && alert.ruleUuid) {
            try {
              // Use the /detection/public/{publicid} endpoint for numeric Suricata SIDs
              const detectionResponse = await this.$root.papi.get(`/detection/public/${alert.ruleUuid}`);
              
              if (detectionResponse && detectionResponse.data) {
                // Check for AI summary in the detection response
                // The field name could be aiSummary, AiSummary, or nested in aiFields
                const detection = detectionResponse.data;
                
                // Log the detection structure to understand field names
                console.log('Detection response:', detection);
                
                // Try various possible field paths for AI summary
                let aiSummary = detection.aiSummary || 
                               detection.AiSummary ||
                               detection.ai_summary ||
                               detection.summary ||
                               detection.description;
                
                // Check nested structures
                if (!aiSummary && detection.aiFields) {
                  aiSummary = detection.aiFields.aiSummary || 
                             detection.aiFields.AiSummary ||
                             detection.aiFields.summary ||
                             detection.aiFields.description;
                }
                
                // Check if it's in a details or content field
                if (!aiSummary && detection.details) {
                  aiSummary = detection.details.aiSummary || 
                             detection.details.summary ||
                             detection.details.description;
                }
                
                // If we found a summary, use it
                if (aiSummary) {
                  // If it's an object, try to extract the text
                  if (typeof aiSummary === 'object' && aiSummary !== null) {
                    aiSummary = aiSummary.text || aiSummary.content || aiSummary.description || JSON.stringify(aiSummary);
                  }
                  
                  this.selectedAlertDetails.aiSummary = aiSummary;
                  console.log('Found AI summary:', aiSummary);
                }
                
                // Also store the full detection for additional context
                this.selectedAlertDetails.detection = detection;
              }
            } catch (detectionError) {
              // Silently ignore 404s - not all rules have detections
              if (detectionError.response && detectionError.response.status !== 404) {
                console.warn(`Failed to fetch detection for rule ${alert.ruleUuid}:`, detectionError);
              }
            }
          }
          
          // Fetch playbook/guided analysis data
          if (alert.ruleUuid) {
            this.selectedAlertDetails.playbookLoading = true;
            try {
              const playbookResponse = await this.$root.papi.get(`/playbook/detection/${alert.ruleUuid}`);
              
              if (playbookResponse && playbookResponse.data) {
                const playbooks = playbookResponse.data;
                
                // Process playbook questions - variable substitution
                for (let pb of playbooks) {
                  for (let question of pb.questions) {
                    // Simple query variable substitution
                    let query = question.query;
                    
                    // Replace variables with values from the event
                    const variables = query.match(/\{([^}]+)\}/g) || [];
                    for (const variable of variables) {
                      const fieldName = variable.slice(1, -1); // Remove { and }
                      const value = this.selectedAlertDetails.rawData[fieldName] || 'NODATA';
                      query = query.replace(variable, value);
                    }
                    
                    question.filledQuery = query;
                  }
                }
                
                // Convert queries from Sigma/other formats to OQL
                await this.convertPlaybookQueries(playbooks);
                
                // Execute queries and get answers
                await this.executePlaybookQueries(playbooks, fullEvent);
                
                this.selectedAlertDetails.playbooks = playbooks;
                this.selectedAlertDetails.playbookError = false;
              }
            } catch (playbookError) {
              console.log('Failed to fetch playbook:', playbookError);
              this.selectedAlertDetails.playbookError = true;
            } finally {
              this.selectedAlertDetails.playbookLoading = false;
            }
          }
        }
      } catch (error) {
        console.error('Failed to fetch full alert details:', error);
        // Still show the dialog with what we have
        this.selectedAlertDetails = {
          ...alert,
          rawData: {},
          aiSummary: null
        };
      }
      
      this.detailsDialog = true;
    },
    
    getSeverityColor(severityLabel) {
      const severity = (severityLabel || '').toLowerCase();
      if (severity.includes('high') || severity.includes('critical')) return 'error';
      if (severity.includes('medium')) return 'warning';
      return 'info';
    },
    
    getHuntUrl(alert) {
      if (!alert) return '#/hunt';
      const query = `_id:"${alert.id}"`;
      return `#/hunt?q=${encodeURIComponent(query)}`;
    },
    
    getHuntUrlForQuestion(question) {
      if (!question || !question.filledOQL) return '#/hunt';
      // Use the OQL query for hunting
      return `#/hunt?q=${encodeURIComponent(question.filledOQL)}`;
    },
    
    async convertPlaybookQueries(playbooks) {
      const queries = playbooks.map(pb => pb.questions.map(q => q.filledQuery)).flat();
      
      if (queries.length === 0) return;
      
      try {
        const response = await this.$root.papi.post('playbook/convert', queries);
        if (!response || !response.data) {
          console.error('Invalid response from playbook/convert API');
          return;
        }
        
        let index = 0;
        for (let pb of playbooks) {
          for (let question of pb.questions) {
            if (response.data[index]) {
              question.filledOQL = response.data[index].query;
              question.fields = response.data[index].fields;
            } else {
              question.filledOQL = '';
              question.fields = [];
            }
            index++;
          }
        }
      } catch (error) {
        console.error('Error converting playbook queries:', error);
        // Set default values
        for (let pb of playbooks) {
          for (let question of pb.questions) {
            question.filledOQL = question.filledQuery || '';
            question.fields = [];
          }
        }
      }
    },
    
    async executePlaybookQueries(playbooks, event) {
      for (let pb of playbooks) {
        for (let question of pb.questions) {
          await this.askQuestion(question, event);
        }
      }
      
      // Sort questions by results
      let good = [];  // has answers
      let bad = [];   // no answers  
      let ugly = [];  // error
      
      for (let pb of playbooks) {
        for (let q of pb.questions) {
          if (q.error) {
            ugly.push(q);
          } else if (q.answers && q.answers.length > 0) {
            good.push(q);
          } else {
            bad.push(q);
          }
        }
      }
      
      // Replace questions with sorted array
      if (playbooks.length > 0) {
        playbooks[0].sortedQuestions = [...good, ...bad, ...ugly];
        playbooks[0].hasResults = good.length > 0;
        
        // Auto-expand questions with results
        this.expandedQuestions = [];
        for (let i = 0; i < good.length; i++) {
          this.expandedQuestions.push(i);
        }
      }
    },
    
    async askQuestion(question, event) {
      if (question.range) {
        // Query with a time range
        if (question.filledOQL) {
          try {
            const dateRange = this.buildQuestionRange(event, question.range);
            let query = question.filledOQL;
            
            // Check if aggregate query
            const isAggregate = query.includes('| groupby') || query.includes('| metrics');
            if (!isAggregate) {
              query = query + ' | sortby @timestamp';
            }
            
            const response = await this.$root.papi.get('events/', {
              params: {
                query: query,
                range: dateRange,
                format: '2006/01/02 3:04:05 PM',
                zone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                metricLimit: 5,
                eventLimit: 5
              }
            });
            
            if (isAggregate && response.data.metrics) {
              // Handle aggregate results
              let biggest = '';
              for (let field in response.data.metrics) {
                if (field.length > biggest.length) biggest = field;
              }
              if (biggest) {
                question.answers = this.sortAggregateEvents(response.data.metrics[biggest]);
              } else {
                question.answers = response.data.events || [];
              }
            } else {
              question.answers = response.data.events || [];
            }
          } catch (e) {
            console.error('Failed to execute playbook query:', e);
            question.error = true;
            question.answers = [];
            question.errorMessage = e.response?.data?.error || e.message;
          }
        } else {
          question.error = true;
          question.answers = [];
          question.errorMessage = 'Query conversion failed';
        }
      } else {
        // No range - answer is in the event itself
        const dupe = JSON.parse(JSON.stringify(event.payload || {}));
        question.answers = [{ payload: dupe }];
      }
    },
    
    buildQuestionRange(event, range) {
      if (!range) return '';
      
      // Get event timestamp
      const timestamp = event.timestamp;
      if (!timestamp) return '';
      
      const t = new Date(timestamp);
      
      let plusMinus = false;
      let lookingBack = false;
      
      if (range.startsWith('+/-')) {
        plusMinus = true;
        range = range.substring(3);
      } else if (range.startsWith('-')) {
        lookingBack = true;
        range = range.substring(1);
      }
      
      const unit = range[range.length - 1].toLowerCase();
      range = range.substring(0, range.length - 1);
      
      const value = parseInt(range);
      if (isNaN(value)) return '';
      
      const unitMap = { d: 'days', h: 'hours', m: 'minutes', s: 'seconds' };
      const unitName = unitMap[unit];
      if (!unitName) return '';
      
      // Calculate date range
      let startDate, endDate;
      const msMap = {
        days: 24 * 60 * 60 * 1000,
        hours: 60 * 60 * 1000,
        minutes: 60 * 1000,
        seconds: 1000
      };
      
      const ms = value * msMap[unitName];
      
      if (plusMinus) {
        startDate = new Date(t.getTime() - ms);
        endDate = new Date(t.getTime() + ms);
      } else if (lookingBack) {
        startDate = new Date(t.getTime() - ms);
        endDate = t;
      } else {
        startDate = t;
        endDate = new Date(t.getTime() + ms);
      }
      
      // Format dates
      const format = (date) => {
        const year = date.getFullYear();
        const month = String(date.getMonth() + 1).padStart(2, '0');
        const day = String(date.getDate()).padStart(2, '0');
        let hours = date.getHours();
        const minutes = String(date.getMinutes()).padStart(2, '0');
        const seconds = String(date.getSeconds()).padStart(2, '0');
        const ampm = hours >= 12 ? 'PM' : 'AM';
        hours = hours % 12 || 12;
        
        return `${year}/${month}/${day} ${hours}:${minutes}:${seconds} ${ampm}`;
      };
      
      return `${format(startDate)} - ${format(endDate)}`;
    },
    
    sortAggregateEvents(events) {
      events = events.sort((a, b) => b.value - a.value);
      if (events.length > 5) {
        events = events.slice(0, 5);
      }
      return events;
    },
    
    getQuestionColor(question) {
      if (question.error) return 'error';
      if (question.answers && question.answers.length > 0) return 'success';
      return 'default';
    },
    
    async copyAlertId() {
      if (!this.selectedAlertDetails) return;
      
      try {
        await navigator.clipboard.writeText(this.selectedAlertDetails.id);
        this.$root.showTip('Alert ID copied to clipboard');
      } catch (error) {
        this.$root.showError('Failed to copy Alert ID');
      }
    },
    
    async copyRawData() {
      if (!this.selectedAlertDetails || !this.selectedAlertDetails.rawData) return;
      
      try {
        const jsonStr = JSON.stringify(this.selectedAlertDetails.rawData, null, 2);
        await navigator.clipboard.writeText(jsonStr);
        this.$root.showTip('Raw data copied to clipboard');
      } catch (error) {
        this.$root.showError('Failed to copy raw data');
      }
    },
    
    toggleGrouping() {
      this.groupAlerts = !this.groupAlerts;
      if (this.groupAlerts) {
        // Reset expanded states
        this.expandedGroups = [];
        this.expandedSubGroups = {};
      }
      // Reload alerts with appropriate limit based on grouping state
      this.loadAlerts();
    },
    
    toggleGroup(index) {
      const idx = this.expandedGroups.indexOf(index);
      if (idx > -1) {
        this.expandedGroups.splice(idx, 1);
      } else {
        this.expandedGroups.push(index);
      }
    },
    
    isGroupExpanded(index) {
      return this.expandedGroups.includes(index);
    },
    
    toggleSubGroup(groupKey, subGroupKey) {
      if (!this.expandedSubGroups[groupKey]) {
        this.$set(this.expandedSubGroups, groupKey, []);
      }
      const idx = this.expandedSubGroups[groupKey].indexOf(subGroupKey);
      if (idx > -1) {
        this.expandedSubGroups[groupKey].splice(idx, 1);
        // Clean up load more state when collapsing
        if (this.subGroupLoadMore[subGroupKey]) {
          delete this.subGroupLoadMore[subGroupKey];
        }
      } else {
        this.expandedSubGroups[groupKey].push(subGroupKey);
      }
    },
    
    getDisplayedAlerts(subGroup) {
      // Sort alerts by timestamp (most recent first) for better visibility
      const sortedAlerts = [...subGroup.alerts].sort((a, b) => {
        return new Date(b.timestamp) - new Date(a.timestamp);
      });
      
      // Return limited alerts for display unless "load more" is active
      const showAll = this.subGroupLoadMore[subGroup.key];
      if (showAll || sortedAlerts.length <= this.subGroupDisplayLimit) {
        return sortedAlerts;
      }
      return sortedAlerts.slice(0, this.subGroupDisplayLimit);
    },
    
    toggleLoadMore(subGroup) {
      if (this.subGroupLoadMore[subGroup.key]) {
        // Collapse back to limited view
        this.$delete(this.subGroupLoadMore, subGroup.key);
      } else {
        // Show all alerts
        this.$set(this.subGroupLoadMore, subGroup.key, true);
      }
    },
    
    shouldShowLoadMore(subGroup) {
      return subGroup.alerts.length > this.subGroupDisplayLimit;
    },
    
    getLoadMoreText(subGroup) {
      const isExpanded = this.subGroupLoadMore[subGroup.key];
      const remaining = subGroup.alerts.length - this.subGroupDisplayLimit;
      if (isExpanded) {
        return `Show less (collapse to ${this.subGroupDisplayLimit})`;
      }
      return `Load ${remaining} more alerts`;
    },
    
    isSubGroupExpanded(groupKey, subGroupKey) {
      return this.expandedSubGroups[groupKey] && this.expandedSubGroups[groupKey].includes(subGroupKey);
    },
    
    getGroupSummary(group) {
      // Get unique source/destination combinations count
      const uniqueCombos = new Set();
      group.alerts.forEach(alert => {
        if (alert.sourceIp && alert.destIp) {
          uniqueCombos.add(`${alert.sourceIp}->${alert.destIp}`);
        }
      });
      
      if (uniqueCombos.size > 0) {
        return `${group.count} event${group.count > 1 ? 's' : ''} across ${uniqueCombos.size} unique connection${uniqueCombos.size > 1 ? 's' : ''}`;
      }
      return `${group.count} event${group.count > 1 ? 's' : ''}`;
    },
    
    async requestPcap() {
      if (!this.selectedAlertDetails || !this.selectedAlertDetails.sourceIp || !this.selectedAlertDetails.destIp) {
        this.$root.showError('Cannot request PCAP: Missing network information');
        return;
      }
      
      this.pcapLoading = true;
      this.pcapError = null;
      this.pcapData = null;
      
      try {
        // Parse timestamp and create time window
        const alertTime = new Date(this.selectedAlertDetails.timestamp);
        const beginTime = new Date(alertTime.getTime() - 30000); // 30 seconds before
        const endTime = new Date(alertTime.getTime() + 30000); // 30 seconds after
        
        // Build PCAP filter based on alert details
        const filter = {
          beginTime: beginTime.toISOString(),
          endTime: endTime.toISOString(),
          srcIp: this.selectedAlertDetails.sourceIp,
          dstIp: this.selectedAlertDetails.destIp
        };
        
        // Add ports if available
        if (this.selectedAlertDetails.sourcePort) {
          filter.srcPort = parseInt(this.selectedAlertDetails.sourcePort);
        }
        if (this.selectedAlertDetails.destPort) {
          filter.dstPort = parseInt(this.selectedAlertDetails.destPort);
        }
        
        // Build job request
        const jobRequest = {
          nodeId: this.selectedAlertDetails.rawData?.['observer.name'] || this.selectedAlertDetails.rawData?.['agent.name'] || '',
          filter: filter
        };
        
        console.log('Requesting PCAP job with params:', jobRequest);
        
        // Request PCAP job
        const response = await this.$root.papi.post('job/', jobRequest);
        
        if (response && response.data && response.data.id) {
          this.pcapJobId = response.data.id;
          this.pcapJobStatus = 0; // JobStatusPending
          
          // Start monitoring the job
          this.monitorPcapJob();
        } else {
          throw new Error('Failed to create PCAP job');
        }
      } catch (error) {
        console.error('PCAP request failed:', error);
        this.pcapError = error.message || 'Failed to request PCAP';
        this.pcapLoading = false;
        this.$root.showError('Failed to request PCAP: ' + this.pcapError);
      }
    },
    
    async monitorPcapJob() {
      if (!this.pcapJobId) return;
      
      // Clear any existing interval
      if (this.pcapMonitorInterval) {
        clearInterval(this.pcapMonitorInterval);
      }
      
      // Check job status every 2 seconds
      this.pcapMonitorInterval = setInterval(async () => {
        try {
          const response = await this.$root.papi.get(`job/${this.pcapJobId}`);
          
          if (response && response.data) {
            const job = response.data;
            this.pcapJobStatus = job.status;
            
            // Check if job is complete (status = 1 = JobStatusCompleted)
            if (job.status === 1) {
              clearInterval(this.pcapMonitorInterval);
              this.pcapMonitorInterval = null;
              this.pcapLoading = false;
              
              // Store PCAP data
              this.pcapData = {
                id: this.pcapJobId,
                bytes: job.completedBytes || 0,
                sensor: job.nodeId,
                filter: job.filter,
                downloadUrl: this.$root.apiUrl + `stream?jobId=${this.pcapJobId}&ext=pcap`
              };
              
              // Load packet details
              this.loadPcapPackets();
              
              this.$root.showTip('PCAP capture completed');
            } else if (job.status === 2 || job.status === 3) {
              // JobStatusIncomplete = 2, JobStatusDeleted = 3
              clearInterval(this.pcapMonitorInterval);
              this.pcapMonitorInterval = null;
              this.pcapLoading = false;
              
              // Check for common error messages
              let errorMessage = job.failure || 'PCAP job failed';
              if (errorMessage.includes('No data available')) {
                errorMessage = 'PCAP data is no longer available (may have rolled off due to retention policy)';
              }
              
              this.pcapError = errorMessage;
              this.$root.showError('PCAP capture failed: ' + this.pcapError);
            }
          }
        } catch (error) {
          console.error('Failed to check PCAP job status:', error);
          // Continue monitoring unless it's a 404
          if (error.response && error.response.status === 404) {
            clearInterval(this.pcapMonitorInterval);
            this.pcapMonitorInterval = null;
            this.pcapLoading = false;
            this.pcapError = 'PCAP job not found';
          }
        }
      }, 2000);
    },
    
    downloadPcap() {
      if (!this.pcapData || !this.pcapData.downloadUrl) return;
      
      // Create a download link
      const link = document.createElement('a');
      link.href = this.pcapData.downloadUrl;
      link.download = `alert_${this.selectedAlertDetails.id}_${Date.now()}.pcap`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    },
    
    clearPcapData() {
      // Clear PCAP state when dialog closes
      if (this.pcapMonitorInterval) {
        clearInterval(this.pcapMonitorInterval);
      }
      this.pcapJobId = null;
      this.pcapJobStatus = null;
      this.pcapData = null;
      this.pcapError = null;
      this.pcapLoading = false;
      this.pcapPackets = [];
      this.pcapPacketsLoading = false;
      this.expandedPackets = [];
    },
    
    downloadPcap() {
      if (this.pcapData && this.pcapData.downloadUrl) {
        window.open(this.pcapData.downloadUrl, '_blank');
      }
    },
    
    async loadPcapPackets() {
      if (!this.pcapJobId) return;
      
      console.log('Loading PCAP packets for job:', this.pcapJobId);
      this.pcapPacketsLoading = true;
      try {
        const response = await this.$root.papi.get('packets', {
          params: {
            jobId: this.pcapJobId,
            offset: this.pcapPackets.length,
            count: 100,
            unwrap: false
          }
        });
        
        console.log('PCAP packets response:', response);
        
        if (response && response.data && response.data.length > 0) {
          // Prepare IPs for batch lookup
          const batch = [];
          for (let i = 0; i < response.data.length; i++) {
            const pkt = response.data[i];
            batch.push(pkt.dstIp);
            batch.push(pkt.srcIp);
          }
          
          this.pcapPackets = this.pcapPackets.concat(response.data);
          console.log('Loaded', response.data.length, 'packets. Total:', this.pcapPackets.length);
          this.$root.batchLookup(batch, this);
        } else {
          console.log('No packets in response');
        }
      } catch (error) {
        console.error('Failed to load PCAP packets:', error);
        // Silently fail if packets can't be loaded
      }
      this.pcapPacketsLoading = false;
    },
    
    formatPacketTimestamp(timestamp) {
      if (!timestamp) return '';
      const date = new Date(timestamp);
      return date.toLocaleString();
    },
    
    getPacketTypeColor(type) {
      if (!type) return '';
      if (type.startsWith("ICMP")) return "cyan";
      if (type.startsWith("DHCP")) return "teal-lighten-2";
      if (type.startsWith("ARP")) return "secondary";
      if (type.startsWith("DNS")) return "accent";
      if (type.startsWith("TCP")) return "primary";
      if (type.startsWith("UDP")) return "success";
      return "";
    },
    
    getPacketFlagColor(flag) {
      if (flag === "SYN") return "success";
      if (flag === "PSH") return "primary";
      if (flag === "RST") return "error";
      if (flag === "FIN") return "warning";
      if (flag === "VXLAN") return "accent";
      return "";
    },
    
    togglePacket(packetNumber) {
      const index = this.expandedPackets.indexOf(packetNumber);
      if (index > -1) {
        this.expandedPackets.splice(index, 1);
      } else {
        this.expandedPackets.push(packetNumber);
      }
    },
    
    isPacketExpanded(packetNumber) {
      return this.expandedPackets.includes(packetNumber);
    },
    
    formatPacketPayload(packet) {
      if (!packet.payload) return 'No payload data';
      
      try {
        const bytes = atob(packet.payload);
        // Show as hex view
        return this.formatHexView(bytes);
      } catch (e) {
        return 'Error decoding payload';
      }
    },
    
    formatHexView(bytes) {
      let hex = '';
      let ascii = '';
      let result = '';
      
      for (let i = 0; i < bytes.length; i++) {
        const byte = bytes.charCodeAt(i);
        hex += byte.toString(16).padStart(2, '0') + ' ';
        ascii += (byte >= 32 && byte <= 126) ? bytes.charAt(i) : '.';
        
        if ((i + 1) % 16 === 0 || i === bytes.length - 1) {
          // Pad hex to align ASCII
          while (hex.length < 48) {
            hex += '   ';
          }
          result += hex + ' |' + ascii + '|\n';
          hex = '';
          ascii = '';
        }
      }
      
      return result;
    },
    
    // Selection methods
    toggleSelectionMode() {
      this.selectionMode = !this.selectionMode;
      if (!this.selectionMode) {
        this.clearSelection();
      }
    },
    
    clearSelection() {
      this.selectedAlerts.clear();
      this.selectedSubGroups.clear();
      this.selectedGroups.clear();
      this.$forceUpdate();
    },
    
    selectAll() {
      if (this.groupAlerts) {
        // Select all groups
        this.alertGroups.forEach(group => {
          this.selectedGroups.add(group.key);
        });
      } else {
        // Select all visible alerts
        this.alerts.forEach(alert => {
          this.selectedAlerts.add(alert.id);
        });
      }
      this.$forceUpdate();
    },
    
    toggleGroupSelection(group) {
      if (this.selectedGroups.has(group.key)) {
        this.selectedGroups.delete(group.key);
        // Also deselect all subgroups and alerts in this group
        const subGroups = this.getSubGroups(group);
        subGroups.forEach(subGroup => {
          this.selectedSubGroups.delete(subGroup.key);
          subGroup.alerts.forEach(alert => {
            this.selectedAlerts.delete(alert.id);
          });
        });
      } else {
        this.selectedGroups.add(group.key);
      }
      this.$forceUpdate();
    },
    
    toggleSubGroupSelection(subGroup) {
      const key = subGroup.key;
      if (this.selectedSubGroups.has(key)) {
        this.selectedSubGroups.delete(key);
        // Also deselect all alerts in this subgroup
        subGroup.alerts.forEach(alert => {
          this.selectedAlerts.delete(alert.id);
        });
      } else {
        this.selectedSubGroups.add(key);
      }
      this.$forceUpdate();
    },
    
    toggleAlertSelection(alert) {
      if (this.selectedAlerts.has(alert.id)) {
        this.selectedAlerts.delete(alert.id);
      } else {
        this.selectedAlerts.add(alert.id);
      }
      this.$forceUpdate();
    },
    
    isGroupSelected(group) {
      return this.selectedGroups.has(group.key);
    },
    
    isSubGroupSelected(subGroup) {
      return this.selectedSubGroups.has(subGroup.key);
    },
    
    isAlertSelected(alertId) {
      // Check if alert is individually selected
      if (this.selectedAlerts.has(alertId)) {
        return true;
      }
      
      // Check if alert's subgroup or group is selected
      const alert = this.alerts.find(a => a.id === alertId);
      if (!alert) return false;
      
      // Check if parent group is selected
      if (this.selectedGroups.has(alert.ruleName)) {
        return true;
      }
      
      // Check if parent subgroup is selected
      const subGroupKey = `${alert.sourceIp || 'unknown'} → ${alert.destIp || 'unknown'}`;
      if (this.selectedSubGroups.has(subGroupKey)) {
        return true;
      }
      
      return false;
    },
    
    getSelectedAlertIds() {
      const alertIds = new Set(this.selectedAlerts);
      
      // Add alerts from selected subgroups
      this.alertGroups.forEach(group => {
        const subGroups = this.getSubGroups(group);
        subGroups.forEach(subGroup => {
          if (this.selectedSubGroups.has(subGroup.key)) {
            subGroup.alerts.forEach(alert => {
              alertIds.add(alert.id);
            });
          }
        });
      });
      
      // Add alerts from selected groups
      this.selectedGroups.forEach(groupKey => {
        const group = this.alertGroups.find(g => g.key === groupKey);
        if (group) {
          group.alerts.forEach(alert => {
            alertIds.add(alert.id);
          });
        }
      });
      
      return Array.from(alertIds);
    },
    
    async bulkAcknowledge() {
      const alertIds = this.getSelectedAlertIds();
      if (alertIds.length === 0) return;
      
      this.actionLoading = true;
      try {
        // Use bulk API for all alerts at once
        await this.updateAlertStatuses(alertIds, 'acknowledged');
        
        this.$root.showTip(`${alertIds.length} alert${alertIds.length > 1 ? 's' : ''} acknowledged`);
        this.clearSelection();
        await this.loadAlerts();
      } catch (error) {
        this.$root.showError(error);
      } finally {
        this.actionLoading = false;
      }
    },
    
    async bulkEscalate() {
      const alertIds = this.getSelectedAlertIds();
      if (alertIds.length === 0) return;
      
      // Show escalate dialog for bulk operation
      this.selectedAlert = { id: 'bulk', ruleName: `${alertIds.length} alerts` };
      this.actionType = 'escalate-bulk';
      this.actionTitle = `Escalate ${alertIds.length} Alerts to Case`;
      this.caseTitle = `Bulk Escalation: ${alertIds.length} alerts`;
      this.caseDescription = `Escalating ${alertIds.length} related alerts`;
      this.actionDialog = true;
    },
    
    
    async acknowledgeGroup(group) {
      // Show confirmation dialog
      this.selectedAlert = { 
        id: 'group-' + group.key, 
        ruleName: group.ruleName
      };
      this.selectedGroup = group;
      this.actionType = 'acknowledge-group';
      this.actionTitle = `Acknowledge ${group.count} Alerts`;
      this.caseTitle = ''; // Not needed for acknowledge
      this.caseDescription = `Acknowledge all ${group.count} alerts for "${group.ruleName}"?`;
      this.actionDialog = true;
    },
    
    async escalateGroup(group) {
      // Set up for escalation
      this.selectedAlert = { 
        id: 'group-' + group.key, 
        ruleName: group.ruleName,
        severityLabel: group.severityLabel 
      };
      this.actionType = 'escalate-group';
      this.actionTitle = `Escalate ${group.count} Alerts to Case`;
      this.caseTitle = `${group.ruleName} - ${group.count} alerts`;
      this.caseDescription = `Escalating ${group.count} alerts for rule: ${group.ruleName}`;
      
      // Store the group for later use in confirmAction
      this.selectedGroup = group;
      
      this.actionDialog = true;
    },
    
    async acknowledgeSubGroup(group, subGroup) {
      // Show confirmation dialog
      this.selectedAlert = { 
        id: 'subgroup-' + subGroup.key, 
        ruleName: group.ruleName
      };
      this.selectedGroup = group;
      this.selectedSubGroup = subGroup;
      this.actionType = 'acknowledge-subgroup';
      this.actionTitle = `Acknowledge ${subGroup.count} Alerts`;
      this.caseTitle = ''; // Not needed for acknowledge
      this.caseDescription = `Acknowledge all ${subGroup.count} "${group.ruleName}" alerts for ${subGroup.sourceIp} → ${subGroup.destIp}?`;
      this.actionDialog = true;
    },
    
    async escalateSubGroup(group, subGroup) {
      // Set up for escalation
      this.selectedAlert = { 
        id: 'subgroup-' + subGroup.key, 
        ruleName: group.ruleName,
        severityLabel: group.severityLabel 
      };
      this.actionType = 'escalate-subgroup';
      this.actionTitle = `Escalate ${subGroup.count} Alerts to Case`;
      this.caseTitle = `${group.ruleName}: ${subGroup.sourceIp} → ${subGroup.destIp}`;
      this.caseDescription = `Escalating ${subGroup.count} "${group.ruleName}" alerts for connection ${subGroup.sourceIp} → ${subGroup.destIp}`;
      
      // Store the subgroup for later use in confirmAction
      this.selectedSubGroup = subGroup;
      this.selectedGroup = group;
      
      this.actionDialog = true;
    },
    
    async suppressBySource(group, subGroup) {
      const sourceIp = subGroup.sourceIp;
      if (!sourceIp) {
        this.$root.showError('No source IP to suppress');
        return;
      }
      
      // Get the rule ID from the first alert
      const firstAlert = subGroup.alerts[0];
      if (!firstAlert || !firstAlert.ruleUuid) {
        this.$root.showError('Cannot suppress: Rule ID not found');
        return;
      }
      
      const ruleId = firstAlert.ruleUuid;
      const ruleName = group.ruleName;
      
      if (!confirm(`Create a suppression for rule "${ruleName}" from source IP ${sourceIp}?\n\nThis will prevent alerts from this source IP for this specific rule.`)) {
        return;
      }
      
      this.$set(this.suppressLoading, subGroup.key, true);
      
      try {
        // Create a tuning/suppression for this rule and source IP
        const suppressionData = {
          ruleId: ruleId,
          type: 'suppress',
          conditions: {
            sourceIp: sourceIp
          },
          comment: `Suppression created from Simple Alerts view on ${new Date().toISOString()}`
        };
        
        await this.$root.papi.post('detection/tuning', suppressionData);
        
        this.$root.showTip(`Suppression created for "${ruleName}" from source ${sourceIp}`);
        await this.loadAlerts();
      } catch (error) {
        console.error('Failed to create suppression:', error);
        this.$root.showError(`Failed to create suppression: ${error.message || 'Unknown error'}`);
      } finally {
        this.$delete(this.suppressLoading, subGroup.key);
      }
    },
    
    async suppressByDest(group, subGroup) {
      const destIp = subGroup.destIp;
      if (!destIp) {
        this.$root.showError('No destination IP to suppress');
        return;
      }
      
      // Get the rule ID from the first alert
      const firstAlert = subGroup.alerts[0];
      if (!firstAlert || !firstAlert.ruleUuid) {
        this.$root.showError('Cannot suppress: Rule ID not found');
        return;
      }
      
      const ruleId = firstAlert.ruleUuid;
      const ruleName = group.ruleName;
      
      if (!confirm(`Create a suppression for rule "${ruleName}" to destination IP ${destIp}?\n\nThis will prevent alerts to this destination IP for this specific rule.`)) {
        return;
      }
      
      this.$set(this.suppressLoading, subGroup.key, true);
      
      try {
        // Create a tuning/suppression for this rule and destination IP
        const suppressionData = {
          ruleId: ruleId,
          type: 'suppress',
          conditions: {
            destIp: destIp
          },
          comment: `Suppression created from Simple Alerts view on ${new Date().toISOString()}`
        };
        
        await this.$root.papi.post('detection/tuning', suppressionData);
        
        this.$root.showTip(`Suppression created for "${ruleName}" to destination ${destIp}`);
        await this.loadAlerts();
      } catch (error) {
        console.error('Failed to create suppression:', error);
        this.$root.showError(`Failed to create suppression: ${error.message || 'Unknown error'}`);
      } finally {
        this.$delete(this.suppressLoading, subGroup.key);
      }
    },
    
    tuneRuleForPair(group, subGroup) {
      // Get the rule UUID/PublicId from the first alert
      const firstAlert = subGroup.alerts[0];
      if (!firstAlert || !firstAlert.ruleUuid) {
        this.$root.showError('Cannot tune rule: Rule ID not found');
        return;
      }
      
      const ruleId = firstAlert.ruleUuid;
      
      // Navigate to detections page with the rule ID and pre-filled source/dest for tuning
      this.$router.push({
        name: 'detections',
        query: {
          action: 'tune',
          publicId: ruleId,
          sourceIp: subGroup.sourceIp,
          destIp: subGroup.destIp
        }
      });
    },
    
    tuneRule(group) {
      // Get the rule UUID/PublicId from the first alert in the group
      const firstAlert = group.alerts[0];
      if (!firstAlert || !firstAlert.ruleUuid) {
        this.$root.showError('Cannot tune rule: Rule ID not found');
        return;
      }
      
      const ruleId = firstAlert.ruleUuid;
      
      // Navigate to detections page with the rule ID to tune it
      // This will open the tuning interface for this specific rule
      this.$router.push({
        name: 'detections',
        query: {
          action: 'tune',
          publicId: ruleId
        }
      });
    },
    
    viewInDetections(group) {
      // Get the rule UUID/PublicId from the first alert in the group
      const firstAlert = group.alerts[0];
      if (!firstAlert || !firstAlert.ruleUuid) {
        this.$root.showError('Cannot view rule: Rule ID not found');
        return;
      }
      
      const ruleId = firstAlert.ruleUuid;
      
      // Navigate to detections page filtered to show this specific rule
      this.$router.push({
        name: 'detections',
        query: {
          search: ruleId
        }
      });
    },
    
    async disableRule(group) {
      // Get the rule UUID/PublicId from the first alert in the group
      const firstAlert = group.alerts[0];
      if (!firstAlert || !firstAlert.ruleUuid) {
        this.$root.showError('Cannot disable rule: Rule ID not found');
        return;
      }
      
      const ruleId = firstAlert.ruleUuid;
      const ruleName = group.ruleName;
      
      // Confirm with user
      if (!confirm(`Are you sure you want to disable the rule "${ruleName}"?\n\nThis will prevent new alerts from being generated for this rule. Existing alerts will remain.\n\nRule ID: ${ruleId}`)) {
        return;
      }
      
      // Track loading state
      this.$set(this.disablingRules, group.key, true);
      
      try {
        // Call the detection API to disable the rule
        // The API expects the public ID (for Suricata, this is the SID)
        const response = await this.$root.papi.put(`detection/public/${ruleId}`, {
          isEnabled: false,
          // Optional: Add a comment about why it was disabled
          comment: `Disabled from Simple Alerts view on ${new Date().toISOString()}`
        });
        
        if (response && response.data) {
          this.$root.showTip(`Rule "${ruleName}" has been disabled successfully`);
          
          // Optionally refresh the alerts to reflect the change
          // Though existing alerts will remain, this might update any UI state
          await this.loadAlerts();
        } else {
          throw new Error('Failed to disable rule - no response from server');
        }
      } catch (error) {
        console.error('Failed to disable rule:', error);
        
        // Check if it's a 404 (rule not found in detections)
        if (error.response && error.response.status === 404) {
          this.$root.showError(`Cannot disable rule: Detection rule not found in the system (ID: ${ruleId})`);
        } else if (error.response && error.response.status === 403) {
          this.$root.showError('Permission denied: You do not have permission to disable detection rules');
        } else {
          this.$root.showError(`Failed to disable rule: ${error.message || 'Unknown error'}`);
        }
      } finally {
        // Clear loading state
        this.$delete(this.disablingRules, group.key);
      }
    },
    
    getSubGroups(group) {
      // Sub-group alerts by source and destination IPs (ignoring ports)
      const subGroups = new Map();
      
      group.alerts.forEach(alert => {
        // Only create subgroups if there are IPs to group by
        if (alert.sourceIp || alert.destIp) {
          const subKey = `${alert.sourceIp || 'unknown'} → ${alert.destIp || 'unknown'}`;
          
          if (!subGroups.has(subKey)) {
            subGroups.set(subKey, {
              key: subKey,
              sourceIp: alert.sourceIp,
              destIp: alert.destIp,
              alerts: [],
              count: 0,
              ports: new Set(), // Track unique port combinations
              firstSeen: alert.timestamp,
              lastSeen: alert.timestamp
            });
          }
          
          const subGroup = subGroups.get(subKey);
          subGroup.alerts.push(alert);
          subGroup.count++;
          
          // Update timestamps
          if (alert.timestamp < subGroup.firstSeen) {
            subGroup.firstSeen = alert.timestamp;
          }
          if (alert.timestamp > subGroup.lastSeen) {
            subGroup.lastSeen = alert.timestamp;
          }
          
          // Track unique port combinations
          if (alert.sourcePort || alert.destPort) {
            subGroup.ports.add(`${alert.sourcePort || '*'}:${alert.destPort || '*'}`);
          }
        } else {
          // For alerts without IPs, create a single "no network data" group
          const subKey = 'no-network-data';
          
          if (!subGroups.has(subKey)) {
            subGroups.set(subKey, {
              key: subKey,
              sourceIp: null,
              destIp: null,
              alerts: [],
              count: 0,
              firstSeen: alert.timestamp,
              lastSeen: alert.timestamp
            });
          }
          
          const subGroup = subGroups.get(subKey);
          subGroup.alerts.push(alert);
          subGroup.count++;
          
          // Update timestamps
          if (alert.timestamp < subGroup.firstSeen) {
            subGroup.firstSeen = alert.timestamp;
          }
          if (alert.timestamp > subGroup.lastSeen) {
            subGroup.lastSeen = alert.timestamp;
          }
        }
      });
      
      // Convert to array and sort by count
      const groups = Array.from(subGroups.values()).sort((a, b) => b.count - a.count);
      
      // Convert ports Set to array for display
      groups.forEach(g => {
        if (g.ports) {
          g.uniquePorts = Array.from(g.ports);
        }
      });
      
      return groups;
    }
  }
};

// Register the simple-alerts route only - leave the existing alerts route as is
routes.push({ path: '/simple-alerts', name: 'simple-alerts', component: simpleAlertsComponent });