// Copyright 2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

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
      caseTitle: '',
      caseDescription: '',
      
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
    }
  },
  mounted() {
    this.loadAlerts();
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
        
        const params = new URLSearchParams({
          query: query,
          range: dateRange,
          format: '2006/01/02 3:04:05 PM',
          zone: Intl.DateTimeFormat().resolvedOptions().timeZone,
          metricLimit: '10',
          eventLimit: this.eventLimit.toString(),
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
        dismissed: event.payload['event.dismissed'] || false
      }));
    },
    
    getSeverityLevel(alert) {
      const label = (alert.severityLabel || '').toLowerCase();
      if (label.includes('high') || label.includes('critical')) return 'high';
      if (label.includes('medium')) return 'medium';
      return 'low';
    },
    
    acknowledgeAlert(alert) {
      this.selectedAlert = alert;
      this.actionType = 'acknowledge';
      this.actionTitle = 'Acknowledge Alert';
      this.actionDialog = true;
    },
    
    escalateAlert(alert) {
      this.selectedAlert = alert;
      this.actionType = 'escalate';
      this.actionTitle = 'Escalate to Case';
      this.caseTitle = `Alert: ${alert.ruleName}`;
      this.caseDescription = `Alert from ${alert.sourceIp} to ${alert.destIp}`;
      this.actionDialog = true;
    },
    
    dismissAlert(alert) {
      this.selectedAlert = alert;
      this.actionType = 'dismiss';
      this.actionTitle = 'Dismiss Alert';
      this.actionDialog = true;
    },
    
    async confirmAction() {
      if (!this.selectedAlert) return;
      
      this.actionLoading = true;
      
      try {
        if (this.actionType === 'escalate') {
          // Create a case
          const caseData = {
            title: this.caseTitle,
            description: this.caseDescription,
            severity: this.selectedAlert.severityLabel,
            status: 'new',
            events: [this.selectedAlert.id]
          };
          
          await this.$root.papi.post('case', caseData);
          
          // Update alert status
          await this.updateAlertStatus(this.selectedAlert.id, 'escalated');
        } else {
          // Update alert status
          await this.updateAlertStatus(this.selectedAlert.id, this.actionType === 'acknowledge' ? 'acknowledged' : 'dismissed');
        }
        
        // Refresh the list
        await this.loadAlerts();
        
        this.actionDialog = false;
        this.$root.showTip(`Alert ${this.actionType}d successfully`);
      } catch (error) {
        this.$root.showError(error);
      } finally {
        this.actionLoading = false;
      }
    },
    
    async updateAlertStatus(alertId, status) {
      await this.$root.papi.put(`events/${alertId}/status`, { status });
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
    }
  }
};

// Register the simple-alerts route only - leave the existing alerts route as is
routes.push({ path: '/simple-alerts', name: 'simple-alerts', component: simpleAlertsComponent });