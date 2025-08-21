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
      filterCategory: 'all',
      
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
      showDetailedRule: false,
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
      expandedGroupRules: {},  // Track expanded state of rule text
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
      
      // Sort options
      sortBy: 'count', // Default sort by count
      sortOptions: [
        { value: 'count', title: 'Alert Count' },
        { value: 'category', title: 'Category' },
        { value: 'severity', title: 'Severity' },
        { value: 'ruleName', title: 'Rule Name' },
        { value: 'timestamp', title: 'Most Recent' }
      ],
      
      // True counts from aggregation
      trueRuleCounts: {},
      
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
      categoryOptions: [],
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
        // Ungrouped view - return filtered alerts
        let filteredAlerts = this.alerts;
        if (this.filterCategory !== 'all') {
          filteredAlerts = this.alerts.filter(alert => 
            alert['rule.category'] === this.filterCategory
          );
        }
        return filteredAlerts;
      }
      
      // Grouped view - return the already processed alertGroups
      // (loaded via loadRuleAggregations)
      if (this.alertGroups && this.alertGroups.length > 0) {
        // Apply category filter to groups if needed
        if (this.filterCategory !== 'all') {
          return this.alertGroups.filter(group => 
            group['rule.category'] === this.filterCategory
          );
        }
        return this.alertGroups;
      }
      
      // Fallback: OLD processing logic (shouldn't be reached with new approach)
      const groups = new Map();
      let filteredAlerts = this.alerts;
      if (this.filterCategory !== 'all') {
        filteredAlerts = this.alerts.filter(alert => 
          alert['rule.category'] === this.filterCategory
        );
      }
      
      filteredAlerts.forEach(alert => {
        const groupKey = alert.ruleName;
        
        if (!groups.has(groupKey)) {
          groups.set(groupKey, {
            key: groupKey,
            ruleName: alert.ruleName,
            ruleText: alert.ruleText,
            module: alert.module,
            severityLabel: alert.severityLabel,
            category: alert.category,
            'rule.category': alert['rule.category'],
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
        group.loadedCount = group.count; // Track how many we actually loaded
        
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
      
      // Convert to array and apply true counts if available
      let groupArray = Array.from(groups.values());
      
      // Apply true counts from aggregation if available
      if (this.trueRuleCounts && Object.keys(this.trueRuleCounts).length > 0) {
        groupArray.forEach(group => {
          if (this.trueRuleCounts[group.ruleName]) {
            group.trueCount = this.trueRuleCounts[group.ruleName];
            // Update count to true count for sorting/display
            group.displayCount = group.trueCount;
            group.hasMore = group.trueCount > group.loadedCount;
          } else {
            group.displayCount = group.count;
            group.trueCount = group.count;
            group.hasMore = false;
          }
        });
      } else {
        // No true counts available, use loaded counts
        groupArray.forEach(group => {
          group.displayCount = group.count;
          group.trueCount = group.count;
          group.hasMore = this.totalAlerts > this.alerts.length; // Might have more
        });
      }
      
      // Filter out empty groups and sort based on selected option
      this.alertGroups = groupArray
        .filter(group => group.count > 0)  // Remove groups with no alerts
        .sort((a, b) => {
          switch (this.sortBy) {
            case 'category':
              // Sort by category alphabetically, then by count
              if (a['rule.category'] === b['rule.category']) {
                return b.displayCount - a.displayCount;
              }
              return (a['rule.category'] || '').localeCompare(b['rule.category'] || '');
            
            case 'severity':
              // Sort by severity (high > medium > low)
              const severityOrder = { 'high': 3, 'critical': 3, 'medium': 2, 'low': 1 };
              const aLevel = severityOrder[this.getSeverityLevel(a)] || 0;
              const bLevel = severityOrder[this.getSeverityLevel(b)] || 0;
              if (aLevel === bLevel) {
                return b.displayCount - a.displayCount;
              }
              return bLevel - aLevel;
            
            case 'ruleName':
              // Sort by rule name alphabetically
              return a.ruleName.localeCompare(b.ruleName);
            
            case 'timestamp':
              // Sort by most recent activity
              return new Date(b.lastSeen) - new Date(a.lastSeen);
            
            case 'count':
            default:
              // Sort by count (default)
              return b.displayCount - a.displayCount;
          }
        });
      
      return this.alertGroups;
    }
  },
  mounted() {
    console.log('SimpleAlerts component mounted, loading alerts...');
    this.loadAlerts().then(() => {
      console.log('Initial load complete');
    }).catch(err => {
      console.error('Initial load failed:', err);
    });
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
        console.log('Group alerts enabled:', this.groupAlerts);
        
        if (this.groupAlerts) {
          // NEW APPROACH: Only load aggregated rule counts, no actual alerts yet
          await this.loadRuleAggregations(query, dateRange);
        } else {
          // Ungrouped view - load alerts directly as before
          await this.loadUngroupedAlerts(query, dateRange);
        }
        
        // Update statistics in parallel (don't wait for it)
        this.loadStatistics().catch(err => {
          console.error('Failed to load statistics:', err);
        });
        
      } catch (error) {
        console.error('Failed to load alerts:', error);
        this.$root.showError(error.message || 'Failed to load alerts');
      } finally {
        this.loading = false;
      }
    },
    
    async loadRuleAggregations(baseQuery, dateRange) {
      // TIER 1: For now, fallback to loading actual alerts and grouping them
      // until we figure out the correct aggregation syntax
      try {
        console.log('Loading alerts for grouping...');
        
        // Load a reasonable number of alerts to group
        const params = new URLSearchParams({
          query: baseQuery,
          range: dateRange,
          format: '2006/01/02 3:04:05 PM',
          zone: Intl.DateTimeFormat().resolvedOptions().timeZone,
          metricLimit: '10',
          eventLimit: '5000', // Load 5000 alerts for grouping
          view: 'simple'
        });
        
        const response = await this.$root.papi.get('events/?' + params.toString());
        
        if (response && response.data) {
          this.totalAlerts = response.data.totalEvents || 0;
          const events = response.data.events || [];
          
          console.log(`Processing ${events.length} events from ${this.totalAlerts} total`);
          
          // Process the events into groups
          const groups = new Map();
          
          events.forEach(event => {
            const data = event.payload || event;
            const ruleName = data['rule.name'] || 'Unknown Rule';
            
            if (!groups.has(ruleName)) {
              // Extract rule category
              let ruleCategory = '';
              const match = ruleName.match(/^(?:ET|GPL|SURICATA)\s+([A-Z_]+)/);
              if (match) {
                ruleCategory = match[1];
              }
              
              groups.set(ruleName, {
                key: ruleName,
                ruleName: ruleName,
                count: 0,
                trueCount: 0, // Will be updated if we have more than loaded
                displayCount: 0,
                severityLabel: data['event.severity_label'] || 'unknown',
                category: data['event.category'] || '',
                'rule.category': ruleCategory,
                module: data['event.module'] || '',
                ruleText: data['rule.rule'] || data['rule.text'] || '',
                ruleUuid: data['rule.uuid'],
                // Lazy loading states
                subGroupsLoaded: false,
                subGroups: [],
                alertsLoaded: false,
                alerts: [],
                firstSeen: event.timestamp,
                lastSeen: event.timestamp
              });
            }
            
            const group = groups.get(ruleName);
            group.count++;
            group.alerts.push(this.processAlerts([event])[0]); // Store some sample alerts
            
            // Update timestamps
            if (event.timestamp < group.firstSeen) {
              group.firstSeen = event.timestamp;
            }
            if (event.timestamp > group.lastSeen) {
              group.lastSeen = event.timestamp;
            }
            
            // Use highest severity
            const severity = data['event.severity_label'];
            if (severity === 'high' && group.severityLabel !== 'high') {
              group.severityLabel = severity;
            } else if (severity === 'medium' && group.severityLabel === 'low') {
              group.severityLabel = severity;
            }
          });
          
          // If we have more total alerts than loaded, estimate true counts
          if (this.totalAlerts > events.length) {
            const ratio = this.totalAlerts / events.length;
            groups.forEach(group => {
              group.trueCount = Math.ceil(group.count * ratio);
              group.displayCount = group.trueCount;
              group.hasMore = true;
            });
          } else {
            // We loaded everything
            groups.forEach(group => {
              group.trueCount = group.count;
              group.displayCount = group.count;
              group.hasMore = false;
            });
          }
          
          
          // Convert to array and sort
          this.alertGroups = Array.from(groups.values()).sort((a, b) => b.displayCount - a.displayCount);
          
          console.log(`Loaded ${this.alertGroups.length} rules with ${this.totalAlerts} total alerts`);
          console.log('First few groups:', this.alertGroups.slice(0, 3).map(g => ({
            rule: g.ruleName,
            count: g.count,
            displayCount: g.displayCount
          })));
          
          // Batch lookup hostnames if enabled
          if (this.$root.enableReverseLookup && events.length > 0) {
            const ips = new Set();
            events.forEach(event => {
              const data = event.payload || event;
              if (data['source.ip']) ips.add(data['source.ip']);
              if (data['destination.ip']) ips.add(data['destination.ip']);
            });
            if (ips.size > 0) {
              this.$root.batchLookup(Array.from(ips), this);
            }
          }
        }
      } catch (error) {
        console.error('Failed to load rule aggregations:', error);
        throw error;
      }
    },
    
    async loadUngroupedAlerts(query, dateRange) {
      // Original ungrouped loading logic
      const params = new URLSearchParams({
        query: query,
        range: dateRange,
        format: '2006/01/02 3:04:05 PM',
        zone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        metricLimit: '10',
        eventLimit: this.eventLimit.toString(),
        view: 'simple'
      });
      
      const response = await this.$root.papi.get('events/?' + params.toString());
      
      if (response && response.data) {
        this.alerts = this.processAlerts(response.data.events || []);
        this.totalAlerts = response.data.totalEvents || 0;
        this.hasMore = this.totalAlerts > this.alerts.length;
        
        // Batch lookup hostnames if reverse lookup is enabled
        if (this.$root.enableReverseLookup) {
          const ips = [];
          this.alerts.forEach(alert => {
            if (alert.sourceIp) ips.push(alert.sourceIp);
            if (alert.destIp) ips.push(alert.destIp);
          });
          if (ips.length > 0) {
            // Use the root app's batchLookup method
            this.$root.batchLookup(ips, this);
          }
        }
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
          
          // Batch lookup hostnames for new alerts if reverse lookup is enabled
          if (this.$root.enableReverseLookup) {
            const ips = [];
            newAlerts.forEach(alert => {
              if (alert.sourceIp) ips.push(alert.sourceIp);
              if (alert.destIp) ips.push(alert.destIp);
            });
            if (ips.length > 0) {
              // Use the root app's batchLookup method
              this.$root.batchLookup(ips, this);
            }
          }
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
      const categoriesSet = new Set();
      
      const processedAlerts = events.map(event => {
        // The API returns the event with fields at the root level, not in event.payload
        // Check if we have a payload object or if fields are at root level
        const data = event.payload || event;
        
        const ruleName = data['rule.name'] || 'Unknown Rule';
        
        // Extract category from rule name
        // Common patterns:
        // "ET MALWARE ..." -> "MALWARE"
        // "ET TROJAN ..." -> "TROJAN"  
        // "ET DNS ..." -> "DNS"
        // "ET POLICY ..." -> "POLICY"
        // "GPL ATTACK_RESPONSE ..." -> "ATTACK_RESPONSE"
        let ruleCategory = '';
        if (ruleName) {
          // Match patterns like "ET CATEGORY" or "GPL CATEGORY"
          const match = ruleName.match(/^(?:ET|GPL|SURICATA)\s+([A-Z_]+)/);
          if (match) {
            ruleCategory = match[1];
            categoriesSet.add(ruleCategory);
          }
        }
        const sourceIp = data['source.ip'];
        const destIp = data['destination.ip'];
        const module = data['event.module'];
        
        // Determine if this is a host-based alert
        const isHostBased = !sourceIp && !destIp;
        
        return {
          id: event.id,
          timestamp: event.timestamp,
          ruleName: ruleName,
          ruleUuid: data['rule.uuid'],
          ruleText: data['rule.rule'] || data['rule.text'] || '',
          severity: data['event.severity'],
          severityLabel: data['event.severity_label'] || 'unknown',
          sourceIp: sourceIp,
          sourcePort: data['source.port'],
          sourceGeo: null,  // Geo data not available in simple view
          destIp: destIp,
          destPort: data['destination.port'],
          destGeo: null,  // Geo data not available in simple view
          module: module,
          category: data['event.category'],
          'rule.category': ruleCategory,
          acknowledged: data['event.acknowledged'] || false,
          escalated: data['event.escalated'] || false,
          dismissed: data['event.dismissed'] || false,
          isHostBased: isHostBased,
          // Store raw data for accessing agent.name, host.name, etc
          rawData: data,
          // Store the entire payload for potential AI summary extraction
          payload: data
        };
      });
      
      // Update category options based on found categories
      const sortedCategories = Array.from(categoriesSet).sort();
      this.categoryOptions = [
        { value: 'all', title: 'All Categories' },
        ...sortedCategories.map(cat => ({ value: cat, title: cat }))
      ];
      
      return processedAlerts;
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
      
      // Create appropriate description based on alert type
      if (alert.isHostBased) {
        const agentName = alert.rawData?.['agent.name'] || alert.rawData?.['observer.name'] || 'Unknown Agent';
        const hostName = alert.rawData?.['host.name'] || '';
        this.caseDescription = hostName ? 
          `Host-based alert on ${hostName} (Agent: ${agentName})` : 
          `Host-based alert from Agent: ${agentName}`;
      } else {
        this.caseDescription = `Alert from ${alert.sourceIp || 'unknown'} to ${alert.destIp || 'unknown'}`;
      }
      
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
    
    updateSort(value) {
      this.sortBy = value;
      // No need to reload alerts, just re-sort the existing data
      // The computed property will handle the re-sorting automatically
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
      // Reset show rule state
      this.showDetailedRule = false;
      
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
          const fullData = fullEvent.payload || fullEvent;
          
          // Extract geo data from the full event
          const sourceGeo = {
            country: fullData['source.geo.country_name'],
            city: fullData['source.geo.city_name'],
            regionCode: fullData['source.geo.region_iso_code'],
            regionName: fullData['source.geo.region_name'],
            asOrg: fullData['source.as.organization.name']
          };
          
          const destGeo = {
            country: fullData['destination.geo.country_name'],
            city: fullData['destination.geo.city_name'],
            regionCode: fullData['destination.geo.region_iso_code'],
            regionName: fullData['destination.geo.region_name'],
            asOrg: fullData['destination.as.organization.name']
          };
          
          // Merge the full data with our simplified alert
          this.selectedAlertDetails = {
            ...alert,
            rawData: fullEvent.payload || {},
            ruleText: fullEvent.payload?.['rule.rule'] || fullEvent['rule.rule'] || alert.ruleText || '',
            sourceGeo: sourceGeo,
            destGeo: destGeo,
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
      
      // Create a time range around the alert (e.g., 1 hour before and after)
      const alertTime = new Date(alert.timestamp);
      const startTime = new Date(alertTime.getTime() - 60 * 60 * 1000); // 1 hour before
      const endTime = new Date(alertTime.getTime() + 60 * 60 * 1000);   // 1 hour after
      
      // Format dates for the hunt page (ISO format)
      const start = startTime.toISOString();
      const end = endTime.toISOString();
      
      // Search by alert ID
      const query = `_id:"${alert.id}"`;
      
      // Include time range in the URL
      return `#/hunt?q=${encodeURIComponent(query)}&start=${encodeURIComponent(start)}&end=${encodeURIComponent(end)}&t=custom`;
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
    
    toggleGroupRule(group) {
      if (this.expandedGroupRules[group.key]) {
        // Hide rule text
        this.$delete(this.expandedGroupRules, group.key);
      } else {
        // Show rule text
        this.$set(this.expandedGroupRules, group.key, true);
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
    
    isPrivateIP(ip) {
      if (!ip) return false;
      
      // Check for RFC1918 private addresses
      const parts = ip.split('.');
      if (parts.length !== 4) return false;
      
      const first = parseInt(parts[0]);
      const second = parseInt(parts[1]);
      
      // 10.0.0.0/8
      if (first === 10) return true;
      
      // 172.16.0.0/12
      if (first === 172 && second >= 16 && second <= 31) return true;
      
      // 192.168.0.0/16
      if (first === 192 && second === 168) return true;
      
      // 127.0.0.0/8 (localhost)
      if (first === 127) return true;
      
      return false;
    },
    
    formatGeoInfo(geo, ip) {
      // Check if it's a private IP first
      if (this.isPrivateIP(ip)) {
        return 'Private Network (RFC1918)';
      }
      
      // If geo is null or empty, return a message
      if (!geo || (!geo.country && !geo.city && !geo.asOrg && !geo.regionCode)) {
        return 'Geo data not available\n(View details for location info)';
      }
      
      const parts = [];
      
      // Show city, region ISO code, country
      if (geo.city) parts.push(geo.city);
      if (geo.regionCode) {
        parts.push(geo.regionCode);
      } else if (geo.regionName) {
        parts.push(geo.regionName);
      }
      if (geo.country) parts.push(geo.country);
      
      let location = parts.length > 0 ? parts.join(', ') : '';
      
      // Show AS organization on a separate line if available
      if (geo.asOrg) {
        if (location) {
          location += '\n';
        }
        location += `AS: ${geo.asOrg}`;
      }
      
      return location || 'Geo data not available\n(View details for location info)';
    },
    
    getIpGeoInfo(alert, ipType) {
      if (ipType === 'source') {
        return alert.sourceGeo;
      } else if (ipType === 'dest') {
        return alert.destGeo;
      }
      return null;
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
      
      const displayCount = group.displayCount || group.count;
      const eventText = `${displayCount} event${displayCount > 1 ? 's' : ''}`;
      
      // Show loaded status if we have more than loaded
      let loadedInfo = '';
      if (group.hasMore && group.loadedCount < group.trueCount) {
        loadedInfo = ` (${group.loadedCount} loaded)`;
      }
      
      if (uniqueCombos.size > 0) {
        return `${eventText}${loadedInfo} across ${uniqueCombos.size} unique connection${uniqueCombos.size > 1 ? 's' : ''}`;
      }
      return `${eventText}${loadedInfo}`;
    },
    
    formatCompactNumber(num) {
      // Format large numbers in a compact way
      if (num >= 1000000) {
        return (num / 1000000).toFixed(1).replace(/\.0$/, '') + 'M';
      } else if (num >= 100000) {
        return Math.round(num / 1000) + 'K';
      } else if (num >= 10000) {
        return (num / 1000).toFixed(1).replace(/\.0$/, '') + 'K';
      } else if (num >= 1000) {
        return (num / 1000).toFixed(1).replace(/\.0$/, '') + 'K';
      }
      return num.toString();
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
      const alertCount = group.trueCount || group.displayCount || group.count;
      this.selectedAlert = { 
        id: 'group-' + group.key, 
        ruleName: group.ruleName
      };
      this.selectedGroup = group;
      this.actionType = 'acknowledge-group';
      this.actionTitle = `Acknowledge ${alertCount} Alerts`;
      this.caseTitle = ''; // Not needed for acknowledge
      this.caseDescription = `Acknowledge all ${alertCount} alerts for "${group.ruleName}"?`;
      this.actionDialog = true;
    },
    
    async escalateGroup(group) {
      // Set up for escalation
      const alertCount = group.trueCount || group.displayCount || group.count;
      this.selectedAlert = { 
        id: 'group-' + group.key, 
        ruleName: group.ruleName,
        severityLabel: group.severityLabel 
      };
      this.actionType = 'escalate-group';
      this.actionTitle = `Escalate ${alertCount} Alerts to Case`;
      this.caseTitle = `${group.ruleName} - ${alertCount} alerts`;
      this.caseDescription = `Escalating ${alertCount} alerts for rule: ${group.ruleName}`;
      
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
    
    async loadSubGroupsForRule(group) {
      // TIER 2: Load all alerts for this specific rule to get accurate IP pair counts
      if (group.subGroupsLoaded) {
        return group.subGroups; // Already loaded
      }
      
      group.loadingSubGroups = true;
      
      try {
        const query = this.buildQuery() + ` AND rule.name:"${group.ruleName}"`;
        const dateRange = this.getDateRange();
        
        // First, check if this is likely a host-based rule by checking the first alert
        const isLikelyHostBased = group.alerts && group.alerts[0] && 
                                  (!group.alerts[0].sourceIp && !group.alerts[0].destIp);
        
        // For host-based alerts, we need to aggregate by agent.name
        // For network alerts, we load events to group by IP pairs
        let response;
        
        if (isLikelyHostBased) {
          // Use aggregation query for host-based alerts
          const agentAggQuery = {
            query: query,
            range: dateRange,
            format: '2006/01/02 3:04:05 PM', 
            zone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            view: 'simple',
            eventLimit: '0', // Don't need events, just aggregations
            aggregationType: 'terms',
            aggregationField: 'agent.name',
            metricLimit: '100' // Get top 100 agents
          };
          
          const agentResponse = await this.$root.papi.get('events/?' + new URLSearchParams(agentAggQuery).toString());
          
          if (agentResponse && agentResponse.data && agentResponse.data.metrics) {
            const subGroups = [];
            
            for (const metric of agentResponse.data.metrics) {
              const agentName = metric.keys[0] || 'unknown-agent';
              const count = metric.count || 0;
              
              subGroups.push({
                key: `Agent: ${agentName}`,
                sourceIp: agentName,
                destIp: 'endpoint',
                count: count,
                loadedCount: 0,
                trueCount: count,
                displayCount: this.formatCompactNumber(count),
                alerts: [],
                alertsLoaded: false,
                loadingAlerts: false,
                isHostBased: true,
                agentName: agentName
              });
            }
            
            // Sort by count
            group.subGroups = subGroups.sort((a, b) => b.count - a.count);
            group.subGroupsLoaded = true;
            
            console.log(`Loaded ${subGroups.length} agents for host-based rule "${group.ruleName}"`);
            return group.subGroups;
          }
        }
        
        // For network-based alerts, use the existing logic
        const params = new URLSearchParams({
          query: query,
          range: dateRange,
          format: '2006/01/02 3:04:05 PM',
          zone: Intl.DateTimeFormat().resolvedOptions().timeZone,
          metricLimit: '10',
          eventLimit: '2000', // Load up to 2000 alerts for this rule
          view: 'simple'
        });
        
        response = await this.$root.papi.get('events/?' + params.toString());
        
        if (response && response.data && response.data.events) {
          const subGroups = new Map();
          const totalAlertsForRule = response.data.totalEvents || 0;
          const loadedAlerts = response.data.events || [];
          
          // Process loaded alerts into subgroups
          loadedAlerts.forEach(event => {
            const alert = this.processAlerts([event])[0];
            
            // Determine grouping key based on alert type
            let key;
            let sourceIp = alert.sourceIp || null;
            let destIp = alert.destIp || null;
            
            // For YARA/Sigma/host-based alerts without IPs, group by agent.name
            if (!sourceIp && !destIp) {
              // Always try to get agent name for any alert without IPs
              const agentName = alert.rawData?.['agent.name'] || alert.rawData?.['observer.name'] || 'unknown-agent';
              const hostname = alert.rawData?.['host.name'] || '';
              
              // For any alert without IPs, group by agent
              key = `Agent: ${agentName}`;
              // Store these for display purposes
              sourceIp = agentName;
              destIp = hostname || 'endpoint';
            } else {
              // Network-based alerts with IPs
              key = `${sourceIp || 'unknown'} → ${destIp || 'unknown'}`;
            }
            
            if (!subGroups.has(key)) {
              subGroups.set(key, {
                key: key,
                sourceIp: sourceIp || 'unknown',
                destIp: destIp || 'unknown',
                count: 0,
                loadedCount: 0,
                trueCount: 0,
                alerts: [],
                alertsLoaded: false,
                loadingAlerts: false,
                firstSeen: alert.timestamp,
                lastSeen: alert.timestamp,
                isHostBased: !alert.sourceIp && !alert.destIp // Flag for host-based alerts
              });
            }
            
            const subGroup = subGroups.get(key);
            subGroup.count++;
            subGroup.loadedCount++;
            
            // Store first 50 alerts for quick display
            if (subGroup.alerts.length < 50) {
              subGroup.alerts.push(alert);
              subGroup.alertsLoaded = subGroup.alerts.length >= 50;
            }
            
            // Update timestamps
            if (alert.timestamp < subGroup.firstSeen) {
              subGroup.firstSeen = alert.timestamp;
            }
            if (alert.timestamp > subGroup.lastSeen) {
              subGroup.lastSeen = alert.timestamp;
            }
          });
          
          // If we couldn't load all alerts, estimate true counts
          let subGroupArray = Array.from(subGroups.values());
          
          if (totalAlertsForRule > loadedAlerts.length) {
            // We have more alerts than loaded, need to estimate
            const ratio = totalAlertsForRule / loadedAlerts.length;
            subGroupArray.forEach(sg => {
              sg.trueCount = Math.ceil(sg.count * ratio);
              sg.hasMore = true;
            });
            
            // Add a note that there might be more IP pairs
            group.hasMorePairs = true;
            group.loadedPairsCount = subGroupArray.length;
          } else {
            // We loaded all alerts for this rule
            subGroupArray.forEach(sg => {
              sg.trueCount = sg.count;
              sg.hasMore = false;
            });
            group.hasMorePairs = false;
          }
          
          // Sort by count
          group.subGroups = subGroupArray.sort((a, b) => b.trueCount - a.trueCount);
          group.subGroupsLoaded = true;
          
          console.log(`Loaded ${subGroupArray.length} IP pairs for rule "${group.ruleName}" (${totalAlertsForRule} total alerts)`);
          
          // The counts should now add up to the total
          const totalInSubgroups = subGroupArray.reduce((sum, sg) => sum + sg.trueCount, 0);
          console.log(`Subgroup total: ${totalInSubgroups}, Rule total: ${group.displayCount}`);
        }
      } catch (error) {
        console.error(`Failed to load IP pairs for rule ${group.ruleName}:`, error);
        // Fallback to using loaded alerts
        this.createSubGroupsFromLoadedAlerts(group);
      } finally {
        group.loadingSubGroups = false;
      }
      
      return group.subGroups;
    },
    
    createSubGroupsFromLoadedAlerts(group) {
      // Fallback method using already loaded alerts
      if (group.alerts && group.alerts.length > 0) {
        const subGroups = new Map();
        
        group.alerts.forEach(alert => {
          // Determine grouping key based on alert type
          let key;
          let sourceIp = alert.sourceIp || null;
          let destIp = alert.destIp || null;
          
          // For YARA/Sigma/host-based alerts without IPs, group by agent.name
          if (!sourceIp && !destIp) {
            // Always try to get agent name for any alert without IPs
            const agentName = alert.rawData?.['agent.name'] || alert.rawData?.['observer.name'] || 'unknown-agent';
            const hostname = alert.rawData?.['host.name'] || '';
            
            // For any alert without IPs, group by agent
            key = `Agent: ${agentName}`;
            // Store these for display purposes
            sourceIp = agentName;
            destIp = hostname || 'endpoint';
          } else {
            key = `${sourceIp || 'unknown'} → ${destIp || 'unknown'}`;
          }
          
          if (!subGroups.has(key)) {
            subGroups.set(key, {
              key: key,
              sourceIp: sourceIp || 'unknown',
              destIp: destIp || 'unknown',
              count: 0,
              trueCount: 0,
              alerts: [],
              alertsLoaded: true,
              loadingAlerts: false,
              firstSeen: alert.timestamp,
              lastSeen: alert.timestamp,
              isHostBased: !alert.sourceIp && !alert.destIp
            });
          }
          
          const subGroup = subGroups.get(key);
          subGroup.count++;
          subGroup.alerts.push(alert);
          
          // Update timestamps
          if (alert.timestamp < subGroup.firstSeen) {
            subGroup.firstSeen = alert.timestamp;
          }
          if (alert.timestamp > subGroup.lastSeen) {
            subGroup.lastSeen = alert.timestamp;
          }
        });
        
        // Estimate true counts if needed
        if (group.hasMore) {
          const ratio = group.displayCount / group.count;
          subGroups.forEach(sg => {
            sg.trueCount = Math.ceil(sg.count * ratio);
          });
        } else {
          subGroups.forEach(sg => {
            sg.trueCount = sg.count;
          });
        }
        
        group.subGroups = Array.from(subGroups.values()).sort((a, b) => b.trueCount - a.trueCount);
        group.subGroupsLoaded = true;
      } else {
        group.subGroups = [];
        group.subGroupsLoaded = true;
      }
    },
    
    async loadAlertsForSubGroup(group, subGroup) {
      // TIER 3: Load actual alerts for a specific IP pair or agent
      if (subGroup.alertsLoaded || subGroup.loadingAlerts) {
        return subGroup.alerts;
      }
      
      subGroup.loadingAlerts = true;
      
      try {
        let query = this.buildQuery() + ` AND rule.name:"${group.ruleName}"`;
        
        // Check if this is a host-based subgroup
        if (subGroup.isHostBased || subGroup.key.startsWith('Agent:')) {
          // For host-based alerts, filter by agent.name
          if (subGroup.agentName) {
            query += ` AND agent.name:"${subGroup.agentName}"`;
          } else if (subGroup.sourceIp && subGroup.sourceIp !== 'unknown' && subGroup.sourceIp !== 'endpoint') {
            // sourceIp might contain the agent name for host-based alerts
            query += ` AND agent.name:"${subGroup.sourceIp}"`;
          }
        } else {
          // For network-based alerts, add IP filters
          if (subGroup.sourceIp && subGroup.sourceIp !== 'unknown') {
            query += ` AND source.ip:"${subGroup.sourceIp}"`;
          }
          if (subGroup.destIp && subGroup.destIp !== 'unknown') {
            query += ` AND destination.ip:"${subGroup.destIp}"`;
          }
        }
        
        const dateRange = this.getDateRange();
        
        const params = new URLSearchParams({
          query: query,
          range: dateRange,
          format: '2006/01/02 3:04:05 PM',
          zone: Intl.DateTimeFormat().resolvedOptions().timeZone,
          metricLimit: '0',
          eventLimit: '50', // Load first 50 alerts
          view: 'simple'
        });
        
        const response = await this.$root.papi.get('events/?' + params.toString());
        
        if (response && response.data && response.data.events) {
          subGroup.alerts = this.processAlerts(response.data.events);
          subGroup.totalAlerts = response.data.totalEvents || subGroup.alerts.length;
          subGroup.hasMore = subGroup.totalAlerts > subGroup.alerts.length;
          
          // Update timestamps
          if (subGroup.alerts.length > 0) {
            subGroup.firstSeen = subGroup.alerts[subGroup.alerts.length - 1].timestamp;
            subGroup.lastSeen = subGroup.alerts[0].timestamp;
          }
          
          // Batch lookup hostnames if needed
          if (this.$root.enableReverseLookup) {
            const ips = [];
            subGroup.alerts.forEach(alert => {
              if (alert.sourceIp) ips.push(alert.sourceIp);
              if (alert.destIp) ips.push(alert.destIp);
            });
            if (ips.length > 0) {
              this.$root.batchLookup(ips, this);
            }
          }
        }
        
        subGroup.alertsLoaded = true;
        console.log(`Loaded ${subGroup.alerts.length} alerts for ${subGroup.key}`);
      } catch (error) {
        console.error(`Failed to load alerts for ${subGroup.key}:`, error);
        subGroup.alerts = [];
        subGroup.alertsLoaded = true;
      } finally {
        subGroup.loadingAlerts = false;
      }
      
      return subGroup.alerts;
    },
    
    getSubGroups(group) {
      // Trigger lazy loading of subgroups when first accessed
      if (!group.subGroupsLoaded && !group.loadingSubGroups) {
        // Start loading subgroups asynchronously
        this.loadSubGroupsForRule(group).then(() => {
          this.$forceUpdate(); // Force Vue to re-render when loaded
        });
      }
      
      return group.subGroups || [];
    },
    
    getSubGroupsOld(group) {
      // OLD METHOD - kept for reference, but not used
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
              sourceGeo: alert.sourceGeo,
              destGeo: alert.destGeo,
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