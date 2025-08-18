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
      caseTitle: '',
      caseDescription: '',
      
      // Details dialog
      detailsDialog: false,
      selectedAlertDetails: null,
      expandedQuestions: [],
      
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
    }
  }
};

// Register the simple-alerts route only - leave the existing alerts route as is
routes.push({ path: '/simple-alerts', name: 'simple-alerts', component: simpleAlertsComponent });