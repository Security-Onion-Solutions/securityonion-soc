// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

export default {
  saveAIInvestigations() {
    // Save AI investigation results to localStorage
    try {
      localStorage['aiInvestigations'] = JSON.stringify(this.aiInvestigations);
    } catch (error) {
      console.error('Failed to save AI investigations to localStorage:', error);
    }
  },

  loadAIInvestigations() {
    // Load AI investigation results from localStorage
    try {
      if (localStorage['aiInvestigations']) {
        this.aiInvestigations = JSON.parse(localStorage['aiInvestigations']);
      }
    } catch (error) {
      console.error('Failed to load AI investigations from localStorage:', error);
      this.aiInvestigations = {};
    }
  },

  applyAIInvestigationsToEvents() {
    // Apply loaded AI investigation results to current event data
    if (this.eventData && this.eventData.length > 0) {
      this.eventData.forEach(item => {
        const alertId = item['rule.uuid'] || item.soc_id;
        if (alertId && this.aiInvestigations[alertId]) {
          const investigation = this.aiInvestigations[alertId];
          item._aiInvestigationStatus = 'completed';
          item._aiInvestigationResult = investigation;
        }
      });
    }

    // Also apply to grouped data
    if (this.groupBys && this.groupBys.length > 0) {
      this.groupBys.forEach(group => {
        if (group.data && group.data.length > 0) {
          group.data.forEach(item => {
            const alertId = item['rule.uuid'] || item.soc_id;
            if (alertId && this.aiInvestigations[alertId]) {
              const investigation = this.aiInvestigations[alertId];
              item._aiInvestigationStatus = 'completed';
              item._aiInvestigationResult = investigation;
            }
          });
        }
      });
    }
  },

  startAIInvestigation(event, item, groupIdx) {
    const alertId = item['rule.uuid'] || item.soc_id;
    if (!alertId) {
      this.$root.showError(this.i18n.aiInvestigationUnableToIdentify);
      return;
    }

    // If investigation is completed, navigate to existing chat session
    if (item._aiInvestigationStatus === 'completed' && item._aiInvestigationResult && item._aiInvestigationResult.chatSessionId) {
      const chatUrl = `${window.location.origin}/#/chat/${item._aiInvestigationResult.chatSessionId}`;
      window.open(chatUrl, '_blank');
      return;
    }

    // Prevent multiple investigations for the same alert
    if (item._aiInvestigationStatus === 'investigating') {
      return;
    }

    // Generate a unique chat session ID for this investigation
    const chatSessionId = 'investigation_' + alertId + '_' + Date.now();

    // Set investigation status to investigating
    item._aiInvestigationStatus = 'investigating';

    // Store the chat session ID with the investigation
    if (!this.aiInvestigations[alertId]) {
      this.aiInvestigations[alertId] = {};
    }
    this.aiInvestigations[alertId].chatSessionId = chatSessionId;
    this.aiInvestigations[alertId].status = 'investigating';
    this.aiInvestigations[alertId].alertId = alertId;
    this.aiInvestigations[alertId].timestamp = new Date().toISOString();
    this.saveAIInvestigations();

    // Create the investigation prompt with alert data
    const investigationPrompt = this.generateInvestigationPrompt(item);

    // Store the investigation prompt in localStorage to avoid URL encoding issues
    const investigationData = {
      alertId: alertId,
      prompt: investigationPrompt,
      timestamp: new Date().toISOString()
    };
    localStorage.setItem(`investigation_${chatSessionId}`, JSON.stringify(investigationData));

    // Open chat in new tab with investigation session ID
    const chatUrl = `${window.location.origin}/#/chat/${chatSessionId}?investigation=true&alertId=${encodeURIComponent(alertId)}`;
    window.open(chatUrl, '_blank');
  },

  generateInvestigationPrompt(item) {
    const alertId = item['rule.uuid'] || item.soc_id;

    // Prepare the alert data for investigation
    const alertData = {
      alertId: alertId,
      ruleUuid: item['rule.uuid'],
      ruleName: item['rule.name'],
      severity: item['event.severity_label'],
      timestamp: item['soc_timestamp'] || item['@timestamp'],
      sourceIp: item['source.ip'],
      destIp: item['destination.ip'],
      eventModule: item['event.module'],
      eventDataset: item['event.dataset'],
      message: item['message'],
      alertRule: item['rule.rule']
    };

    // Create investigation message
    const investigationMsg = `Please investigate the following Security Onion alert systematically:

Alert ID: ${alertData.alertId || 'Unknown'}
Title: ${alertData.ruleName || 'Unknown'}
Severity: ${alertData.severity || 'Unknown'}
Rule: ${alertData.alertRule || 'Unknown'}
Source IP: ${alertData.sourceIp || 'Unknown'}
Destination IP: ${alertData.destIp || 'Unknown'}
Timestamp: ${alertData.timestamp || 'Unknown'}

INVESTIGATION STEPS:

1. First, fetch the complete alert details using the alert ID:
   - Query for the specific alert to get full context
   - Extract all relevant fields and metadata

2. Get the playbook questions for this alert type:
   - Use the rule UUID to retrieve investigation playbook
   - Follow the structured investigation questions

3. Answer each playbook question by:
   - Running the suggested queries provided in the playbook
   - Analyzing the results thoroughly
   - Drawing evidence-based conclusions

4. Search for related activity:
   - Additional alerts from the same source IP
   - Other connections to/from the involved IPs
   - Related activity in suggested time windows
   - Pattern analysis across similar events

5. Provide a comprehensive assessment including:
   - Verdict (malicious/suspicious/benign/unknown)
   - Confidence level (0-100%)
   - Detailed findings and evidence
   - Recommended actions
   - MITRE ATT&CK mapping if applicable

Please begin the investigation now.`;

    return investigationMsg;
  },

  getAIInvestigationButtonColor(item) {
    const alertId = item['rule.uuid'] || item.soc_id;
    const investigation = this.aiInvestigations[alertId];

    switch (item._aiInvestigationStatus) {
      case 'investigating':
        return 'primary';
      case 'completed':
        if (investigation && investigation.assessment) {
          return investigation.assessment === 'true_positive' ? 'red darken-1' :
                 investigation.assessment === 'false_positive' ? 'green darken-1' : 'amber darken-1';
        }
        return 'secondary';
      case 'error':
        return 'red darken-1';
      default:
        return 'pink-lighten-2';
    }
  },

  getAIInvestigationTooltip(item) {
    const alertId = item['rule.uuid'] || item.soc_id;
    const investigation = this.aiInvestigations[alertId];

    if (item._aiInvestigationStatus === 'completed' && investigation) {
      if (investigation.assessment) {
        const assessmentText = investigation.assessment === 'true_positive' ? this.i18n.aiTruePositive :
                              investigation.assessment === 'false_positive' ? this.i18n.aiFalsePositive : this.i18n.aiUncertain;
        const confidence = investigation.confidence || 'Unknown';
        return `${this.i18n.aiAssessment}: ${assessmentText} (${confidence}% ${this.i18n.aiConfidence}) - ${this.i18n.clickToOpenChat}`;
      }
      return `${this.i18n.aiInvestigationCompleted} - ${this.i18n.clickToOpenChat}`;
    } else if (item._aiInvestigationStatus === 'investigating') {
      return `${this.i18n.aiInvestigationInProgress} - ${this.i18n.clickToOpenChat}`;
    }
    return `${this.i18n.startAIInvestigation}`;
  },
};