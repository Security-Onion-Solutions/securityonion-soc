# Case Enhancement Plan: Guided Analysis Integration

## Executive Summary

This document outlines a comprehensive plan to modernize the Security Onion case management module by integrating guided analysis results from alert investigations. The enhancement will ensure that cases capture the complete investigation context, including all related events discovered through automated playbook queries.

## Problem Statement

### Current Limitations
- Cases only include the primary alert event ID(s)
- No context from guided analysis queries is preserved
- Analysts must manually re-run investigations when reviewing cases
- Case module appears outdated compared to the rich alert details view
- Loss of valuable investigation context and relationships between events

### Alert Details vs Cases Gap
The alert details popup includes:
- AI-generated rule descriptions
- Guided analysis with automated playbook queries
- Related events discovered through investigation
- Rich context including network data, PCAP, and event relationships

The case module only includes:
- Basic title and description
- Primary alert event(s)
- Manual comments and attachments
- No automated investigation context

## Solution Overview

Enhance the case creation process to automatically capture and preserve all guided analysis results, creating a comprehensive investigation package that includes:

1. **Primary alert event(s)**
2. **All related events discovered through guided analysis**
3. **Query metadata and relationships**
4. **AI summaries and rule descriptions**
5. **Investigation timeline and context**

## Technical Architecture

### Data Flow

```
Alert Escalation Flow:
┌─────────────────┐
│  Alert Details  │
│     Popup       │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Collect Guided  │
│ Analysis Events │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Enrich Case    │
│   Metadata      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Create Case    │
│  with Context   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Case View      │
│  with Analysis  │
└─────────────────┘
```

### Component Architecture

```
Frontend Components:
├── Alert Management (simplealerts.js)
│   ├── escalateAlert() - Enhanced
│   ├── collectGuidedAnalysisEvents() - New
│   ├── buildEnrichedCaseDescription() - New
│   └── formatGuidedAnalysisMetadata() - New
│
├── Case Management (case.js)
│   ├── loadAnalysisContext() - New
│   ├── buildEventTimeline() - New
│   ├── displayQueryResults() - New
│   └── analysisContext{} - New data structure
│
└── Templates
    ├── case.html - Enhanced with Analysis Context tab
    └── Components for query visualization
```

## Implementation Details

### Phase 1: Basic Integration (Week 1-2)

#### 1.1 Event Collection (`simplealerts.js`)

```javascript
// New method to collect all guided analysis event IDs
async collectGuidedAnalysisEvents(alert) {
  const eventIds = new Set();
  const queryMetadata = [];
  
  if (alert.playbooks) {
    for (const playbook of alert.playbooks) {
      const questions = playbook.sortedQuestions || playbook.questions || [];
      
      for (const question of questions) {
        if (question.answers && question.answers.length > 0) {
          const queryInfo = {
            question: question.question,
            context: question.context,
            query: question.filledOQL || question.filledQuery,
            range: question.range,
            resultCount: question.answers.length,
            eventIds: []
          };
          
          for (const answer of question.answers) {
            // Collect event IDs from different answer formats
            const eventId = answer.id || 
                          answer.fields?.soc_id || 
                          answer.fields?.['_id'];
            
            if (eventId) {
              eventIds.add(eventId);
              queryInfo.eventIds.push(eventId);
            }
          }
          
          if (queryInfo.eventIds.length > 0) {
            queryMetadata.push(queryInfo);
          }
        }
      }
    }
  }
  
  return {
    eventIds: Array.from(eventIds),
    metadata: queryMetadata
  };
}
```

#### 1.2 Enhanced Case Creation

```javascript
async confirmAction() {
  if (this.actionType === 'escalate') {
    // Collect guided analysis context
    const analysisData = await this.collectGuidedAnalysisEvents(this.selectedAlert);
    
    // Build comprehensive event list
    const allEventIds = [this.selectedAlert.id, ...analysisData.eventIds];
    
    // Create enriched case
    const caseData = {
      title: this.caseTitle,
      description: this.buildEnrichedDescription(this.selectedAlert, analysisData),
      severity: this.selectedAlert.severityLabel,
      status: 'new',
      events: allEventIds,
      metadata: {
        primaryEventId: this.selectedAlert.id,
        guidedAnalysisQueries: analysisData.metadata,
        aiSummary: this.selectedAlert.aiSummary,
        ruleName: this.selectedAlert.ruleName,
        ruleText: this.selectedAlert.ruleText,
        collectionTimestamp: new Date().toISOString()
      }
    };
    
    const response = await this.$root.papi.post('case', caseData);
    
    // Navigate to the new case
    if (response.data?.id) {
      this.$router.push({ name: 'case', params: { id: response.data.id } });
    }
  }
}
```

#### 1.3 Enriched Description Builder

```javascript
buildEnrichedDescription(alert, analysisData) {
  let description = this.caseDescription + '\n\n';
  
  // Add rule information
  description += `## Alert Details\n`;
  description += `- **Rule**: ${alert.ruleName}\n`;
  description += `- **Severity**: ${alert.severityLabel}\n`;
  description += `- **Time**: ${new Date(alert.timestamp).toLocaleString()}\n`;
  
  if (alert.sourceIp && alert.destIp) {
    description += `- **Connection**: ${alert.sourceIp} → ${alert.destIp}\n`;
  } else if (alert.agentName) {
    description += `- **Agent**: ${alert.agentName}\n`;
  }
  
  // Add AI Summary
  if (alert.aiSummary) {
    description += `\n## AI Analysis\n${alert.aiSummary}\n`;
  }
  
  // Add guided analysis summary
  if (analysisData.metadata.length > 0) {
    description += `\n## Guided Analysis Summary\n\n`;
    description += `Executed ${analysisData.metadata.length} investigation queries:\n\n`;
    
    for (const query of analysisData.metadata) {
      description += `### ${query.question}\n`;
      description += `- **Results**: ${query.resultCount} related events\n`;
      if (query.context) {
        description += `- **Context**: ${query.context}\n`;
      }
      description += `- **Time Range**: ${query.range || 'Default'}\n\n`;
    }
    
    description += `\n**Total Related Events**: ${analysisData.eventIds.length}\n`;
  }
  
  return description;
}
```

### Phase 2: Enhanced Display (Week 3-4)

#### 2.1 Case View Enhancement (`case.js`)

```javascript
// Add to data() in case.js
analysisContext: {
  primaryEvent: null,
  guidedQueries: [],
  timeline: [],
  eventsByQuery: {},
  loading: false,
  error: null
},

// Add to mounted() or created()
async mounted() {
  await this.loadCase();
  if (this.caseObj.metadata?.guidedAnalysisQueries) {
    await this.loadAnalysisContext();
  }
},

// New methods
async loadAnalysisContext() {
  this.analysisContext.loading = true;
  this.analysisContext.error = null;
  
  try {
    // Parse guided analysis metadata
    const metadata = this.caseObj.metadata;
    this.analysisContext.guidedQueries = metadata.guidedAnalysisQueries || [];
    
    // Load primary event details
    if (metadata.primaryEventId) {
      this.analysisContext.primaryEvent = await this.loadEventDetails(metadata.primaryEventId);
    }
    
    // Organize events by query
    for (const query of this.analysisContext.guidedQueries) {
      if (query.eventIds && query.eventIds.length > 0) {
        // Load first few events for preview
        const previewEvents = await this.loadEventDetails(query.eventIds.slice(0, 3));
        this.analysisContext.eventsByQuery[query.question] = previewEvents;
      }
    }
    
    // Build timeline
    await this.buildEventTimeline();
    
  } catch (error) {
    console.error('Failed to load analysis context:', error);
    this.analysisContext.error = 'Failed to load analysis context';
  } finally {
    this.analysisContext.loading = false;
  }
},

async buildEventTimeline() {
  const timeline = [];
  
  // Add primary event
  if (this.analysisContext.primaryEvent) {
    timeline.push({
      timestamp: this.analysisContext.primaryEvent.timestamp,
      type: 'primary',
      title: 'Initial Alert',
      event: this.analysisContext.primaryEvent
    });
  }
  
  // Add related events from queries
  for (const query of this.analysisContext.guidedQueries) {
    const events = this.analysisContext.eventsByQuery[query.question] || [];
    for (const event of events) {
      timeline.push({
        timestamp: event.timestamp,
        type: 'related',
        title: query.question,
        event: event
      });
    }
  }
  
  // Sort by timestamp
  timeline.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
  this.analysisContext.timeline = timeline;
}
```

#### 2.2 Case Template Enhancement (`case.html`)

```html
<!-- Add new tab to v-tabs -->
<v-tab value="analysis" v-if="caseObj.metadata?.guidedAnalysisQueries">
  <v-icon start size="small">fa-magnifying-glass-chart</v-icon>
  Analysis Context
  <v-chip size="x-small" class="ml-2" color="primary">
    {{ caseObj.metadata.guidedAnalysisQueries.length }}
  </v-chip>
</v-tab>

<!-- Add new tab panel -->
<v-window-item value="analysis">
  <v-container fluid>
    <!-- AI Summary Card -->
    <v-card v-if="caseObj.metadata?.aiSummary" class="mb-4">
      <v-card-title>
        <v-icon start>fa-robot</v-icon>
        AI Analysis
      </v-card-title>
      <v-card-text>
        <div class="text-body-1">{{ caseObj.metadata.aiSummary }}</div>
      </v-card-text>
    </v-card>
    
    <!-- Primary Alert Card -->
    <v-card v-if="analysisContext.primaryEvent" class="mb-4">
      <v-card-title>
        <v-icon start>fa-exclamation-triangle</v-icon>
        Primary Alert
      </v-card-title>
      <v-card-text>
        <v-row>
          <v-col cols="12" md="6">
            <div class="text-subtitle-2">Rule</div>
            <div>{{ caseObj.metadata.ruleName }}</div>
          </v-col>
          <v-col cols="12" md="6">
            <div class="text-subtitle-2">Timestamp</div>
            <div>{{ new Date(analysisContext.primaryEvent.timestamp).toLocaleString() }}</div>
          </v-col>
        </v-row>
      </v-card-text>
    </v-card>
    
    <!-- Guided Analysis Results -->
    <v-card>
      <v-card-title>
        <v-icon start>fa-compass</v-icon>
        Guided Analysis Queries
        <v-spacer></v-spacer>
        <v-chip>
          {{ analysisContext.guidedQueries.reduce((sum, q) => sum + q.resultCount, 0) }} 
          Total Events
        </v-chip>
      </v-card-title>
      <v-card-text>
        <v-expansion-panels variant="accordion">
          <v-expansion-panel 
            v-for="(query, idx) in analysisContext.guidedQueries" 
            :key="idx">
            <v-expansion-panel-title>
              <div class="d-flex align-center justify-space-between w-100 pr-4">
                <div>
                  <v-icon 
                    size="small" 
                    :color="query.resultCount > 0 ? 'success' : 'grey'"
                    class="mr-2">
                    {{ query.resultCount > 0 ? 'fa-check-circle' : 'fa-circle' }}
                  </v-icon>
                  {{ query.question }}
                </div>
                <v-chip size="small" :color="query.resultCount > 0 ? 'success' : 'default'">
                  {{ query.resultCount }} events
                </v-chip>
              </div>
            </v-expansion-panel-title>
            <v-expansion-panel-text>
              <!-- Query Details -->
              <div v-if="query.context" class="mb-3">
                <div class="text-caption font-weight-bold">Context</div>
                <div class="text-body-2">{{ query.context }}</div>
              </div>
              
              <div v-if="query.query" class="mb-3">
                <div class="text-caption font-weight-bold">Query</div>
                <v-sheet color="grey-darken-3" rounded class="pa-2">
                  <code class="text-caption">{{ query.query }}</code>
                </v-sheet>
              </div>
              
              <div v-if="query.range" class="mb-3">
                <div class="text-caption font-weight-bold">Time Range</div>
                <div class="text-body-2">{{ query.range }}</div>
              </div>
              
              <!-- Event Preview -->
              <div v-if="analysisContext.eventsByQuery[query.question]">
                <div class="text-caption font-weight-bold mb-2">Event Preview</div>
                <v-list density="compact">
                  <v-list-item 
                    v-for="event in analysisContext.eventsByQuery[query.question]" 
                    :key="event.id">
                    <v-list-item-title>
                      {{ event.timestamp }} - {{ event.summary || event.id }}
                    </v-list-item-title>
                  </v-list-item>
                </v-list>
                <v-btn 
                  v-if="query.resultCount > 3"
                  size="small" 
                  variant="text" 
                  color="primary"
                  @click="viewAllQueryEvents(query)">
                  View All {{ query.resultCount }} Events
                </v-btn>
              </div>
              
              <!-- Hunt Link -->
              <v-divider class="my-3"></v-divider>
              <v-btn
                size="small"
                variant="outlined"
                color="primary"
                :href="getHuntUrlForQuery(query)"
                target="_blank">
                <v-icon start size="small">fa-crosshairs</v-icon>
                Re-run in Hunt
              </v-btn>
            </v-expansion-panel-text>
          </v-expansion-panel>
        </v-expansion-panels>
      </v-card-text>
    </v-card>
    
    <!-- Event Timeline -->
    <v-card v-if="analysisContext.timeline.length > 0" class="mt-4">
      <v-card-title>
        <v-icon start>fa-clock</v-icon>
        Event Timeline
      </v-card-title>
      <v-card-text>
        <v-timeline density="compact">
          <v-timeline-item
            v-for="(item, idx) in analysisContext.timeline"
            :key="idx"
            :dot-color="item.type === 'primary' ? 'error' : 'primary'"
            size="small">
            <template v-slot:opposite>
              <div class="text-caption">
                {{ new Date(item.timestamp).toLocaleTimeString() }}
              </div>
            </template>
            <div>
              <div class="font-weight-medium">{{ item.title }}</div>
              <div class="text-caption text--secondary">
                {{ item.event.summary || item.event.id }}
              </div>
            </div>
          </v-timeline-item>
        </v-timeline>
      </v-card-text>
    </v-card>
  </v-container>
</v-window-item>
```

### Phase 3: Advanced Features (Week 5-6)

#### 3.1 Export Functionality

```javascript
// Add to case.js
async exportAnalysisReport() {
  const report = {
    case: {
      id: this.caseObj.id,
      title: this.caseObj.title,
      created: this.caseObj.createTime,
      severity: this.caseObj.severity
    },
    primaryAlert: this.analysisContext.primaryEvent,
    aiSummary: this.caseObj.metadata?.aiSummary,
    guidedAnalysis: this.analysisContext.guidedQueries,
    timeline: this.analysisContext.timeline,
    totalEvents: this.associations.events.length
  };
  
  // Convert to JSON and download
  const blob = new Blob([JSON.stringify(report, null, 2)], 
                        { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `case_${this.caseObj.id}_analysis.json`;
  a.click();
  URL.revokeObjectURL(url);
}
```

#### 3.2 Pattern Detection

```javascript
// Add pattern detection for similar cases
async findSimilarCases() {
  if (!this.caseObj.metadata?.ruleName) return;
  
  try {
    // Search for cases with same rule
    const response = await this.$root.papi.get('cases', {
      params: {
        query: `metadata.ruleName:"${this.caseObj.metadata.ruleName}"`,
        limit: 10
      }
    });
    
    this.similarCases = response.data.filter(c => c.id !== this.caseObj.id);
    
    if (this.similarCases.length > 0) {
      this.$root.showTip(`Found ${this.similarCases.length} similar cases`);
    }
  } catch (error) {
    console.error('Failed to find similar cases:', error);
  }
}
```

## API Requirements

### Backend Modifications

The case API endpoint needs to support:

1. **Metadata field** in case creation and updates
2. **Larger event arrays** (potentially 100+ events)
3. **Efficient event retrieval** by case ID
4. **Query for cases by metadata fields**

Example API request:
```javascript
POST /api/case
{
  "title": "Alert: Suspicious Network Activity",
  "description": "Enhanced description with analysis...",
  "severity": "high",
  "status": "new",
  "events": ["event1", "event2", ..., "eventN"],
  "metadata": {
    "primaryEventId": "event1",
    "guidedAnalysisQueries": [...],
    "aiSummary": "...",
    "ruleName": "...",
    "collectionTimestamp": "2024-01-15T10:30:00Z"
  }
}
```

## Testing Strategy

### Unit Tests
- Event collection from guided analysis
- Metadata formatting
- Description building
- Timeline generation

### Integration Tests
- Case creation with full context
- Loading analysis context in case view
- Export functionality
- Performance with large event sets

### User Acceptance Tests
- Escalate alert with guided analysis
- View case with analysis context
- Export analysis report
- Find similar cases

## Rollout Plan

### Phase 1 (Weeks 1-2)
- Implement event collection
- Update case creation
- Basic metadata storage
- Deploy to development environment

### Phase 2 (Weeks 3-4)
- Add Analysis Context tab
- Implement timeline view
- Query result display
- Deploy to staging environment

### Phase 3 (Weeks 5-6)
- Export functionality
- Pattern detection
- Performance optimization
- Production deployment

## Success Metrics

1. **Context Preservation**: 100% of guided analysis events captured
2. **Investigation Efficiency**: 50% reduction in time to review cases
3. **User Adoption**: 80% of escalated alerts include guided analysis
4. **Performance**: Case loading time < 2 seconds with full context
5. **Audit Compliance**: Complete investigation trail maintained

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Large event volumes | Performance degradation | Implement pagination and lazy loading |
| API compatibility | Backend changes required | Coordinate with backend team early |
| Storage requirements | Increased database usage | Implement data retention policies |
| User training | Adoption challenges | Create documentation and training materials |

## Conclusion

This enhancement brings the case management module to parity with the sophisticated alert investigation capabilities, ensuring that all discovered context is preserved for future reference. The phased approach allows for incremental delivery of value while maintaining system stability.

## Appendices

### A. File Modification Summary

- `/html/js/routes/simplealerts.js` - Event collection and enhanced escalation
- `/html/js/routes/case.js` - Analysis context display and management
- `/html/pages/case.html` - New UI components for analysis visualization
- `/html/js/routes/hunt/playbook.js` - Ensure proper event ID capture

### B. Configuration Requirements

- No new configuration files required
- Existing API endpoints extended with metadata support
- Backward compatibility maintained for existing cases

### C. Dependencies

- Existing playbook infrastructure
- Current case management API
- Alert investigation framework
- No new external dependencies required