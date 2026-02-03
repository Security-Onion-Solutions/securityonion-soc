// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

import { ref, computed } from 'vue'

// =============================================================================
// Types
// =============================================================================

export interface AgentTool {
  id: string
  name: string
  description: string
  enabled: boolean
}

export interface AIAgent {
  id: string
  name: string
  description: string
  status: 'active' | 'paused'
  triggerType: 'manual' | 'scheduled' | 'event-driven'
  systemPrompt: string
  tools: AgentTool[]
  lastRun?: string
  createTime: string
  updateTime: string
}

export interface AgentStats {
  total: number
  active: number
  paused: number
}

export interface AgentSearchCriteria {
  search?: string
  status?: 'all' | 'active' | 'paused'
  triggerType?: 'all' | 'manual' | 'scheduled' | 'event-driven'
}

// =============================================================================
// Execution & Metrics Types
// =============================================================================

export interface AgentAction {
  id: string
  tool: string
  action: string
  description: string
  timestamp: string
  status: 'success' | 'failed'
  details?: Record<string, any>
}

export interface AgentExecution {
  id: string
  agentId: string
  agentName: string
  trigger: 'manual' | 'scheduled' | 'event'
  triggerEvent?: string
  triggerData?: Record<string, any>
  status: 'running' | 'completed' | 'failed' | 'cancelled'
  startTime: string
  endTime?: string
  duration?: number
  actions: AgentAction[]
  tokensUsed?: number
  summary?: string
  error?: string
}

export interface AgentMetricsSummary {
  totalExecutions: number
  successfulExecutions: number
  failedExecutions: number
  totalActions: number
  alertsAcknowledged: number
  casesCreated: number
  casesUpdated: number
  analyzersRun: number
  averageDuration: number
  tokensUsed: number
}

// =============================================================================
// Available Tools (Mock Data)
// =============================================================================

export const availableTools: AgentTool[] = [
  {
    id: 'hunt',
    name: 'Hunt',
    description: 'Search and query security events in the data lake',
    enabled: false
  },
  {
    id: 'cases',
    name: 'Cases',
    description: 'Create, update, and manage security cases',
    enabled: false
  },
  {
    id: 'alerts',
    name: 'Alerts',
    description: 'View, acknowledge, and escalate security alerts',
    enabled: false
  },
  {
    id: 'analyzers',
    name: 'Analyzers',
    description: 'Run automated analyzers on artifacts and observables',
    enabled: false
  },
  {
    id: 'detections',
    name: 'Detections',
    description: 'Query and manage detection rules',
    enabled: false
  },
  {
    id: 'playbooks',
    name: 'Playbooks',
    description: 'Execute investigation playbooks',
    enabled: false
  }
]

// =============================================================================
// Mock Data
// =============================================================================

// =============================================================================
// Mock Execution History
// =============================================================================

const mockExecutions: AgentExecution[] = [
  // Alert Triage - Recent executions
  {
    id: 'exec-001',
    agentId: '1',
    agentName: 'Alert Triage',
    trigger: 'event',
    triggerEvent: 'alert.created',
    triggerData: { alertId: 'alert-5847', ruleName: 'Suspicious PowerShell Download' },
    status: 'completed',
    startTime: new Date(Date.now() - 1000 * 60 * 5).toISOString(),
    endTime: new Date(Date.now() - 1000 * 60 * 4).toISOString(),
    duration: 45000,
    tokensUsed: 1250,
    summary: 'Analyzed alert and determined it was a false positive - known admin script.',
    actions: [
      { id: 'a1', tool: 'hunt', action: 'search', description: 'Searched for similar events from same source', timestamp: new Date(Date.now() - 1000 * 60 * 5).toISOString(), status: 'success', details: { resultsFound: 15 } },
      { id: 'a2', tool: 'alerts', action: 'get_context', description: 'Retrieved alert context and enrichment', timestamp: new Date(Date.now() - 1000 * 60 * 4.5).toISOString(), status: 'success' },
      { id: 'a3', tool: 'hunt', action: 'search', description: 'Checked baseline for source user', timestamp: new Date(Date.now() - 1000 * 60 * 4.2).toISOString(), status: 'success', details: { isBaseline: true } },
      { id: 'a4', tool: 'alerts', action: 'acknowledge', description: 'Acknowledged alert as false positive', timestamp: new Date(Date.now() - 1000 * 60 * 4).toISOString(), status: 'success' }
    ]
  },
  {
    id: 'exec-002',
    agentId: '1',
    agentName: 'Alert Triage',
    trigger: 'event',
    triggerEvent: 'alert.created',
    triggerData: { alertId: 'alert-5846', ruleName: 'Brute Force Attempt Detected' },
    status: 'completed',
    startTime: new Date(Date.now() - 1000 * 60 * 15).toISOString(),
    endTime: new Date(Date.now() - 1000 * 60 * 13).toISOString(),
    duration: 120000,
    tokensUsed: 2100,
    summary: 'Alert requires human review - potential brute force from external IP.',
    actions: [
      { id: 'a5', tool: 'hunt', action: 'search', description: 'Searched for failed login attempts', timestamp: new Date(Date.now() - 1000 * 60 * 15).toISOString(), status: 'success', details: { resultsFound: 247 } },
      { id: 'a6', tool: 'alerts', action: 'get_context', description: 'Retrieved alert context', timestamp: new Date(Date.now() - 1000 * 60 * 14).toISOString(), status: 'success' },
      { id: 'a7', tool: 'hunt', action: 'search', description: 'Checked if source IP is known', timestamp: new Date(Date.now() - 1000 * 60 * 13.5).toISOString(), status: 'success', details: { isKnown: false } },
      { id: 'a8', tool: 'alerts', action: 'add_note', description: 'Added analysis note for human review', timestamp: new Date(Date.now() - 1000 * 60 * 13).toISOString(), status: 'success' }
    ]
  },
  {
    id: 'exec-003',
    agentId: '1',
    agentName: 'Alert Triage',
    trigger: 'event',
    triggerEvent: 'alert.created',
    triggerData: { alertId: 'alert-5845', ruleName: 'DNS Query to Known Bad Domain' },
    status: 'completed',
    startTime: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
    endTime: new Date(Date.now() - 1000 * 60 * 29).toISOString(),
    duration: 38000,
    tokensUsed: 980,
    summary: 'False positive - domain is a security vendor update server.',
    actions: [
      { id: 'a9', tool: 'hunt', action: 'search', description: 'Searched for DNS query context', timestamp: new Date(Date.now() - 1000 * 60 * 30).toISOString(), status: 'success' },
      { id: 'a10', tool: 'alerts', action: 'acknowledge', description: 'Acknowledged alert as false positive', timestamp: new Date(Date.now() - 1000 * 60 * 29).toISOString(), status: 'success' }
    ]
  },
  // More Alert Triage executions
  {
    id: 'exec-004',
    agentId: '1',
    agentName: 'Alert Triage',
    trigger: 'event',
    triggerEvent: 'alert.created',
    triggerData: { alertId: 'alert-5840', ruleName: 'Unusual Process Execution' },
    status: 'completed',
    startTime: new Date(Date.now() - 1000 * 60 * 60).toISOString(),
    endTime: new Date(Date.now() - 1000 * 60 * 59).toISOString(),
    duration: 52000,
    tokensUsed: 1450,
    summary: 'Acknowledged - scheduled task from IT automation.',
    actions: [
      { id: 'a11', tool: 'hunt', action: 'search', description: 'Investigated process tree', timestamp: new Date(Date.now() - 1000 * 60 * 60).toISOString(), status: 'success' },
      { id: 'a12', tool: 'alerts', action: 'acknowledge', description: 'Acknowledged as known automation', timestamp: new Date(Date.now() - 1000 * 60 * 59).toISOString(), status: 'success' }
    ]
  },
  // Case Analyzer executions
  {
    id: 'exec-010',
    agentId: '2',
    agentName: 'Case Analyzer',
    trigger: 'event',
    triggerEvent: 'case.created',
    triggerData: { caseId: 'case-1247', title: 'Potential Data Exfiltration' },
    status: 'completed',
    startTime: new Date(Date.now() - 1000 * 60 * 60 * 2).toISOString(),
    endTime: new Date(Date.now() - 1000 * 60 * 60 * 2 + 180000).toISOString(),
    duration: 180000,
    tokensUsed: 3200,
    summary: 'Enriched 5 observables with threat intelligence. Found 2 malicious indicators.',
    actions: [
      { id: 'a20', tool: 'cases', action: 'get_observables', description: 'Retrieved case observables', timestamp: new Date(Date.now() - 1000 * 60 * 60 * 2).toISOString(), status: 'success', details: { observables: 5 } },
      { id: 'a21', tool: 'analyzers', action: 'run', description: 'Ran VirusTotal analyzer on file hash', timestamp: new Date(Date.now() - 1000 * 60 * 60 * 2 + 30000).toISOString(), status: 'success', details: { malicious: true, score: '45/70' } },
      { id: 'a22', tool: 'analyzers', action: 'run', description: 'Ran AbuseIPDB analyzer on IP', timestamp: new Date(Date.now() - 1000 * 60 * 60 * 2 + 60000).toISOString(), status: 'success', details: { abuseScore: 87 } },
      { id: 'a23', tool: 'analyzers', action: 'run', description: 'Ran URLhaus analyzer on domain', timestamp: new Date(Date.now() - 1000 * 60 * 60 * 2 + 90000).toISOString(), status: 'success', details: { malicious: true } },
      { id: 'a24', tool: 'cases', action: 'add_note', description: 'Added threat intelligence summary', timestamp: new Date(Date.now() - 1000 * 60 * 60 * 2 + 150000).toISOString(), status: 'success' },
      { id: 'a25', tool: 'cases', action: 'update', description: 'Updated case severity to High', timestamp: new Date(Date.now() - 1000 * 60 * 60 * 2 + 180000).toISOString(), status: 'success' }
    ]
  },
  {
    id: 'exec-011',
    agentId: '2',
    agentName: 'Case Analyzer',
    trigger: 'event',
    triggerEvent: 'case.created',
    triggerData: { caseId: 'case-1246', title: 'Phishing Email Investigation' },
    status: 'completed',
    startTime: new Date(Date.now() - 1000 * 60 * 60 * 5).toISOString(),
    endTime: new Date(Date.now() - 1000 * 60 * 60 * 5 + 95000).toISOString(),
    duration: 95000,
    tokensUsed: 1800,
    summary: 'Analyzed 3 observables. Email sender domain is newly registered and suspicious.',
    actions: [
      { id: 'a26', tool: 'cases', action: 'get_observables', description: 'Retrieved case observables', timestamp: new Date(Date.now() - 1000 * 60 * 60 * 5).toISOString(), status: 'success', details: { observables: 3 } },
      { id: 'a27', tool: 'analyzers', action: 'run', description: 'Ran WHOIS analyzer on domain', timestamp: new Date(Date.now() - 1000 * 60 * 60 * 5 + 30000).toISOString(), status: 'success', details: { ageInDays: 3 } },
      { id: 'a28', tool: 'analyzers', action: 'run', description: 'Ran URLscan analyzer', timestamp: new Date(Date.now() - 1000 * 60 * 60 * 5 + 60000).toISOString(), status: 'success' },
      { id: 'a29', tool: 'cases', action: 'add_note', description: 'Added analysis findings', timestamp: new Date(Date.now() - 1000 * 60 * 60 * 5 + 95000).toISOString(), status: 'success' }
    ]
  },
  // Daily Summary executions
  {
    id: 'exec-020',
    agentId: '3',
    agentName: 'Daily Summary',
    trigger: 'scheduled',
    status: 'completed',
    startTime: new Date(Date.now() - 1000 * 60 * 60 * 20).toISOString(),
    endTime: new Date(Date.now() - 1000 * 60 * 60 * 20 + 240000).toISOString(),
    duration: 240000,
    tokensUsed: 4500,
    summary: 'Generated daily security report. 847 alerts processed, 12 cases updated, 3 high-priority items flagged.',
    actions: [
      { id: 'a30', tool: 'alerts', action: 'search', description: 'Retrieved alert statistics for last 24h', timestamp: new Date(Date.now() - 1000 * 60 * 60 * 20).toISOString(), status: 'success', details: { totalAlerts: 847 } },
      { id: 'a31', tool: 'hunt', action: 'search', description: 'Analyzed trending event patterns', timestamp: new Date(Date.now() - 1000 * 60 * 60 * 20 + 60000).toISOString(), status: 'success' },
      { id: 'a32', tool: 'cases', action: 'search', description: 'Retrieved case status summary', timestamp: new Date(Date.now() - 1000 * 60 * 60 * 20 + 120000).toISOString(), status: 'success', details: { open: 24, closed: 8 } },
      { id: 'a33', tool: 'detections', action: 'search', description: 'Identified top triggered detections', timestamp: new Date(Date.now() - 1000 * 60 * 60 * 20 + 180000).toISOString(), status: 'success' },
      { id: 'a34', tool: 'cases', action: 'create_note', description: 'Created daily summary report', timestamp: new Date(Date.now() - 1000 * 60 * 60 * 20 + 240000).toISOString(), status: 'success' }
    ]
  },
  // Failed execution example
  {
    id: 'exec-030',
    agentId: '2',
    agentName: 'Case Analyzer',
    trigger: 'event',
    triggerEvent: 'case.created',
    triggerData: { caseId: 'case-1245', title: 'Malware Detection' },
    status: 'failed',
    startTime: new Date(Date.now() - 1000 * 60 * 60 * 8).toISOString(),
    endTime: new Date(Date.now() - 1000 * 60 * 60 * 8 + 45000).toISOString(),
    duration: 45000,
    tokensUsed: 800,
    error: 'Analyzer timeout: VirusTotal rate limit exceeded',
    actions: [
      { id: 'a40', tool: 'cases', action: 'get_observables', description: 'Retrieved case observables', timestamp: new Date(Date.now() - 1000 * 60 * 60 * 8).toISOString(), status: 'success', details: { observables: 8 } },
      { id: 'a41', tool: 'analyzers', action: 'run', description: 'Attempted VirusTotal analysis', timestamp: new Date(Date.now() - 1000 * 60 * 60 * 8 + 30000).toISOString(), status: 'failed', details: { error: 'Rate limit exceeded' } }
    ]
  },
  // Threat Hunter manual execution
  {
    id: 'exec-040',
    agentId: '4',
    agentName: 'Threat Hunter',
    trigger: 'manual',
    triggerData: { input: 'Investigate suspicious lateral movement from 10.0.5.47' },
    status: 'completed',
    startTime: new Date(Date.now() - 1000 * 60 * 60 * 24 * 3).toISOString(),
    endTime: new Date(Date.now() - 1000 * 60 * 60 * 24 * 3 + 600000).toISOString(),
    duration: 600000,
    tokensUsed: 8500,
    summary: 'Confirmed lateral movement activity. Created case with timeline and MITRE mapping. Recommended immediate containment.',
    actions: [
      { id: 'a50', tool: 'hunt', action: 'search', description: 'Searched for all activity from 10.0.5.47', timestamp: new Date(Date.now() - 1000 * 60 * 60 * 24 * 3).toISOString(), status: 'success', details: { resultsFound: 1247 } },
      { id: 'a51', tool: 'hunt', action: 'search', description: 'Identified authentication events', timestamp: new Date(Date.now() - 1000 * 60 * 60 * 24 * 3 + 60000).toISOString(), status: 'success', details: { resultsFound: 89 } },
      { id: 'a52', tool: 'hunt', action: 'search', description: 'Tracked process executions', timestamp: new Date(Date.now() - 1000 * 60 * 60 * 24 * 3 + 120000).toISOString(), status: 'success', details: { resultsFound: 342 } },
      { id: 'a53', tool: 'hunt', action: 'search', description: 'Analyzed network connections', timestamp: new Date(Date.now() - 1000 * 60 * 60 * 24 * 3 + 180000).toISOString(), status: 'success', details: { resultsFound: 567 } },
      { id: 'a54', tool: 'alerts', action: 'search', description: 'Correlated with existing alerts', timestamp: new Date(Date.now() - 1000 * 60 * 60 * 24 * 3 + 240000).toISOString(), status: 'success', details: { relatedAlerts: 12 } },
      { id: 'a55', tool: 'cases', action: 'create', description: 'Created incident case', timestamp: new Date(Date.now() - 1000 * 60 * 60 * 24 * 3 + 400000).toISOString(), status: 'success', details: { caseId: 'case-1240' } },
      { id: 'a56', tool: 'playbooks', action: 'run', description: 'Executed lateral movement playbook', timestamp: new Date(Date.now() - 1000 * 60 * 60 * 24 * 3 + 500000).toISOString(), status: 'success' },
      { id: 'a57', tool: 'cases', action: 'update', description: 'Added MITRE ATT&CK mapping and recommendations', timestamp: new Date(Date.now() - 1000 * 60 * 60 * 24 * 3 + 600000).toISOString(), status: 'success' }
    ]
  }
]

const mockAgents: AIAgent[] = [
  {
    id: '1',
    name: 'Alert Triage',
    description: 'Reviews low and medium severity alerts and acknowledges false positives based on historical patterns and known-good baselines.',
    status: 'active',
    triggerType: 'event-driven',
    systemPrompt: `You are an alert triage specialist. Your job is to review incoming low and medium severity alerts and determine if they are likely false positives.

Review each alert by:
1. Checking if the source IP/user is in known-good baselines
2. Comparing to similar historical alerts that were confirmed false positives
3. Evaluating the alert context and enrichment data

If you determine an alert is a false positive with high confidence, acknowledge it and add a note explaining your reasoning. If uncertain, leave it for human review.`,
    tools: [
      { ...availableTools[0], enabled: true },
      { ...availableTools[2], enabled: true },
      { ...availableTools[4], enabled: true }
    ],
    lastRun: new Date(Date.now() - 1000 * 60 * 5).toISOString(),
    createTime: new Date(Date.now() - 1000 * 60 * 60 * 24 * 30).toISOString(),
    updateTime: new Date(Date.now() - 1000 * 60 * 60 * 24 * 2).toISOString()
  },
  {
    id: '2',
    name: 'Case Analyzer',
    description: 'Automatically runs relevant analyzers when new cases are created, enriching observables with threat intelligence.',
    status: 'active',
    triggerType: 'event-driven',
    systemPrompt: `You are a case enrichment specialist. When a new case is created, your job is to automatically run relevant analyzers on the observables.

For each observable in the case:
1. Determine the appropriate analyzers based on observable type (IP, domain, hash, etc.)
2. Run the analyzers and wait for results
3. Summarize findings and add them as case notes
4. Flag any high-confidence malicious indicators for immediate attention`,
    tools: [
      { ...availableTools[1], enabled: true },
      { ...availableTools[3], enabled: true }
    ],
    lastRun: new Date(Date.now() - 1000 * 60 * 60 * 2).toISOString(),
    createTime: new Date(Date.now() - 1000 * 60 * 60 * 24 * 45).toISOString(),
    updateTime: new Date(Date.now() - 1000 * 60 * 60 * 24 * 7).toISOString()
  },
  {
    id: '3',
    name: 'Daily Summary',
    description: 'Generates a daily security summary report including alert statistics, notable events, and trending threats.',
    status: 'active',
    triggerType: 'scheduled',
    systemPrompt: `You are a security reporting analyst. Generate a daily security summary at the end of each day.

Your report should include:
1. Alert statistics (total, by severity, by category)
2. Notable events that warrant attention
3. Trending attack patterns or IOCs
4. Case status summary (open, closed, pending)
5. Recommendations for the security team

Format the report in a clear, executive-friendly manner.`,
    tools: [
      { ...availableTools[0], enabled: true },
      { ...availableTools[1], enabled: true },
      { ...availableTools[2], enabled: true },
      { ...availableTools[4], enabled: true }
    ],
    lastRun: new Date(Date.now() - 1000 * 60 * 60 * 20).toISOString(),
    createTime: new Date(Date.now() - 1000 * 60 * 60 * 24 * 60).toISOString(),
    updateTime: new Date(Date.now() - 1000 * 60 * 60 * 24 * 14).toISOString()
  },
  {
    id: '4',
    name: 'Threat Hunter',
    description: 'Investigates suspicious activity on demand, correlating events across multiple data sources to identify potential threats.',
    status: 'paused',
    triggerType: 'manual',
    systemPrompt: `You are an expert threat hunter. When invoked, investigate the specified suspicious activity thoroughly.

Investigation process:
1. Gather context about the initial indicator or activity
2. Pivot across data sources to find related events
3. Build a timeline of activity
4. Identify potential attack techniques (map to MITRE ATT&CK)
5. Determine scope and impact
6. Provide recommended response actions

Document all findings and create a case if malicious activity is confirmed.`,
    tools: [
      { ...availableTools[0], enabled: true },
      { ...availableTools[1], enabled: true },
      { ...availableTools[2], enabled: true },
      { ...availableTools[3], enabled: true },
      { ...availableTools[4], enabled: true },
      { ...availableTools[5], enabled: true }
    ],
    lastRun: new Date(Date.now() - 1000 * 60 * 60 * 24 * 3).toISOString(),
    createTime: new Date(Date.now() - 1000 * 60 * 60 * 24 * 90).toISOString(),
    updateTime: new Date(Date.now() - 1000 * 60 * 60 * 24 * 10).toISOString()
  }
]

// =============================================================================
// Composable
// =============================================================================

// Shared state
const agents = ref<AIAgent[]>([...mockAgents])
const loading = ref(false)
const error = ref<string | null>(null)

export function useAgents() {
  // =========================================================================
  // Computed Stats
  // =========================================================================

  const stats = computed<AgentStats>(() => ({
    total: agents.value.length,
    active: agents.value.filter(a => a.status === 'active').length,
    paused: agents.value.filter(a => a.status === 'paused').length
  }))

  // =========================================================================
  // CRUD Operations
  // =========================================================================

  /**
   * Get all agents with optional filtering
   */
  async function getAgents(criteria: AgentSearchCriteria = {}): Promise<AIAgent[]> {
    loading.value = true
    error.value = null

    // Simulate API delay
    await new Promise(resolve => setTimeout(resolve, 300))

    try {
      let result = [...agents.value]

      // Filter by status
      if (criteria.status && criteria.status !== 'all') {
        result = result.filter(a => a.status === criteria.status)
      }

      // Filter by trigger type
      if (criteria.triggerType && criteria.triggerType !== 'all') {
        result = result.filter(a => a.triggerType === criteria.triggerType)
      }

      // Filter by search query
      if (criteria.search) {
        const query = criteria.search.toLowerCase()
        result = result.filter(a =>
          a.name.toLowerCase().includes(query) ||
          a.description.toLowerCase().includes(query)
        )
      }

      return result
    } finally {
      loading.value = false
    }
  }

  /**
   * Get a single agent by ID
   */
  async function getAgent(id: string): Promise<AIAgent | null> {
    await new Promise(resolve => setTimeout(resolve, 100))
    return agents.value.find(a => a.id === id) || null
  }

  /**
   * Create a new agent
   */
  async function createAgent(agent: Omit<AIAgent, 'id' | 'createTime' | 'updateTime'>): Promise<AIAgent> {
    loading.value = true
    error.value = null

    await new Promise(resolve => setTimeout(resolve, 300))

    try {
      const newAgent: AIAgent = {
        ...agent,
        id: String(Date.now()),
        createTime: new Date().toISOString(),
        updateTime: new Date().toISOString()
      }
      agents.value.push(newAgent)
      return newAgent
    } finally {
      loading.value = false
    }
  }

  /**
   * Update an existing agent
   */
  async function updateAgent(agent: AIAgent): Promise<AIAgent> {
    loading.value = true
    error.value = null

    await new Promise(resolve => setTimeout(resolve, 300))

    try {
      const index = agents.value.findIndex(a => a.id === agent.id)
      if (index === -1) {
        throw new Error('Agent not found')
      }

      const updated: AIAgent = {
        ...agent,
        updateTime: new Date().toISOString()
      }
      agents.value[index] = updated
      return updated
    } finally {
      loading.value = false
    }
  }

  /**
   * Delete an agent
   */
  async function deleteAgent(id: string): Promise<void> {
    loading.value = true
    error.value = null

    await new Promise(resolve => setTimeout(resolve, 300))

    try {
      const index = agents.value.findIndex(a => a.id === id)
      if (index === -1) {
        throw new Error('Agent not found')
      }
      agents.value.splice(index, 1)
    } finally {
      loading.value = false
    }
  }

  /**
   * Toggle agent status (active <-> paused)
   */
  async function toggleAgentStatus(id: string): Promise<AIAgent> {
    const agent = agents.value.find(a => a.id === id)
    if (!agent) {
      throw new Error('Agent not found')
    }

    const updated: AIAgent = {
      ...agent,
      status: agent.status === 'active' ? 'paused' : 'active',
      updateTime: new Date().toISOString()
    }

    return updateAgent(updated)
  }

  /**
   * Get available tools for agent configuration
   */
  function getAvailableTools(): AgentTool[] {
    return availableTools.map(t => ({ ...t }))
  }

  // =========================================================================
  // Execution History & Metrics
  // =========================================================================

  /**
   * Get execution history, optionally filtered by agent
   */
  async function getExecutions(agentId?: string, limit = 50): Promise<AgentExecution[]> {
    await new Promise(resolve => setTimeout(resolve, 200))

    let executions = [...mockExecutions]

    if (agentId) {
      executions = executions.filter(e => e.agentId === agentId)
    }

    // Sort by start time descending (most recent first)
    executions.sort((a, b) => new Date(b.startTime).getTime() - new Date(a.startTime).getTime())

    return executions.slice(0, limit)
  }

  /**
   * Get a single execution by ID
   */
  async function getExecution(executionId: string): Promise<AgentExecution | null> {
    await new Promise(resolve => setTimeout(resolve, 100))
    return mockExecutions.find(e => e.id === executionId) || null
  }

  /**
   * Get aggregated metrics summary
   */
  async function getMetricsSummary(agentId?: string): Promise<AgentMetricsSummary> {
    await new Promise(resolve => setTimeout(resolve, 150))

    let executions = [...mockExecutions]
    if (agentId) {
      executions = executions.filter(e => e.agentId === agentId)
    }

    const completed = executions.filter(e => e.status === 'completed')
    const failed = executions.filter(e => e.status === 'failed')
    const allActions = executions.flatMap(e => e.actions)

    // Count specific action types
    const alertActions = allActions.filter(a => a.tool === 'alerts')
    const caseActions = allActions.filter(a => a.tool === 'cases')
    const analyzerActions = allActions.filter(a => a.tool === 'analyzers')

    const alertsAcked = alertActions.filter(a => a.action === 'acknowledge').length
    const casesCreated = caseActions.filter(a => a.action === 'create').length
    const casesUpdated = caseActions.filter(a => a.action === 'update' || a.action === 'add_note').length

    const totalDuration = completed.reduce((sum, e) => sum + (e.duration || 0), 0)
    const totalTokens = executions.reduce((sum, e) => sum + (e.tokensUsed || 0), 0)

    return {
      totalExecutions: executions.length,
      successfulExecutions: completed.length,
      failedExecutions: failed.length,
      totalActions: allActions.length,
      alertsAcknowledged: alertsAcked,
      casesCreated: casesCreated,
      casesUpdated: casesUpdated,
      analyzersRun: analyzerActions.filter(a => a.action === 'run').length,
      averageDuration: completed.length > 0 ? Math.round(totalDuration / completed.length) : 0,
      tokensUsed: totalTokens
    }
  }

  /**
   * Get execution counts grouped by day for charting
   */
  async function getExecutionsByDay(days = 7, agentId?: string): Promise<{ date: string; completed: number; failed: number }[]> {
    await new Promise(resolve => setTimeout(resolve, 100))

    const result: { date: string; completed: number; failed: number }[] = []
    const now = new Date()

    for (let i = days - 1; i >= 0; i--) {
      const date = new Date(now)
      date.setDate(date.getDate() - i)
      const dateStr = date.toISOString().split('T')[0]

      const dayExecutions = mockExecutions.filter(e => {
        const execDate = e.startTime.split('T')[0]
        const matchesAgent = !agentId || e.agentId === agentId
        return execDate === dateStr && matchesAgent
      })

      result.push({
        date: dateStr,
        completed: dayExecutions.filter(e => e.status === 'completed').length,
        failed: dayExecutions.filter(e => e.status === 'failed').length
      })
    }

    // Add some mock data for visualization
    if (result.every(r => r.completed === 0 && r.failed === 0)) {
      result[result.length - 1].completed = 8
      result[result.length - 1].failed = 1
      result[result.length - 2].completed = 12
      result[result.length - 3].completed = 6
      result[result.length - 3].failed = 1
      result[result.length - 4].completed = 15
      result[result.length - 5].completed = 9
      result[result.length - 6].completed = 11
      result[result.length - 6].failed = 2
    }

    return result
  }

  /**
   * Get top actions by type
   */
  async function getActionBreakdown(agentId?: string): Promise<{ tool: string; action: string; count: number }[]> {
    await new Promise(resolve => setTimeout(resolve, 100))

    let executions = [...mockExecutions]
    if (agentId) {
      executions = executions.filter(e => e.agentId === agentId)
    }

    const allActions = executions.flatMap(e => e.actions)
    const actionCounts = new Map<string, number>()

    for (const action of allActions) {
      const key = `${action.tool}:${action.action}`
      actionCounts.set(key, (actionCounts.get(key) || 0) + 1)
    }

    return Array.from(actionCounts.entries())
      .map(([key, count]) => {
        const [tool, action] = key.split(':')
        return { tool, action, count }
      })
      .sort((a, b) => b.count - a.count)
  }

  return {
    // State
    agents,
    loading,
    error,
    stats,

    // CRUD Operations
    getAgents,
    getAgent,
    createAgent,
    updateAgent,
    deleteAgent,
    toggleAgentStatus,

    // Utilities
    getAvailableTools,

    // Execution & Metrics
    getExecutions,
    getExecution,
    getMetricsSummary,
    getExecutionsByDay,
    getActionBreakdown
  }
}
