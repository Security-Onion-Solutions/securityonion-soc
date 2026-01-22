// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

import { ref, shallowRef, computed } from 'vue'
import { useApi } from './useApi'
import { useTimeRange } from './useTimeRange'
import type {
    AlertGroup,
    SourceDestPair,
    AcknowledgedFilter
} from '../types/alerts'
import type { EventRecord, EventSearchResponse, ChartMetric } from '../types/hunt'

// =============================================================================
// Constants
// =============================================================================

const GROUP_PAGE_SIZE = 50
const PAIR_PAGE_SIZE = 25
const ALERT_PAGE_SIZE = 50
const GO_TIME_FORMAT = '2006/01/02 3:04:05 PM'

// =============================================================================
// Composable
// =============================================================================

export function useAlerts() {
    const { get, loading: apiLoading, error: apiError } = useApi()
    const { formattedRange, zone } = useTimeRange()

    // =========================================================================
    // State - Alert Groups
    // =========================================================================

    const alertGroups = shallowRef<AlertGroup[]>([])
    const totalAlerts = ref(0)
    const groupsLoading = ref(false)
    const groupsLoadingMore = ref(false)
    const groupsError = ref<string | null>(null)
    const hasMoreGroups = ref(true)
    const groupsOffset = ref(0)

    // =========================================================================
    // State - Filters
    // =========================================================================

    const searchQuery = ref('')
    const acknowledgedFilter = ref<AcknowledgedFilter>('unacknowledged')
    const severityFilter = ref<string[]>([])

    // =========================================================================
    // State - Sorting
    // =========================================================================

    type SortField = 'count' | 'name' | 'severity'
    type SortDirection = 'asc' | 'desc'

    const sortField = ref<SortField>('count')
    const sortDirection = ref<SortDirection>('desc')

    // =========================================================================
    // State - Triage View Grouping
    // =========================================================================

    type TriageGroupBy = 'rule' | 'severity' | 'source' | 'destination'
    const triageGroupBy = ref<TriageGroupBy>('rule')

    function setTriageGroupBy(groupBy: TriageGroupBy) {
        triageGroupBy.value = groupBy
        // Re-fetch with new grouping
        fetchAlertGroups()
    }

    // =========================================================================
    // State - Alert Group Detail
    // =========================================================================

    const currentRuleName = ref('')
    const pairs = shallowRef<SourceDestPair[]>([])
    const alerts = shallowRef<EventRecord[]>([])
    const selectedPair = ref<SourceDestPair | null>(null)

    const pairsLoading = ref(false)
    const pairsLoadingMore = ref(false)
    const pairsError = ref<string | null>(null)
    const hasMorePairs = ref(true)
    const pairsOffset = ref(0)

    const alertsLoading = ref(false)
    const alertsLoadingMore = ref(false)
    const alertsError = ref<string | null>(null)
    const hasMoreAlerts = ref(true)
    const alertsOffset = ref(0)

    // =========================================================================
    // Cache
    // =========================================================================

    const groupsCache = ref<AlertGroup[] | null>(null)
    const pairsCache = ref<Map<string, SourceDestPair[]>>(new Map())

    // =========================================================================
    // Computed
    // =========================================================================

    const filteredGroups = computed(() => {
        let groups = alertGroups.value

        // Apply search filter
        if (searchQuery.value) {
            const query = searchQuery.value.toLowerCase()
            groups = groups.filter(group =>
                group.ruleName.toLowerCase().includes(query)
            )
        }

        // Apply sorting
        const field = sortField.value
        const direction = sortDirection.value
        const multiplier = direction === 'asc' ? 1 : -1

        return [...groups].sort((a, b) => {
            if (field === 'count') {
                return (a.count - b.count) * multiplier
            } else if (field === 'name') {
                return a.ruleName.localeCompare(b.ruleName) * multiplier
            } else if (field === 'severity') {
                return compareSeverity(a.severity, b.severity) * multiplier
            }
            return 0
        })
    })

    // =========================================================================
    // Build Query
    // =========================================================================

    function buildBaseQuery(): string {
        let query = 'tags:alert'

        if (acknowledgedFilter.value === 'acknowledged') {
            query += ' AND event.acknowledged:true'
        } else if (acknowledgedFilter.value === 'unacknowledged') {
            query += ' AND NOT event.acknowledged:true'
        }

        if (severityFilter.value.length > 0) {
            const severities = severityFilter.value.map(s => `"${s}"`).join(' OR ')
            query += ` AND event.severity_label:(${severities})`
        }

        return query
    }

    // =========================================================================
    // Fetch Alert Groups
    // =========================================================================

    async function fetchAlertGroups(loadMore = false): Promise<void> {
        if (loadMore) {
            groupsLoadingMore.value = true
            groupsOffset.value += GROUP_PAGE_SIZE
        } else {
            groupsLoading.value = true
            groupsOffset.value = 0
            alertGroups.value = []
            hasMoreGroups.value = true
        }

        groupsError.value = null

        try {
            // Determine primary grouping field based on triageGroupBy
            let groupByFields: string
            switch (triageGroupBy.value) {
                case 'severity':
                    groupByFields = 'event.severity_label rule.name event.module'
                    break
                case 'source':
                    groupByFields = 'source.ip event.severity_label rule.name'
                    break
                case 'destination':
                    groupByFields = 'destination.ip event.severity_label rule.name'
                    break
                case 'rule':
                default:
                    groupByFields = 'rule.name event.severity_label event.module'
                    break
            }
            const query = `${buildBaseQuery()} | groupby ${groupByFields}`

            const response = await get<EventSearchResponse>('/api/events/', {
                query,
                range: formattedRange.value,
                format: GO_TIME_FORMAT,
                zone: zone.value,
                metricLimit: String(GROUP_PAGE_SIZE),
                eventLimit: '0'
            })

            if (!response) {
                throw new Error('No response from server')
            }

            totalAlerts.value = response.totalEvents

            // Process metrics into AlertGroup[]
            const newGroups = processGroupMetrics(response.metrics)

            if (loadMore) {
                alertGroups.value = [...alertGroups.value, ...newGroups]
            } else {
                alertGroups.value = newGroups
                groupsCache.value = newGroups
            }

            hasMoreGroups.value = newGroups.length === GROUP_PAGE_SIZE
        } catch (e: any) {
            groupsError.value = e.message || 'Failed to fetch alert groups'
            console.error('Failed to fetch alert groups:', e)
        } finally {
            groupsLoading.value = false
            groupsLoadingMore.value = false
        }
    }

    function processGroupMetrics(metrics?: Record<string, ChartMetric[]>): AlertGroup[] {
        if (!metrics) return []

        // Find the longest groupby_0 key (contains all fields)
        const groupByKeys = Object.keys(metrics).filter(k => k.startsWith('groupby_0|'))
        if (groupByKeys.length === 0) return []

        // Sort by number of fields (pipe-separated) and take the longest
        const groupByKey = groupByKeys.sort((a, b) => b.split('|').length - a.split('|').length)[0]

        const chartMetrics = metrics[groupByKey]
        if (!chartMetrics) return []

        // Parse field names from key
        const keyParts = groupByKey.split('|')
        const fieldNames = keyParts.slice(1) // Remove "groupby_0" prefix

        // Determine which field is the primary grouping based on triageGroupBy
        let primaryField: string
        switch (triageGroupBy.value) {
            case 'severity':
                primaryField = 'event.severity_label'
                break
            case 'source':
                primaryField = 'source.ip'
                break
            case 'destination':
                primaryField = 'destination.ip'
                break
            case 'rule':
            default:
                primaryField = 'rule.name'
                break
        }

        // Find indices for the fields
        const primaryIdx = fieldNames.indexOf(primaryField)
        const ruleNameIdx = fieldNames.indexOf('rule.name')
        const severityIdx = fieldNames.indexOf('event.severity_label')
        const moduleIdx = fieldNames.indexOf('event.module')
        const sourceIdx = fieldNames.indexOf('source.ip')
        const destIdx = fieldNames.indexOf('destination.ip')

        // Group by primary field and aggregate
        const groupMap = new Map<string, AlertGroup>()

        for (const metric of chartMetrics) {
            // Get primary field value
            const rawPrimary = primaryIdx >= 0 && metric.keys[primaryIdx] ? metric.keys[primaryIdx] : null
            const primaryValue = rawPrimary ? String(rawPrimary).trim() || 'Unknown' : 'Unknown'

            // Get supporting fields
            const rawRuleName = ruleNameIdx >= 0 && metric.keys[ruleNameIdx] ? metric.keys[ruleNameIdx] : null
            const rawSeverity = severityIdx >= 0 && metric.keys[severityIdx] ? metric.keys[severityIdx] : null
            const rawModule = moduleIdx >= 0 && metric.keys[moduleIdx] ? metric.keys[moduleIdx] : null

            const ruleName = rawRuleName ? String(rawRuleName).trim() || 'Unknown' : 'Unknown'
            const severity = rawSeverity ? String(rawSeverity).trim().toLowerCase() || 'unknown' : 'unknown'
            const module = rawModule ? String(rawModule).trim() || 'unknown' : 'unknown'

            const existing = groupMap.get(primaryValue)
            if (existing) {
                existing.count += metric.value
                // Keep highest severity
                if (compareSeverity(severity, existing.severity) > 0) {
                    existing.severity = severity
                }
            } else {
                groupMap.set(primaryValue, {
                    ruleName: triageGroupBy.value === 'rule' ? primaryValue : ruleName,
                    ruleId: encodeURIComponent(primaryValue),
                    count: metric.value,
                    severity: triageGroupBy.value === 'severity' ? primaryValue : severity,
                    module
                })
            }
        }

        // Sort by count descending
        return Array.from(groupMap.values()).sort((a, b) => b.count - a.count)
    }

    function compareSeverity(a: string, b: string): number {
        const order: Record<string, number> = {
            'critical': 4,
            'high': 3,
            'medium': 2,
            'low': 1,
            'unknown': 0
        }
        return (order[a.toLowerCase()] || 0) - (order[b.toLowerCase()] || 0)
    }

    // =========================================================================
    // Fetch Secondary Grouping (Pairs or Rules depending on primary grouping)
    // =========================================================================

    // Generic subgroup that can represent either source/dest pairs or rule names
    interface Subgroup {
        key: string           // Unique key for the subgroup
        label: string         // Display label
        secondaryLabel?: string // Optional secondary label (e.g., dest IP for pairs)
        count: number
        type: 'pair' | 'rule' // Type of subgroup
    }

    const subgroups = shallowRef<Subgroup[]>([])
    const subgroupsLoading = ref(false)
    const subgroupsLoadingMore = ref(false)
    const subgroupsError = ref<string | null>(null)
    const hasMoreSubgroups = ref(true)
    const subgroupsOffset = ref(0)
    const subgroupsCache = ref<Map<string, Subgroup[]>>(new Map())

    // =========================================================================
    // Detection AI Summary Cache
    // =========================================================================

    interface DetectionInfo {
        publicId: string
        title: string
        aiSummary?: string
        isAiSummaryStale?: boolean
    }

    const detectionInfoCache = ref<Map<string, DetectionInfo | null>>(new Map())
    const detectionInfoLoading = ref<Map<string, boolean>>(new Map())

    /**
     * Fetch detection info (including AI summary) by public ID (rule.uuid)
     */
    async function fetchDetectionByPublicId(publicId: string): Promise<DetectionInfo | null> {
        // Check cache first (keyed by publicId)
        if (detectionInfoCache.value.has(publicId)) {
            return detectionInfoCache.value.get(publicId) || null
        }

        // Check if already loading
        if (detectionInfoLoading.value.get(publicId)) {
            return null
        }

        detectionInfoLoading.value.set(publicId, true)

        try {
            const response = await fetch(`/api/detection/public/${encodeURIComponent(publicId)}`)
            if (response.ok) {
                const detection = await response.json()
                const info: DetectionInfo = {
                    publicId: detection.publicId || publicId,
                    title: detection.title || '',
                    aiSummary: detection.aiSummary,
                    isAiSummaryStale: detection.isAiSummaryStale
                }
                detectionInfoCache.value.set(publicId, info)
                return info
            }

            // Detection not found - cache null to avoid repeated lookups
            detectionInfoCache.value.set(publicId, null)
            return null
        } catch (e) {
            console.error('Failed to fetch detection info:', e)
            return null
        } finally {
            detectionInfoLoading.value.set(publicId, false)
        }
    }

    /**
     * Fetch detection info for a rule by fetching a sample alert to get rule.uuid
     */
    async function fetchDetectionForRule(ruleName: string): Promise<DetectionInfo | null> {
        // Check if we already have it cached by rule name
        const cacheKey = `rule:${ruleName}`
        if (detectionInfoCache.value.has(cacheKey)) {
            return detectionInfoCache.value.get(cacheKey) || null
        }

        // Check if already loading
        if (detectionInfoLoading.value.get(cacheKey)) {
            return null
        }

        detectionInfoLoading.value.set(cacheKey, true)

        try {
            // Fetch one sample alert to get the rule.uuid
            const escapedRule = ruleName.replace(/"/g, '\\"')
            const query = `${buildBaseQuery()} AND rule.name:"${escapedRule}"`

            const response = await get<EventSearchResponse>('/api/events/', {
                query,
                range: formattedRange.value,
                format: GO_TIME_FORMAT,
                zone: zone.value,
                metricLimit: '0',
                eventLimit: '1'
            })

            if (response?.events?.length) {
                const event = response.events[0]
                const payload = event.payload || event
                const ruleUuid = payload['rule.uuid']

                if (ruleUuid) {
                    // Now fetch the detection using the rule.uuid
                    const detectionInfo = await fetchDetectionByPublicId(ruleUuid)
                    // Also cache by rule name for future lookups
                    detectionInfoCache.value.set(cacheKey, detectionInfo)
                    return detectionInfo
                }
            }

            // No rule.uuid found - cache null
            detectionInfoCache.value.set(cacheKey, null)
            return null
        } catch (e) {
            console.error('Failed to fetch detection for rule:', e)
            return null
        } finally {
            detectionInfoLoading.value.set(cacheKey, false)
        }
    }

    function getDetectionInfo(ruleName: string): DetectionInfo | null | undefined {
        const cacheKey = `rule:${ruleName}`
        return detectionInfoCache.value.get(cacheKey)
    }

    function isDetectionInfoLoading(ruleName: string): boolean {
        const cacheKey = `rule:${ruleName}`
        return detectionInfoLoading.value.get(cacheKey) || false
    }

    async function fetchSubgroups(groupKey: string, loadMore = false): Promise<void> {
        currentRuleName.value = groupKey

        if (loadMore) {
            subgroupsLoadingMore.value = true
            subgroupsOffset.value += PAIR_PAGE_SIZE
        } else {
            subgroupsLoading.value = true
            subgroupsOffset.value = 0
            subgroups.value = []
            hasMoreSubgroups.value = true

            // Check cache
            const cacheKey = `${triageGroupBy.value}:${groupKey}`
            const cached = subgroupsCache.value.get(cacheKey)
            if (cached) {
                subgroups.value = cached
                subgroupsLoading.value = false
                return
            }
        }

        subgroupsError.value = null

        try {
            const escaped = groupKey.replace(/"/g, '\\"')
            let query: string
            let groupByFields: string

            // Determine filter and secondary grouping based on primary grouping
            switch (triageGroupBy.value) {
                case 'source':
                    query = `${buildBaseQuery()} AND source.ip:"${escaped}"`
                    groupByFields = 'rule.name event.severity_label'
                    break
                case 'destination':
                    query = `${buildBaseQuery()} AND destination.ip:"${escaped}"`
                    groupByFields = 'rule.name event.severity_label'
                    break
                case 'severity':
                    query = `${buildBaseQuery()} AND event.severity_label:"${escaped}"`
                    groupByFields = 'rule.name event.module'
                    break
                case 'rule':
                default:
                    query = `${buildBaseQuery()} AND rule.name:"${escaped}"`
                    groupByFields = 'source.ip destination.ip'
                    break
            }

            query += ` | groupby ${groupByFields}`

            const response = await get<EventSearchResponse>('/api/events/', {
                query,
                range: formattedRange.value,
                format: GO_TIME_FORMAT,
                zone: zone.value,
                metricLimit: String(PAIR_PAGE_SIZE),
                eventLimit: '0'
            })

            if (!response) {
                throw new Error('No response from server')
            }

            const newSubgroups = processSubgroupMetrics(response.metrics)

            const cacheKey = `${triageGroupBy.value}:${groupKey}`
            if (loadMore) {
                subgroups.value = [...subgroups.value, ...newSubgroups]
            } else {
                subgroups.value = newSubgroups
                subgroupsCache.value.set(cacheKey, newSubgroups)
            }

            hasMoreSubgroups.value = newSubgroups.length === PAIR_PAGE_SIZE
        } catch (e: any) {
            subgroupsError.value = e.message || 'Failed to fetch subgroups'
            console.error('Failed to fetch subgroups:', e)
        } finally {
            subgroupsLoading.value = false
            subgroupsLoadingMore.value = false
        }
    }

    function processSubgroupMetrics(metrics?: Record<string, ChartMetric[]>): Subgroup[] {
        if (!metrics) return []

        const groupByKeys = Object.keys(metrics).filter(k => k.startsWith('groupby_0|'))
        if (groupByKeys.length === 0) return []

        const groupByKey = groupByKeys.sort((a, b) => b.split('|').length - a.split('|').length)[0]
        const chartMetrics = metrics[groupByKey]
        if (!chartMetrics) return []

        const keyParts = groupByKey.split('|')
        const fieldNames = keyParts.slice(1)

        // Determine subgroup type and field indices based on primary grouping
        if (triageGroupBy.value === 'rule') {
            // Secondary grouping is source/dest pairs
            const sourceIdx = fieldNames.indexOf('source.ip')
            const destIdx = fieldNames.indexOf('destination.ip')

            return chartMetrics.map(metric => {
                const sourceIp = sourceIdx >= 0 && metric.keys[sourceIdx]
                    ? String(metric.keys[sourceIdx]).trim() || '-' : '-'
                const destIp = destIdx >= 0 && metric.keys[destIdx]
                    ? String(metric.keys[destIdx]).trim() || '-' : '-'

                return {
                    key: `${sourceIp}-${destIp}`,
                    label: sourceIp,
                    secondaryLabel: destIp,
                    count: metric.value,
                    type: 'pair' as const
                }
            }).sort((a, b) => b.count - a.count)
        } else {
            // Secondary grouping is by rule name
            const ruleIdx = fieldNames.indexOf('rule.name')
            const severityIdx = fieldNames.indexOf('event.severity_label')

            return chartMetrics.map(metric => {
                const ruleName = ruleIdx >= 0 && metric.keys[ruleIdx]
                    ? String(metric.keys[ruleIdx]).trim() || 'Unknown' : 'Unknown'
                const severity = severityIdx >= 0 && metric.keys[severityIdx]
                    ? String(metric.keys[severityIdx]).trim() || 'unknown' : 'unknown'

                return {
                    key: ruleName,
                    label: ruleName,
                    secondaryLabel: severity,
                    count: metric.value,
                    type: 'rule' as const
                }
            }).sort((a, b) => b.count - a.count)
        }
    }

    // Keep legacy pairs for backwards compatibility
    async function fetchPairs(ruleName: string, loadMore = false): Promise<void> {
        await fetchSubgroups(ruleName, loadMore)
        // Map subgroups to pairs format for backwards compatibility
        pairs.value = subgroups.value
            .filter(s => s.type === 'pair')
            .map(s => ({
                sourceIp: s.label,
                destinationIp: s.secondaryLabel || '-',
                count: s.count
            }))
    }

    // =========================================================================
    // Fetch Individual Alerts
    // =========================================================================

    async function fetchAlerts(ruleName: string, pair?: SourceDestPair | null, loadMore = false): Promise<void> {
        if (loadMore) {
            alertsLoadingMore.value = true
            alertsOffset.value += ALERT_PAGE_SIZE
        } else {
            alertsLoading.value = true
            alertsOffset.value = 0
            alerts.value = []
            hasMoreAlerts.value = true
        }

        alertsError.value = null

        try {
            const escapedRule = ruleName.replace(/"/g, '\\"')
            let query = `${buildBaseQuery()} AND rule.name:"${escapedRule}"`

            if (pair) {
                if (pair.sourceIp && pair.sourceIp !== '-') {
                    query += ` AND source.ip:"${pair.sourceIp}"`
                }
                if (pair.destinationIp && pair.destinationIp !== '-') {
                    query += ` AND destination.ip:"${pair.destinationIp}"`
                }
            }

            const response = await get<EventSearchResponse>('/api/events/', {
                query,
                range: formattedRange.value,
                format: GO_TIME_FORMAT,
                zone: zone.value,
                metricLimit: '0',
                eventLimit: String(ALERT_PAGE_SIZE)
            })

            if (!response) {
                throw new Error('No response from server')
            }

            // Process events
            const newAlerts = processEvents(response.events || [])

            if (loadMore) {
                alerts.value = [...alerts.value, ...newAlerts]
            } else {
                alerts.value = newAlerts
            }

            hasMoreAlerts.value = newAlerts.length === ALERT_PAGE_SIZE
        } catch (e: any) {
            alertsError.value = e.message || 'Failed to fetch alerts'
            console.error('Failed to fetch alerts:', e)
        } finally {
            alertsLoading.value = false
            alertsLoadingMore.value = false
        }
    }

    function processEvents(events: any[]): EventRecord[] {
        return events.map((event, idx) => {
            const payload = event.payload || {}
            return {
                soc_id: event.id || payload['soc_id'] || `event-${idx}`,
                soc_timestamp: event.timestamp || payload['@timestamp'],
                soc_type: event.type || payload['event.module'],
                soc_source: event.source || payload['observer.name'],
                soc_score: payload['event.severity'] || payload['soc_score'],
                ...payload
            }
        })
    }

    // =========================================================================
    // Fetch Alerts for Subgroup (handles different grouping scenarios)
    // =========================================================================

    async function fetchAlertsForSubgroup(
        parentGroupKey: string,
        subgroup: Subgroup,
        loadMore = false
    ): Promise<void> {
        if (loadMore) {
            alertsLoadingMore.value = true
            alertsOffset.value += ALERT_PAGE_SIZE
        } else {
            alertsLoading.value = true
            alertsOffset.value = 0
            alerts.value = []
            hasMoreAlerts.value = true
        }

        alertsError.value = null

        try {
            const escapedParent = parentGroupKey.replace(/"/g, '\\"')
            let query = buildBaseQuery()

            // Build query based on primary grouping and subgroup type
            switch (triageGroupBy.value) {
                case 'source':
                    // Parent is source IP, subgroup is rule name
                    query += ` AND source.ip:"${escapedParent}" AND rule.name:"${subgroup.label.replace(/"/g, '\\"')}"`
                    break
                case 'destination':
                    // Parent is destination IP, subgroup is rule name
                    query += ` AND destination.ip:"${escapedParent}" AND rule.name:"${subgroup.label.replace(/"/g, '\\"')}"`
                    break
                case 'severity':
                    // Parent is severity, subgroup is rule name
                    query += ` AND event.severity_label:"${escapedParent}" AND rule.name:"${subgroup.label.replace(/"/g, '\\"')}"`
                    break
                case 'rule':
                default:
                    // Parent is rule name, subgroup is source/dest pair
                    query += ` AND rule.name:"${escapedParent}"`
                    if (subgroup.label && subgroup.label !== '-') {
                        query += ` AND source.ip:"${subgroup.label.replace(/"/g, '\\"')}"`
                    }
                    if (subgroup.secondaryLabel && subgroup.secondaryLabel !== '-') {
                        query += ` AND destination.ip:"${subgroup.secondaryLabel.replace(/"/g, '\\"')}"`
                    }
                    break
            }

            const response = await get<EventSearchResponse>('/api/events/', {
                query,
                range: formattedRange.value,
                format: GO_TIME_FORMAT,
                zone: zone.value,
                metricLimit: '0',
                eventLimit: String(ALERT_PAGE_SIZE)
            })

            if (!response) {
                throw new Error('No response from server')
            }

            const newAlerts = processEvents(response.events || [])

            if (loadMore) {
                alerts.value = [...alerts.value, ...newAlerts]
            } else {
                alerts.value = newAlerts
            }

            hasMoreAlerts.value = newAlerts.length === ALERT_PAGE_SIZE
        } catch (e: any) {
            alertsError.value = e.message || 'Failed to fetch alerts'
            console.error('Failed to fetch alerts for subgroup:', e)
        } finally {
            alertsLoading.value = false
            alertsLoadingMore.value = false
        }
    }

    // =========================================================================
    // Query Builders for Bulk Actions
    // =========================================================================

    /**
     * Build a search query filter for a primary group
     * Used for bulk acknowledge/escalate at the group level
     */
    function buildGroupQuery(groupKey: string): string {
        const escaped = groupKey.replace(/"/g, '\\"')
        let query = buildBaseQuery()

        switch (triageGroupBy.value) {
            case 'source':
                query += ` AND source.ip:"${escaped}"`
                break
            case 'destination':
                query += ` AND destination.ip:"${escaped}"`
                break
            case 'severity':
                query += ` AND event.severity_label:"${escaped}"`
                break
            case 'rule':
            default:
                query += ` AND rule.name:"${escaped}"`
                break
        }

        return query
    }

    /**
     * Build a search query filter for a subgroup within a group
     * Used for bulk acknowledge/escalate at the subgroup level
     */
    function buildSubgroupQuery(
        parentGroupKey: string,
        subgroup: Subgroup
    ): string {
        const escapedParent = parentGroupKey.replace(/"/g, '\\"')
        let query = buildBaseQuery()

        switch (triageGroupBy.value) {
            case 'source':
                // Parent is source IP, subgroup is rule name
                query += ` AND source.ip:"${escapedParent}" AND rule.name:"${subgroup.label.replace(/"/g, '\\"')}"`
                break
            case 'destination':
                // Parent is destination IP, subgroup is rule name
                query += ` AND destination.ip:"${escapedParent}" AND rule.name:"${subgroup.label.replace(/"/g, '\\"')}"`
                break
            case 'severity':
                // Parent is severity, subgroup is rule name
                query += ` AND event.severity_label:"${escapedParent}" AND rule.name:"${subgroup.label.replace(/"/g, '\\"')}"`
                break
            case 'rule':
            default:
                // Parent is rule name, subgroup is source/dest pair
                query += ` AND rule.name:"${escapedParent}"`
                if (subgroup.label && subgroup.label !== '-') {
                    query += ` AND source.ip:"${subgroup.label.replace(/"/g, '\\"')}"`
                }
                if (subgroup.secondaryLabel && subgroup.secondaryLabel !== '-') {
                    query += ` AND destination.ip:"${subgroup.secondaryLabel.replace(/"/g, '\\"')}"`
                }
                break
        }

        return query
    }

    /**
     * Get a display label for a group (used in escalation case titles)
     */
    function getGroupLabel(groupKey: string): string {
        switch (triageGroupBy.value) {
            case 'source':
                return `Source IP: ${groupKey}`
            case 'destination':
                return `Destination IP: ${groupKey}`
            case 'severity':
                return `Severity: ${groupKey}`
            case 'rule':
            default:
                return groupKey
        }
    }

    /**
     * Get a display label for a subgroup (used in escalation case titles)
     */
    function getSubgroupLabel(parentGroupKey: string, subgroup: Subgroup): string {
        switch (triageGroupBy.value) {
            case 'source':
                return `${subgroup.label} from ${parentGroupKey}`
            case 'destination':
                return `${subgroup.label} to ${parentGroupKey}`
            case 'severity':
                return `${subgroup.label} (${parentGroupKey})`
            case 'rule':
            default:
                return `${parentGroupKey}: ${subgroup.label} → ${subgroup.secondaryLabel || '-'}`
        }
    }

    // =========================================================================
    // Fetch All Alerts (Flat List for Table View)
    // =========================================================================

    const allAlerts = shallowRef<EventRecord[]>([])
    const allAlertsLoading = ref(false)
    const allAlertsLoadingMore = ref(false)
    const allAlertsError = ref<string | null>(null)
    const hasMoreAllAlerts = ref(true)
    const allAlertsOffset = ref(0)

    // Table view sorting
    type TableSortField = 'timestamp' | 'rule' | 'severity' | 'source' | 'destination'
    const tableSortField = ref<TableSortField>('timestamp')
    const tableSortDirection = ref<SortDirection>('desc')

    // Table view grouping
    type TableGroupBy = 'none' | 'rule' | 'severity' | 'source' | 'destination'
    const tableGroupBy = ref<TableGroupBy>('none')

    interface TableGroup {
        key: string
        label: string
        count: number
        alerts: EventRecord[]
        expanded: boolean
    }
    const tableGroups = shallowRef<TableGroup[]>([])

    function setTableSort(field: TableSortField) {
        if (tableSortField.value === field) {
            tableSortDirection.value = tableSortDirection.value === 'asc' ? 'desc' : 'asc'
        } else {
            tableSortField.value = field
            tableSortDirection.value = field === 'timestamp' ? 'desc' : 'asc'
        }
    }

    function setTableGroupBy(groupBy: TableGroupBy) {
        tableGroupBy.value = groupBy
        if (groupBy !== 'none') {
            computeTableGroups()
        }
    }

    function toggleTableGroup(key: string) {
        tableGroups.value = tableGroups.value.map(g =>
            g.key === key ? { ...g, expanded: !g.expanded } : g
        )
    }

    function computeTableGroups() {
        const alerts = allAlerts.value
        if (!alerts.length || tableGroupBy.value === 'none') {
            tableGroups.value = []
            return
        }

        const groupMap = new Map<string, EventRecord[]>()

        for (const alert of alerts) {
            let key: string
            switch (tableGroupBy.value) {
                case 'rule':
                    key = alert['rule.name'] || 'Unknown'
                    break
                case 'severity':
                    key = alert['event.severity_label'] || 'unknown'
                    break
                case 'source':
                    key = alert['source.ip'] || '-'
                    break
                case 'destination':
                    key = alert['destination.ip'] || '-'
                    break
                default:
                    key = 'Unknown'
            }

            if (!groupMap.has(key)) {
                groupMap.set(key, [])
            }
            groupMap.get(key)!.push(alert)
        }

        // Convert to array and sort by count
        const groups: TableGroup[] = Array.from(groupMap.entries())
            .map(([key, alerts]) => ({
                key,
                label: key,
                count: alerts.length,
                alerts,
                expanded: false
            }))
            .sort((a, b) => b.count - a.count)

        tableGroups.value = groups
    }

    // Computed for sorted alerts in table view
    const sortedAllAlerts = computed(() => {
        const alerts = [...allAlerts.value]
        const field = tableSortField.value
        const direction = tableSortDirection.value
        const multiplier = direction === 'asc' ? 1 : -1

        return alerts.sort((a, b) => {
            let aVal: any, bVal: any

            switch (field) {
                case 'timestamp':
                    aVal = a.soc_timestamp || a['@timestamp'] || ''
                    bVal = b.soc_timestamp || b['@timestamp'] || ''
                    break
                case 'rule':
                    aVal = a['rule.name'] || ''
                    bVal = b['rule.name'] || ''
                    break
                case 'severity':
                    aVal = compareSeverity(a['event.severity_label'] || 'unknown', 'unknown')
                    bVal = compareSeverity(b['event.severity_label'] || 'unknown', 'unknown')
                    return (aVal - bVal) * multiplier
                case 'source':
                    aVal = a['source.ip'] || ''
                    bVal = b['source.ip'] || ''
                    break
                case 'destination':
                    aVal = a['destination.ip'] || ''
                    bVal = b['destination.ip'] || ''
                    break
                default:
                    return 0
            }

            if (typeof aVal === 'string') {
                return aVal.localeCompare(bVal) * multiplier
            }
            return (aVal - bVal) * multiplier
        })
    })

    async function fetchAllAlerts(loadMore = false): Promise<void> {
        if (loadMore) {
            allAlertsLoadingMore.value = true
            allAlertsOffset.value += ALERT_PAGE_SIZE
        } else {
            allAlertsLoading.value = true
            allAlertsOffset.value = 0
            allAlerts.value = []
            hasMoreAllAlerts.value = true
        }

        allAlertsError.value = null

        try {
            const query = buildBaseQuery()

            const response = await get<EventSearchResponse>('/api/events/', {
                query,
                range: formattedRange.value,
                format: GO_TIME_FORMAT,
                zone: zone.value,
                metricLimit: '0',
                eventLimit: String(ALERT_PAGE_SIZE)
            })

            if (!response) {
                throw new Error('No response from server')
            }

            // Update total count from response
            totalAlerts.value = response.totalEvents

            const newAlerts = processEvents(response.events || [])

            if (loadMore) {
                allAlerts.value = [...allAlerts.value, ...newAlerts]
            } else {
                allAlerts.value = newAlerts
            }

            hasMoreAllAlerts.value = newAlerts.length === ALERT_PAGE_SIZE
        } catch (e: any) {
            allAlertsError.value = e.message || 'Failed to fetch alerts'
            console.error('Failed to fetch all alerts:', e)
        } finally {
            allAlertsLoading.value = false
            allAlertsLoadingMore.value = false
        }
    }

    // =========================================================================
    // Actions
    // =========================================================================

    function selectPair(pair: SourceDestPair | null): void {
        selectedPair.value = pair
        if (currentRuleName.value) {
            fetchAlerts(currentRuleName.value, pair)
        }
    }

    function clearCache(): void {
        groupsCache.value = null
        pairsCache.value.clear()
    }

    function setSort(field: SortField, direction?: SortDirection): void {
        if (sortField.value === field && !direction) {
            // Toggle direction if clicking same field
            sortDirection.value = sortDirection.value === 'asc' ? 'desc' : 'asc'
        } else {
            sortField.value = field
            sortDirection.value = direction || (field === 'name' ? 'asc' : 'desc')
        }
    }

    function reset(): void {
        alertGroups.value = []
        pairs.value = []
        alerts.value = []
        selectedPair.value = null
        currentRuleName.value = ''
        totalAlerts.value = 0
        hasMoreGroups.value = true
        hasMorePairs.value = true
        hasMoreAlerts.value = true
        groupsOffset.value = 0
        pairsOffset.value = 0
        alertsOffset.value = 0
        clearCache()
    }

    // =========================================================================
    // Return
    // =========================================================================

    return {
        // State - Groups
        alertGroups,
        filteredGroups,
        totalAlerts,
        groupsLoading,
        groupsLoadingMore,
        groupsError,
        hasMoreGroups,

        // State - Filters
        searchQuery,
        acknowledgedFilter,
        severityFilter,

        // State - Sorting
        sortField,
        sortDirection,

        // State - Triage Grouping
        triageGroupBy,
        setTriageGroupBy,

        // State - Detail
        currentRuleName,
        pairs,
        subgroups,
        subgroupsLoading,
        alerts,
        selectedPair,
        pairsLoading,
        pairsLoadingMore,
        pairsError,
        hasMorePairs,
        alertsLoading,
        alertsLoadingMore,
        alertsError,
        hasMoreAlerts,

        // State - All Alerts (Flat List)
        allAlerts,
        sortedAllAlerts,
        allAlertsLoading,
        allAlertsLoadingMore,
        allAlertsError,
        hasMoreAllAlerts,

        // Table View Sorting & Grouping
        tableSortField,
        tableSortDirection,
        tableGroupBy,
        tableGroups,
        setTableSort,
        setTableGroupBy,
        toggleTableGroup,
        computeTableGroups,

        // Methods
        fetchAlertGroups,
        fetchPairs,
        fetchSubgroups,
        fetchAlerts,
        fetchAlertsForSubgroup,
        fetchAllAlerts,
        selectPair,
        setSort,
        clearCache,
        reset,

        // Query Builders for Bulk Actions
        buildGroupQuery,
        buildSubgroupQuery,
        getGroupLabel,
        getSubgroupLabel,

        // Detection Info (AI Summaries)
        fetchDetectionForRule,
        getDetectionInfo,
        isDetectionInfoLoading
    }
}
