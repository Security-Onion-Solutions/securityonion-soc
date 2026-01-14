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
        if (!searchQuery.value) return alertGroups.value

        const query = searchQuery.value.toLowerCase()
        return alertGroups.value.filter(group =>
            group.ruleName.toLowerCase().includes(query)
        )
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
            // Group by rule.name, event.severity_label (or rule.severity as fallback), and event.module
            const query = `${buildBaseQuery()} | groupby rule.name event.severity_label event.module`

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
        // Keys look like: "groupby_0|rule.name|event.severity_label|event.module"
        const groupByKeys = Object.keys(metrics).filter(k => k.startsWith('groupby_0|'))
        if (groupByKeys.length === 0) return []

        // Sort by number of fields (pipe-separated) and take the longest
        const groupByKey = groupByKeys.sort((a, b) => b.split('|').length - a.split('|').length)[0]

        const chartMetrics = metrics[groupByKey]
        if (!chartMetrics) return []

        // Parse field names from key: "groupby_0|rule.name|event.severity_label|event.module"
        const keyParts = groupByKey.split('|')
        const fieldNames = keyParts.slice(1) // Remove "groupby_0" prefix

        // Find indices for the fields we care about
        const ruleNameIdx = fieldNames.indexOf('rule.name')
        const severityIdx = fieldNames.indexOf('event.severity_label')
        const moduleIdx = fieldNames.indexOf('event.module')

        // Group by rule name and aggregate
        const ruleMap = new Map<string, AlertGroup>()

        for (const metric of chartMetrics) {
            // Extract values, handling empty strings and missing values
            const rawRuleName = ruleNameIdx >= 0 && metric.keys[ruleNameIdx] ? metric.keys[ruleNameIdx] : null
            const rawSeverity = severityIdx >= 0 && metric.keys[severityIdx] ? metric.keys[severityIdx] : null
            const rawModule = moduleIdx >= 0 && metric.keys[moduleIdx] ? metric.keys[moduleIdx] : null

            const ruleName = rawRuleName ? String(rawRuleName).trim() || 'Unknown' : 'Unknown'
            const severity = rawSeverity ? String(rawSeverity).trim().toLowerCase() || 'unknown' : 'unknown'
            const module = rawModule ? String(rawModule).trim() || 'unknown' : 'unknown'

            const existing = ruleMap.get(ruleName)
            if (existing) {
                existing.count += metric.value
                // Keep highest severity
                if (compareSeverity(severity, existing.severity) > 0) {
                    existing.severity = severity
                }
            } else {
                ruleMap.set(ruleName, {
                    ruleName,
                    ruleId: encodeURIComponent(ruleName),
                    count: metric.value,
                    severity,
                    module
                })
            }
        }

        // Sort by count descending
        return Array.from(ruleMap.values()).sort((a, b) => b.count - a.count)
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
    // Fetch Source/Dest Pairs
    // =========================================================================

    async function fetchPairs(ruleName: string, loadMore = false): Promise<void> {
        currentRuleName.value = ruleName

        if (loadMore) {
            pairsLoadingMore.value = true
            pairsOffset.value += PAIR_PAGE_SIZE
        } else {
            pairsLoading.value = true
            pairsOffset.value = 0
            pairs.value = []
            hasMorePairs.value = true

            // Check cache
            const cached = pairsCache.value.get(ruleName)
            if (cached) {
                pairs.value = cached
                pairsLoading.value = false
                return
            }
        }

        pairsError.value = null

        try {
            const escapedRule = ruleName.replace(/"/g, '\\"')
            const query = `${buildBaseQuery()} AND rule.name:"${escapedRule}" | groupby source.ip destination.ip`

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

            const newPairs = processPairMetrics(response.metrics)

            if (loadMore) {
                pairs.value = [...pairs.value, ...newPairs]
            } else {
                pairs.value = newPairs
                pairsCache.value.set(ruleName, newPairs)
            }

            hasMorePairs.value = newPairs.length === PAIR_PAGE_SIZE
        } catch (e: any) {
            pairsError.value = e.message || 'Failed to fetch source/dest pairs'
            console.error('Failed to fetch pairs:', e)
        } finally {
            pairsLoading.value = false
            pairsLoadingMore.value = false
        }
    }

    function processPairMetrics(metrics?: Record<string, ChartMetric[]>): SourceDestPair[] {
        if (!metrics) return []

        // Find the longest groupby_0 key (contains all fields)
        const groupByKeys = Object.keys(metrics).filter(k => k.startsWith('groupby_0|'))
        if (groupByKeys.length === 0) return []

        const groupByKey = groupByKeys.sort((a, b) => b.split('|').length - a.split('|').length)[0]

        const chartMetrics = metrics[groupByKey]
        if (!chartMetrics) return []

        // Parse field names from key: "groupby_0|source.ip|destination.ip"
        const keyParts = groupByKey.split('|')
        const fieldNames = keyParts.slice(1)

        const sourceIdx = fieldNames.indexOf('source.ip')
        const destIdx = fieldNames.indexOf('destination.ip')

        return chartMetrics.map(metric => {
            const rawSource = sourceIdx >= 0 && metric.keys[sourceIdx] ? metric.keys[sourceIdx] : null
            const rawDest = destIdx >= 0 && metric.keys[destIdx] ? metric.keys[destIdx] : null

            return {
                sourceIp: rawSource ? String(rawSource).trim() || '-' : '-',
                destinationIp: rawDest ? String(rawDest).trim() || '-' : '-',
                count: metric.value
            }
        }).sort((a, b) => b.count - a.count)
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

        // State - Detail
        currentRuleName,
        pairs,
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

        // Methods
        fetchAlertGroups,
        fetchPairs,
        fetchAlerts,
        selectPair,
        clearCache,
        reset
    }
}
