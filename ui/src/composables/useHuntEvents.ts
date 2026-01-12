// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

import { ref, computed } from 'vue'
import { useApi } from './useApi'
import { useFormatters } from './useFormatters'
import {
    type EventRecord,
    type EventHeader,
    type SortConfig,
    type EventSearchResponse,
    type GroupByData,
    type ChartMetric,
    type HuntCategory
} from '../types/hunt'

// =============================================================================
// Module-level state
// =============================================================================

const events = ref<EventRecord[]>([])
const headers = ref<EventHeader[]>([])
const groupBys = ref<GroupByData[]>([])
const totalEvents = ref(0)
const fetchTimeSecs = ref(0)
const roundTripTimeSecs = ref(0)

// Pagination
const page = ref(1)
const itemsPerPage = ref(25)
const eventLimit = ref(500)

// Sorting
const sortBy = ref<SortConfig[]>([{ key: 'soc_timestamp', order: 'desc' }])

// Selection (for bulk actions)
const selectedEvents = ref<Set<string>>(new Set())
const selectAllState = ref(false)
const selectAllIndeterminate = ref(false)

// Expanded events
const expandedEvents = ref<Set<string>>(new Set())

// =============================================================================
// Composable
// =============================================================================

export function useHuntEvents() {
    const { get } = useApi()
    const { formatDateForApi } = useFormatters()

    // =========================================================================
    // Computed
    // =========================================================================

    const paginatedEvents = computed(() => {
        const start = (page.value - 1) * itemsPerPage.value
        const end = start + itemsPerPage.value
        return events.value.slice(start, end)
    })

    const totalPages = computed(() => {
        return Math.ceil(events.value.length / itemsPerPage.value)
    })

    const selectedCount = computed(() => selectedEvents.value.size)

    const hasSelection = computed(() => selectedEvents.value.size > 0)

    // =========================================================================
    // Event Data Management
    // =========================================================================

    /**
     * Fetch events from the API
     */
    async function fetchEvents(
        query: string,
        range: string,
        zone: string,
        options: {
            metricLimit?: number
            eventLimit?: number
            gridId?: string
        } = {}
    ): Promise<EventSearchResponse | null> {
        const params: Record<string, string> = {
            query,
            range,
            zone: zone || 'Local',
            metricLimit: String(options.metricLimit ?? 10),
            eventLimit: String(options.eventLimit ?? eventLimit.value)
        }

        if (options.gridId) {
            params.gridId = options.gridId
        }

        try {
            const response = await get<EventSearchResponse>('/api/events/', params)

            if (response) {
                processEventResponse(response)
                return response
            }
        } catch (e) {
            console.error('Failed to fetch events:', e)
        }

        return null
    }

    /**
     * Process API response and populate events
     */
    function processEventResponse(response: EventSearchResponse) {
        totalEvents.value = response.totalEvents || 0
        fetchTimeSecs.value = (response.elapsedMs || 0) / 1000
        roundTripTimeSecs.value = fetchTimeSecs.value

        if (response.events) {
            events.value = response.events.map((event, index) => transformEvent(event, index))
        }

        // Process metrics into groupBys if present
        if (response.metrics) {
            processMetrics(response.metrics)
        }

        // Reset pagination
        page.value = 1
    }

    /**
     * Transform raw event into EventRecord
     */
    function transformEvent(event: any, index: number): EventRecord {
        const payload = event.payload || {}

        return {
            soc_id: event.id || `event-${index}`,
            soc_timestamp: event.timestamp || payload['@timestamp'],
            soc_score: event.score,
            soc_type: event.type || payload['event.module'] || payload['event.dataset'],
            soc_source: event.source || payload['observer.name'],
            _row_idx_: index,
            _isSelected: false,
            ...payload
        }
    }

    /**
     * Process metrics into groupBy data
     */
    function processMetrics(metrics: Record<string, ChartMetric[]>) {
        groupBys.value = []

        for (const [key, data] of Object.entries(metrics)) {
            // Parse the key format: "groupby_N|field1|field2"
            const parts = key.split('|')
            if (parts.length < 2) continue

            const fields = parts.slice(1)
            const title = `Group by ${fields.join(', ')}`

            const records: any[] = data.map((metric, idx) => {
                const record: any = {
                    count: metric.value,
                    _row_idx_: idx
                }
                // Map keys to field names
                fields.forEach((field, i) => {
                    record[field] = metric.keys[i] ?? ''
                })
                return record
            })

            const groupHeaders: EventHeader[] = [
                { title: 'Count', value: 'count', sortable: true },
                ...fields.map(f => ({ title: f, value: f, sortable: true }))
            ]

            groupBys.value.push({
                key,
                title,
                fields,
                data: records,
                headers: groupHeaders,
                chartType: 'table',
                chartMetrics: data,
                chartData: null,
                chartOptions: null,
                sortBy: [{ key: 'count', order: 'desc' }],
                maximized: false,
                isIncomplete: false
            })
        }
    }

    // =========================================================================
    // Header Management
    // =========================================================================

    function setHeaders(newHeaders: EventHeader[]) {
        headers.value = newHeaders
    }

    function addHeader(header: EventHeader) {
        if (!headers.value.find(h => h.value === header.value)) {
            headers.value.push(header)
        }
    }

    function removeHeader(field: string) {
        const idx = headers.value.findIndex(h => h.value === field)
        if (idx >= 0) {
            headers.value.splice(idx, 1)
        }
    }

    function moveHeader(field: string, direction: 'left' | 'right') {
        const idx = headers.value.findIndex(h => h.value === field)
        if (idx < 0) return

        const newIdx = direction === 'left' ? idx - 1 : idx + 1
        if (newIdx < 0 || newIdx >= headers.value.length) return

        const header = headers.value[idx]
        headers.value.splice(idx, 1)
        headers.value.splice(newIdx, 0, header)
    }

    // =========================================================================
    // Sorting
    // =========================================================================

    function toggleSort(column: string) {
        const existing = sortBy.value.find(s => s.key === column)

        if (existing) {
            if (existing.order === 'asc') {
                existing.order = 'desc'
            } else {
                sortBy.value = sortBy.value.filter(s => s.key !== column)
            }
        } else {
            sortBy.value = [{ key: column, order: 'asc' }]
        }

        // Sort events locally
        sortEvents()
    }

    function sortEvents() {
        if (sortBy.value.length === 0) return

        const { key, order } = sortBy.value[0]

        events.value.sort((a, b) => {
            const aVal = a[key] ?? ''
            const bVal = b[key] ?? ''

            // Handle severity sorting specially
            if (key === 'soc_score' || key === 'severity') {
                return sortBySeverity(aVal, bVal, order)
            }

            if (aVal < bVal) return order === 'asc' ? -1 : 1
            if (aVal > bVal) return order === 'asc' ? 1 : -1
            return 0
        })
    }

    function sortBySeverity(a: any, b: any, order: 'asc' | 'desc'): number {
        const severityOrder: Record<string, number> = {
            critical: 4,
            high: 3,
            medium: 2,
            low: 1,
            unknown: 0
        }

        const aScore = typeof a === 'number' ? a : (severityOrder[String(a).toLowerCase()] ?? 0)
        const bScore = typeof b === 'number' ? b : (severityOrder[String(b).toLowerCase()] ?? 0)

        return order === 'asc' ? aScore - bScore : bScore - aScore
    }

    function getSortDirection(column: string): 'asc' | 'desc' | null {
        const sort = sortBy.value.find(s => s.key === column)
        return sort?.order || null
    }

    // =========================================================================
    // Selection
    // =========================================================================

    function toggleSelect(eventId: string) {
        if (selectedEvents.value.has(eventId)) {
            selectedEvents.value.delete(eventId)
        } else {
            selectedEvents.value.add(eventId)
        }
        updateSelectAllState()
    }

    function toggleSelectAll() {
        if (selectAllState.value || selectAllIndeterminate.value) {
            // Clear all
            selectedEvents.value.clear()
            selectAllState.value = false
            selectAllIndeterminate.value = false
        } else {
            // Select all visible
            paginatedEvents.value.forEach(e => {
                selectedEvents.value.add(e.soc_id)
            })
            selectAllState.value = true
            selectAllIndeterminate.value = false
        }
    }

    function updateSelectAllState() {
        const visibleIds = new Set(paginatedEvents.value.map(e => e.soc_id))
        const selectedVisible = [...selectedEvents.value].filter(id => visibleIds.has(id)).length

        if (selectedVisible === 0) {
            selectAllState.value = false
            selectAllIndeterminate.value = false
        } else if (selectedVisible === visibleIds.size) {
            selectAllState.value = true
            selectAllIndeterminate.value = false
        } else {
            selectAllState.value = false
            selectAllIndeterminate.value = true
        }
    }

    function clearSelection() {
        selectedEvents.value.clear()
        selectAllState.value = false
        selectAllIndeterminate.value = false
    }

    function getSelectedItems(): EventRecord[] {
        return events.value.filter(e => selectedEvents.value.has(e.soc_id))
    }

    function isSelected(eventId: string): boolean {
        return selectedEvents.value.has(eventId)
    }

    // =========================================================================
    // Expansion
    // =========================================================================

    function toggleExpand(eventId: string) {
        if (expandedEvents.value.has(eventId)) {
            expandedEvents.value.delete(eventId)
        } else {
            expandedEvents.value.add(eventId)
        }
    }

    function isExpanded(eventId: string): boolean {
        return expandedEvents.value.has(eventId)
    }

    function collapseAll() {
        expandedEvents.value.clear()
    }

    // =========================================================================
    // Event Field Utilities
    // =========================================================================

    function getEventFields(event: EventRecord): { key: string; value: any }[] {
        const fields: { key: string; value: any }[] = []

        for (const [key, value] of Object.entries(event)) {
            if (!key.startsWith('_') && key !== 'soc_id') {
                fields.push({
                    key,
                    value: typeof value === 'object' ? JSON.stringify(value) : value
                })
            }
        }

        return fields.sort((a, b) => a.key.localeCompare(b.key))
    }

    function getFieldValue(event: EventRecord, field: string): any {
        // Support nested field access with dots
        const parts = field.split('.')
        let value: any = event

        for (const part of parts) {
            if (value === null || value === undefined) return undefined
            value = value[part]
        }

        return value
    }

    // =========================================================================
    // Pagination
    // =========================================================================

    function setPage(newPage: number) {
        page.value = Math.max(1, Math.min(newPage, totalPages.value))
    }

    function setItemsPerPage(count: number) {
        itemsPerPage.value = count
        page.value = 1
    }

    function setEventLimit(limit: number) {
        eventLimit.value = limit
    }

    // =========================================================================
    // Reset
    // =========================================================================

    function reset() {
        events.value = []
        groupBys.value = []
        totalEvents.value = 0
        fetchTimeSecs.value = 0
        roundTripTimeSecs.value = 0
        page.value = 1
        selectedEvents.value.clear()
        expandedEvents.value.clear()
        selectAllState.value = false
        selectAllIndeterminate.value = false
    }

    // =========================================================================
    // Local Storage
    // =========================================================================

    function saveToLocalStorage(category: string) {
        const key = `hunt.${category}.events`
        const data = {
            itemsPerPage: itemsPerPage.value,
            eventLimit: eventLimit.value,
            sortBy: sortBy.value
        }
        localStorage.setItem(key, JSON.stringify(data))
    }

    function loadFromLocalStorage(category: string) {
        const key = `hunt.${category}.events`
        const stored = localStorage.getItem(key)

        if (stored) {
            try {
                const data = JSON.parse(stored)
                if (data.itemsPerPage) itemsPerPage.value = data.itemsPerPage
                if (data.eventLimit) eventLimit.value = data.eventLimit
                if (data.sortBy) sortBy.value = data.sortBy
            } catch (e) {
                console.error('Failed to parse event settings:', e)
            }
        }
    }

    return {
        // State
        events,
        headers,
        groupBys,
        totalEvents,
        fetchTimeSecs,
        roundTripTimeSecs,
        page,
        itemsPerPage,
        eventLimit,
        sortBy,
        selectedEvents,
        selectAllState,
        selectAllIndeterminate,
        expandedEvents,

        // Computed
        paginatedEvents,
        totalPages,
        selectedCount,
        hasSelection,

        // Event fetching
        fetchEvents,
        processEventResponse,
        transformEvent,

        // Headers
        setHeaders,
        addHeader,
        removeHeader,
        moveHeader,

        // Sorting
        toggleSort,
        sortEvents,
        getSortDirection,

        // Selection
        toggleSelect,
        toggleSelectAll,
        clearSelection,
        getSelectedItems,
        isSelected,

        // Expansion
        toggleExpand,
        isExpanded,
        collapseAll,

        // Utilities
        getEventFields,
        getFieldValue,

        // Pagination
        setPage,
        setItemsPerPage,
        setEventLimit,

        // Persistence
        saveToLocalStorage,
        loadFromLocalStorage,

        // Reset
        reset
    }
}
