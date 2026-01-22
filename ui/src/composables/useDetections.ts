// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

import { ref, shallowRef, computed, watch } from 'vue'
import { useFormatters } from './useFormatters'

// =============================================================================
// Types
// =============================================================================

export interface Detection {
    soc_id: string
    publicId: string
    title: string
    description: string
    severity: string
    engine: string
    author: string
    isEnabled: boolean
    isReporting: boolean
    isCommunity: boolean
    language: string
    ruleset: string
    license: string
    overrideCount: number
    createdAt?: string
    updatedAt?: string
}

interface EventRecord {
    id: string
    payload: Record<string, any>
    sort?: any[]
    [key: string]: any
}

interface EventSearchResponse {
    totalEvents: number
    events: EventRecord[]
}

// =============================================================================
// Constants
// =============================================================================

const PAGE_SIZE = 100

// =============================================================================
// Composable
// =============================================================================

export function useDetections() {
    const { formatDateForApi } = useFormatters()

    // =========================================================================
    // State
    // =========================================================================

    const detections = shallowRef<Detection[]>([])
    const totalEvents = ref(0)
    const loading = ref(false)
    const error = ref<string | null>(null)

    // Stats
    const enabledCount = ref(0)
    const disabledCount = ref(0)

    // Search & Pagination
    const searchQuery = ref('')
    const currentPage = ref(1)
    const pageSize = ref(PAGE_SIZE)

    // Track searchAfter cursors for each page
    const pageCursors = ref<Map<number, any[]>>(new Map())

    // =========================================================================
    // Computed
    // =========================================================================

    const totalPages = computed(() => Math.ceil(totalEvents.value / pageSize.value))

    const hasNextPage = computed(() => currentPage.value < totalPages.value)
    const hasPrevPage = computed(() => currentPage.value > 1)

    // =========================================================================
    // Helpers
    // =========================================================================

    function mapEventToDetection(event: EventRecord): Detection {
        const payload = event.payload || event

        return {
            soc_id: event.id || payload['soc_id'] || '',
            publicId: payload['so_detection.publicId'] || '',
            title: payload['so_detection.title'] || '',
            description: payload['so_detection.description'] || '',
            severity: payload['so_detection.severity'] || 'unknown',
            engine: payload['so_detection.engine'] || '',
            author: payload['so_detection.author'] || '',
            isEnabled: payload['so_detection.isEnabled'] ?? false,
            isReporting: payload['so_detection.isReporting'] ?? false,
            isCommunity: payload['so_detection.isCommunity'] ?? false,
            language: payload['so_detection.language'] || '',
            ruleset: payload['so_detection.ruleset'] || '',
            license: payload['so_detection.license'] || '',
            overrideCount: payload['so_detection.overrides']?.length || 0,
            createdAt: payload['so_detection.createTime'] || event.timestamp || payload['@timestamp'],
            updatedAt: payload['so_detection.updateTime'] || event.timestamp || payload['@timestamp']
        }
    }

    function buildQuery(search: string): string {
        let query = '_index:"*:so-detection" AND so_kind:detection'

        if (search.trim()) {
            // Search across multiple fields
            const escaped = search.trim().replace(/"/g, '\\"')
            query += ` AND (so_detection.title:"*${escaped}*" OR so_detection.description:"*${escaped}*" OR so_detection.publicId:"*${escaped}*" OR so_detection.engine:"*${escaped}*" OR so_detection.author:"*${escaped}*")`
        }

        return query
    }

    // =========================================================================
    // Fetch Stats (enabled/disabled counts)
    // =========================================================================

    async function fetchStats(search: string): Promise<void> {
        const now = new Date()
        const epoch = new Date(0)
        const dateRange = `${formatDateForApi(epoch)} - ${formatDateForApi(now)}`

        // Use groupby to get counts by isEnabled
        const query = `${buildQuery(search)} | groupby so_detection.isEnabled`

        const params = new URLSearchParams({
            query,
            range: dateRange,
            format: '2006/01/02 3:04:05 PM',
            zone: 'Local',
            metricLimit: '10',
            eventLimit: '0'
        })

        try {
            const response = await fetch(`/api/events?${params.toString()}`)
            if (!response.ok) return

            const data = await response.json()

            // Parse metrics to get enabled/disabled counts
            // Metrics come back as: { "groupby_0|so_detection.isEnabled": [{ keys: [true], value: X }, { keys: [false], value: Y }] }
            let enabled = 0
            let disabled = 0

            if (data.metrics) {
                const metricKey = Object.keys(data.metrics).find(k => k.includes('so_detection.isEnabled'))
                if (metricKey && data.metrics[metricKey]) {
                    for (const metric of data.metrics[metricKey]) {
                        const isEnabled = metric.keys?.[0]
                        if (isEnabled === true || isEnabled === 'true') {
                            enabled = metric.value
                        } else if (isEnabled === false || isEnabled === 'false') {
                            disabled = metric.value
                        }
                    }
                }
            }

            enabledCount.value = enabled
            disabledCount.value = disabled
        } catch (err) {
            console.error('Error fetching detection stats:', err)
        }
    }

    // =========================================================================
    // Fetch
    // =========================================================================

    async function fetchPage(page: number, search: string, searchAfter?: any[]): Promise<EventSearchResponse> {
        const now = new Date()
        const epoch = new Date(0)
        const dateRange = `${formatDateForApi(epoch)} - ${formatDateForApi(now)}`

        const params = new URLSearchParams({
            query: buildQuery(search),
            range: dateRange,
            format: '2006/01/02 3:04:05 PM',
            zone: 'Local',
            metricLimit: '0',
            eventLimit: String(pageSize.value)
        })

        if (searchAfter) {
            params.set('searchAfter', JSON.stringify(searchAfter))
        }

        const response = await fetch(`/api/events?${params.toString()}`)

        if (!response.ok) {
            throw new Error(`Failed to fetch detections: ${response.status}`)
        }

        return response.json()
    }

    async function fetchDetections(): Promise<void> {
        loading.value = true
        error.value = null

        try {
            // Get cursor for current page (if not page 1)
            let searchAfter: any[] | undefined
            if (currentPage.value > 1) {
                searchAfter = pageCursors.value.get(currentPage.value - 1)

                // If we don't have the cursor for the previous page, we need to fetch from start
                if (!searchAfter) {
                    // Reset to page 1 if we don't have the cursor chain
                    currentPage.value = 1
                }
            }

            // Fetch page and stats in parallel
            const [result] = await Promise.all([
                fetchPage(currentPage.value, searchQuery.value, searchAfter),
                fetchStats(searchQuery.value)
            ])

            totalEvents.value = result.totalEvents

            const events = result.events || []
            detections.value = events.map(mapEventToDetection)

            // Store cursor for next page
            if (events.length > 0) {
                const lastEvent = events[events.length - 1]
                if (lastEvent.sort) {
                    pageCursors.value.set(currentPage.value, lastEvent.sort)
                }
            }
        } catch (err: any) {
            console.error('Error fetching detections:', err)
            error.value = err.message
            detections.value = []
        } finally {
            loading.value = false
        }
    }

    // =========================================================================
    // Pagination Actions
    // =========================================================================

    async function goToPage(page: number): Promise<void> {
        if (page < 1 || page > totalPages.value) return
        currentPage.value = page
        await fetchDetections()
    }

    async function nextPage(): Promise<void> {
        if (hasNextPage.value) {
            await goToPage(currentPage.value + 1)
        }
    }

    async function prevPage(): Promise<void> {
        if (hasPrevPage.value) {
            await goToPage(currentPage.value - 1)
        }
    }

    async function firstPage(): Promise<void> {
        await goToPage(1)
    }

    // =========================================================================
    // Search
    // =========================================================================

    let searchTimeout: ReturnType<typeof setTimeout> | null = null

    async function search(query: string): Promise<void> {
        searchQuery.value = query

        // Debounce search
        if (searchTimeout) {
            clearTimeout(searchTimeout)
        }

        searchTimeout = setTimeout(async () => {
            // Reset pagination when searching
            currentPage.value = 1
            pageCursors.value.clear()
            await fetchDetections()
        }, 300)
    }

    // =========================================================================
    // Actions
    // =========================================================================

    async function refresh(): Promise<void> {
        pageCursors.value.clear()
        currentPage.value = 1
        await fetchDetections()
    }

    async function toggleEnabled(detection: Detection): Promise<boolean> {
        const previousState = detection.isEnabled
        detection.isEnabled = !detection.isEnabled

        try {
            const response = await fetch(`/api/detection/${detection.soc_id}`)
            if (!response.ok) throw new Error('Failed to fetch detection')

            const fullDetection = await response.json()
            fullDetection.isEnabled = detection.isEnabled

            const updateResponse = await fetch('/api/detection', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(fullDetection)
            })

            if (!updateResponse.ok) {
                throw new Error('Failed to update detection')
            }

            return true
        } catch (err) {
            console.error('Error toggling detection:', err)
            detection.isEnabled = previousState
            return false
        }
    }

    // =========================================================================
    // Return
    // =========================================================================

    return {
        // State
        detections,
        totalEvents,
        loading,
        error,
        searchQuery,

        // Pagination state
        currentPage,
        pageSize,
        totalPages,
        hasNextPage,
        hasPrevPage,

        // Stats (from current page)
        enabledCount,
        disabledCount,

        // Methods
        fetchDetections,
        search,
        refresh,
        toggleEnabled,

        // Pagination methods
        goToPage,
        nextPage,
        prevPage,
        firstPage
    }
}
