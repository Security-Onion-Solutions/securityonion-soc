<script setup lang="ts">
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

import { ref, computed, onMounted, onUnmounted, watch } from 'vue'
import {
    Search,
    RefreshCw,
    ChevronDown,
    ChevronRight,
    Clock,
    Filter,
    X,
    Play,
    Settings2,
    Table,
    BarChart3,
    AlertTriangle,
    CheckCircle2,
    XCircle,
    Loader2,
    Eye,
    EyeOff,
    PanelRightOpen,
    PanelRightClose,
    Bot,
    MessageSquare
} from 'lucide-vue-next'
import { cn } from '../lib/utils'
import { useApi } from '../composables/useApi'
import { useFormatters } from '../composables/useFormatters'
import { useStatusStyles } from '../composables/useStatusStyles'
import { useTimeRange, RELATIVE_TIME_UNITS, AUTO_REFRESH_OPTIONS } from '../composables/useTimeRange'
import { useHuntQuery } from '../composables/useHuntQuery'
import { useHuntActions } from '../composables/useHuntActions'
import { useHuntParams } from '../composables/useHuntParams'
import { useChatWidget } from '../composables/useChatWidget'
import QuickActionMenu from '../components/hunt/QuickActionMenu.vue'
import AlertActions from '../components/hunt/AlertActions.vue'
import EscalationMenu from '../components/hunt/EscalationMenu.vue'
import PlaybookPanel from '../components/hunt/PlaybookPanel.vue'
import BulkActions from '../components/hunt/BulkActions.vue'
import {
    type HuntCategory,
    type CategoryConfig,
    type EventRecord,
    type EventHeader,
    type SortConfig,
    type EventSearchResponse,
    type FilterMode,
    type ActionConfig,
    type GroupByData,
    type ChartMetric,
    RELATIVE_TIME_HOURS,
    FILTER_INCLUDE
} from '../types/hunt'

// =============================================================================
// Props & Emits
// =============================================================================

const props = defineProps<{
    category: HuntCategory
    initialQuery?: string | null
}>()

const emit = defineEmits<{
    'view-event-detail': [eventId: string]
}>()

// =============================================================================
// Composables
// =============================================================================

const { get, loading: apiLoading, error: apiError } = useApi()
const { formatDate, formatRelativeTime } = useFormatters()
const { getSeverityStyles } = useStatusStyles()

const {
    isRelativeTime,
    relativeTimeValue,
    relativeTimeUnit,
    dateRange,
    zone,
    autoRefreshInterval,
    formattedRange,
    rangeDescription,
    setRelativeTime,
    setAbsoluteTime,
    setEpochTime,
    startAutoRefresh,
    stopAutoRefresh,
    setAutoRefreshInterval,
    loadFromLocalStorage: loadTimeSettings,
    saveToLocalStorage: saveTimeSettings
} = useTimeRange()

const {
    query,
    queryFilters,
    queryGroupBys,
    querySortBys,
    parsedQuery,
    isComplexQuery,
    mruQueries,
    setQuery,
    addFilter,
    removeFilter,
    addGroupBy,
    removeGroupBy,
    addSortBy,
    removeSortBy,
    addMruQuery,
    buildEffectiveQuery,
    loadFromLocalStorage: loadQuerySettings,
    saveToLocalStorage: saveQuerySettings
} = useHuntQuery()

const {
    acknowledgeEvent,
    escalateToNewCase,
    addToCase,
    startInvestigation
} = useHuntActions()

const {
    fetchParams,
    filterVisibleFields,
    constructHeaders: buildHeadersFromFields,
    extractModuleDataset,
    loaded: paramsLoaded
} = useHuntParams()

const { openWithPrompt } = useChatWidget()

// =============================================================================
// Category Configuration
// =============================================================================

const categoryConfig = computed<CategoryConfig>(() => {
    switch (props.category) {
        case 'hunt':
            return {
                defaultQuery: '*',
                queryBaseFilter: '',
                showTimeRange: true,
                useEpochTime: false,
                showMetrics: true,
                showEvents: true,
                showDetailsPanel: false,
                showPlaybooks: false,
                ackEnabled: false,
                escalateEnabled: false,
                investigateEnabled: false,
                multiSelectEnabled: false,
                aggregationActionsEnabled: false,
                showManualSync: false,
                huntButtonLabel: 'Hunt',
                eventsLabel: 'Events'
            }
        case 'alerts':
            return {
                defaultQuery: 'tags:alert',
                queryBaseFilter: '',
                showTimeRange: true,
                useEpochTime: false,
                showMetrics: true,
                showEvents: true,
                showDetailsPanel: true,
                showPlaybooks: true,
                ackEnabled: true,
                escalateEnabled: true,
                investigateEnabled: true,
                multiSelectEnabled: false,
                aggregationActionsEnabled: true,
                showManualSync: false,
                huntButtonLabel: 'Refresh',
                eventsLabel: 'Alerts'
            }
        case 'detections':
            return {
                defaultQuery: '*',
                queryBaseFilter: '',
                showTimeRange: false,
                useEpochTime: true,
                showMetrics: false,
                showEvents: true,
                showDetailsPanel: false,
                showPlaybooks: false,
                ackEnabled: false,
                escalateEnabled: false,
                investigateEnabled: false,
                multiSelectEnabled: true,
                aggregationActionsEnabled: false,
                showManualSync: true,
                huntButtonLabel: 'Refresh',
                eventsLabel: 'Detections'
            }
        default:
            return {
                defaultQuery: '*',
                queryBaseFilter: '',
                showTimeRange: true,
                useEpochTime: false,
                showMetrics: true,
                showEvents: true,
                showDetailsPanel: false,
                showPlaybooks: false,
                ackEnabled: false,
                escalateEnabled: false,
                investigateEnabled: false,
                multiSelectEnabled: false,
                aggregationActionsEnabled: false,
                showManualSync: false,
                huntButtonLabel: 'Hunt',
                eventsLabel: 'Events'
            }
    }
})

// =============================================================================
// State
// =============================================================================

const loaded = ref(false)
const hunting = ref(false)
const autohunt = ref(true)
const showOptions = ref(false)
const showQueryDropdown = ref(false)

// Results
const events = ref<EventRecord[]>([])
const groupBys = ref<GroupByData[]>([])
const totalEvents = ref(0)
const fetchTimeSecs = ref(0)
const roundTripTimeSecs = ref(0)

// Table state - headers will be populated dynamically based on eventFields config
const headers = ref<EventHeader[]>([])
const defaultHeaders: EventHeader[] = [
    { title: 'Timestamp', value: 'soc_timestamp', sortable: true },
    { title: 'Type', value: 'soc_type', sortable: true },
    { title: 'Source', value: 'soc_source', sortable: true }
]
const sortBy = ref<SortConfig[]>([{ key: 'soc_timestamp', order: 'desc' }])
const itemsPerPage = ref(25)
const currentPage = ref(1)
const expandedEvents = ref<string[]>([])

// Items per page options
const itemsPerPageOptions = [10, 25, 50, 100, 200, 500]

// Quick action menu state
const quickActionVisible = ref(false)
const quickActionX = ref(0)
const quickActionY = ref(0)
const quickActionField = ref('')
const quickActionValue = ref<any>(null)
const quickActionIsNumeric = ref(false)

// Escalation menu state
const escalationMenuVisible = ref(false)
const escalationMenuX = ref(0)
const escalationMenuY = ref(0)
const escalationMenuEvent = ref<EventRecord | null>(null)

// Details panel state
const showDetailsPanel = ref(false)
const selectedEvent = ref<EventRecord | null>(null)

// Multi-select state (for detections)
const selectedEventIds = ref<Set<string>>(new Set())
const actionLoading = ref(false)

// AI Assistant state
const aiEnabled = ref(true) // TODO: Check license for AI features

// =============================================================================
// Computed
// =============================================================================

const paginatedEvents = computed(() => {
    const start = (currentPage.value - 1) * itemsPerPage.value
    const end = start + itemsPerPage.value
    return events.value.slice(start, end)
})

const totalPages = computed(() => {
    return Math.ceil(events.value.length / itemsPerPage.value)
})

const hasFilters = computed(() => {
    return queryFilters.value.length > 0 || queryGroupBys.value.length > 0 || querySortBys.value.length > 0
})

// Selection state for bulk actions
const selectedCount = computed(() => selectedEventIds.value.size)

const selectAllState = computed(() => {
    if (events.value.length === 0) return false
    return selectedEventIds.value.size === events.value.length
})

const selectAllIndeterminate = computed(() => {
    return selectedEventIds.value.size > 0 && selectedEventIds.value.size < events.value.length
})

const selectedEvents = computed(() => {
    return events.value.filter(e => selectedEventIds.value.has(e.soc_id))
})

// =============================================================================
// Methods
// =============================================================================

async function hunt() {
    if (hunting.value) return

    hunting.value = true
    currentPage.value = 1

    try {
        const effectiveQuery = buildEffectiveQuery() || categoryConfig.value.defaultQuery
        const range = formattedRange.value

        const params: Record<string, string> = {
            query: effectiveQuery,
            range: range,
            format: '2006/01/02 3:04:05 PM', // Go reference time format
            zone: zone.value || 'Local',
            metricLimit: categoryConfig.value.showMetrics ? '10' : '0',
            eventLimit: '500'
        }

        const response = await get<EventSearchResponse>('/api/events/', params)

        if (response) {
            totalEvents.value = response.totalEvents || 0
            fetchTimeSecs.value = (response.elapsedMs || 0) / 1000
            roundTripTimeSecs.value = fetchTimeSecs.value

            // Process events
            if (response.events) {
                events.value = response.events.map((event, index) => ({
                    ...event,
                    soc_id: event.id || `event-${index}`,
                    soc_timestamp: event.timestamp || event.payload?.['@timestamp'],
                    soc_type: event.type || event.payload?.['event.module'],
                    soc_source: event.source || event.payload?.['observer.name'],
                    _row_idx_: index,
                    ...event.payload
                }))
            }

            // Process metrics for groupby results
            if (response.metrics) {
                processMetrics(response.metrics)
            } else {
                groupBys.value = []
            }

            // Update table headers based on event module/dataset
            updateHeadersFromEvents(events.value)

            // Add to MRU
            if (query.value && query.value !== '*' && query.value !== categoryConfig.value.defaultQuery) {
                addMruQuery(query.value)
            }

            loaded.value = true
        }
    } catch (e) {
        console.error('Hunt failed:', e)
    } finally {
        hunting.value = false
    }
}

function handleQuerySubmit() {
    hunt()
}

function handleQueryKeydown(e: KeyboardEvent) {
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault()
        hunt()
    }
}

function toggleEventExpand(eventId: string) {
    const idx = expandedEvents.value.indexOf(eventId)
    if (idx >= 0) {
        expandedEvents.value.splice(idx, 1)
    } else {
        expandedEvents.value.push(eventId)
    }
}

function isEventExpanded(eventId: string): boolean {
    return expandedEvents.value.includes(eventId)
}

function handleRemoveFilter(filter: string) {
    removeFilter(filter)
    if (autohunt.value) hunt()
}

function handleRemoveGroupBy(groupIdx: number, fieldIdx?: number) {
    removeGroupBy(groupIdx, fieldIdx)
    if (autohunt.value) hunt()
}

function handleRemoveSortBy(sortByField: string) {
    removeSortBy(sortByField)
    if (autohunt.value) hunt()
}

function handleSort(column: string) {
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
    const col = column
    const order = sortBy.value.find(s => s.key === col)?.order || 'asc'
    events.value.sort((a, b) => {
        const aVal = a[col] ?? ''
        const bVal = b[col] ?? ''
        if (aVal < bVal) return order === 'asc' ? -1 : 1
        if (aVal > bVal) return order === 'asc' ? 1 : -1
        return 0
    })
}

function getSortDirection(column: string): 'asc' | 'desc' | null {
    const sort = sortBy.value.find(s => s.key === column)
    return sort?.order || null
}

function getEventFields(event: EventRecord): { key: string; value: any }[] {
    const fields: { key: string; value: any }[] = []
    for (const [key, value] of Object.entries(event)) {
        if (!key.startsWith('_') && key !== 'soc_id') {
            fields.push({ key, value: typeof value === 'object' ? JSON.stringify(value) : value })
        }
    }
    return fields.sort((a, b) => a.key.localeCompare(b.key))
}

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

/**
 * Update table headers based on event module/dataset from results
 * Uses the eventFields configuration from server to determine which fields to show
 */
function updateHeadersFromEvents(eventList: EventRecord[]) {
    if (!paramsLoaded.value || eventList.length === 0) {
        // Fall back to default headers if params not loaded or no events
        headers.value = [...defaultHeaders]
        return
    }

    // Extract module and dataset from first event
    const { module: eventModule, dataset: eventDataset } = extractModuleDataset(eventList)

    // Get all field keys from first event as fallback
    const fallbackFields = Object.keys(eventList[0]).filter(k => !k.startsWith('_'))

    // Filter to configured fields based on module/dataset
    const visibleFields = filterVisibleFields(
        props.category,
        eventModule,
        eventDataset,
        fallbackFields
    )

    // Build headers from the filtered fields
    if (visibleFields.length > 0) {
        headers.value = buildHeadersFromFields(visibleFields)
    } else {
        headers.value = [...defaultHeaders]
    }
}

function selectMruQuery(q: string) {
    setQuery(q)
    showQueryDropdown.value = false
    if (autohunt.value) hunt()
}

// Quick Action Handlers
function showQuickAction(e: MouseEvent, field: string, value: any) {
    e.preventDefault()
    e.stopPropagation()
    quickActionField.value = field
    quickActionValue.value = value
    quickActionX.value = e.clientX
    quickActionY.value = e.clientY
    quickActionIsNumeric.value = typeof value === 'number' || !isNaN(Number(value))
    quickActionVisible.value = true
}

function closeQuickAction() {
    quickActionVisible.value = false
}

async function handleQuickFilter(field: string, value: any, mode: FilterMode) {
    await addFilter(field, value, mode)
    if (autohunt.value) hunt()
}

async function handleQuickGroupBy(field: string) {
    await addGroupBy(field)
    if (autohunt.value) hunt()
}

async function handleQuickGroupByNew(field: string) {
    await addGroupBy(field, 0)
    if (autohunt.value) hunt()
}

// Alert Action Handlers
async function handleAcknowledge(event: EventRecord, acknowledge: boolean) {
    actionLoading.value = true
    try {
        const success = await acknowledgeEvent(event, acknowledge, {
            dateRange: formattedRange.value,
            timezone: zone.value
        })
        if (success) {
            // Update event in local state
            const idx = events.value.findIndex(e => e.soc_id === event.soc_id)
            if (idx >= 0) {
                events.value[idx]['event.acknowledged'] = acknowledge
            }
        }
    } finally {
        actionLoading.value = false
    }
}

function handleEscalate(event: EventRecord, mouseEvent: MouseEvent) {
    escalationMenuEvent.value = event
    escalationMenuX.value = mouseEvent.clientX
    escalationMenuY.value = mouseEvent.clientY
    escalationMenuVisible.value = true
}

function closeEscalationMenu() {
    escalationMenuVisible.value = false
    escalationMenuEvent.value = null
}

async function handleCreateNewCase(event: EventRecord, includeRelated: boolean) {
    actionLoading.value = true
    try {
        const caseId = await escalateToNewCase(event, { includeRelated })
        if (caseId) {
            // Update event in local state
            const idx = events.value.findIndex(e => e.soc_id === event.soc_id)
            if (idx >= 0) {
                events.value[idx]['event.escalated'] = true
                events.value[idx]['so_case.id'] = caseId
            }
        }
    } finally {
        actionLoading.value = false
    }
}

async function handleAddToExistingCase(event: EventRecord, caseId: string, includeRelated: boolean) {
    actionLoading.value = true
    try {
        const success = await addToCase(event, caseId, { includeRelated })
        if (success) {
            // Update event in local state
            const idx = events.value.findIndex(e => e.soc_id === event.soc_id)
            if (idx >= 0) {
                events.value[idx]['event.escalated'] = true
                events.value[idx]['so_case.id'] = caseId
            }
        }
    } finally {
        actionLoading.value = false
    }
}

async function handleInvestigate(event: EventRecord) {
    await startInvestigation(event, (sessionId) => {
        // Navigate to assistant with session ID
        window.location.href = `/modern/assistant?session=${sessionId}`
    })
}

function handleViewInfo(event: EventRecord) {
    selectedEvent.value = event
    showDetailsPanel.value = true
}

function closeDetailsPanel() {
    showDetailsPanel.value = false
}

function askAiAboutEvent(event: EventRecord) {
    // Build a summary of the event for the AI
    const ruleName = event['rule.name'] || event['event.module'] || event.soc_type || 'event'
    const sourceIp = event['source.ip'] || ''
    const destIp = event['destination.ip'] || ''
    const timestamp = event.soc_timestamp || ''

    let prompt = `Tell me about this ${ruleName}`
    if (sourceIp || destIp) {
        prompt += ` involving`
        if (sourceIp) prompt += ` source ${sourceIp}`
        if (sourceIp && destIp) prompt += ` and`
        if (destIp) prompt += ` destination ${destIp}`
    }
    if (timestamp) {
        prompt += ` at ${timestamp}`
    }
    prompt += `. What should I know about this event?`

    // Open chat widget with the prompt
    openWithPrompt(prompt)
}

function askAiAboutField(field: string, value: any) {
    const displayValue = value === null || value === undefined ? 'null' : String(value)
    const prompt = `Tell me about ${field}: ${displayValue}. What does this value mean in a security context and what should I know about it?`
    openWithPrompt(prompt)
}

// Selection Handlers (for detections bulk actions)
function toggleEventSelect(eventId: string) {
    if (selectedEventIds.value.has(eventId)) {
        selectedEventIds.value.delete(eventId)
    } else {
        selectedEventIds.value.add(eventId)
    }
    // Force reactivity
    selectedEventIds.value = new Set(selectedEventIds.value)
}

function toggleSelectAll() {
    if (selectAllState.value) {
        // Deselect all
        selectedEventIds.value.clear()
    } else {
        // Select all
        events.value.forEach(e => selectedEventIds.value.add(e.soc_id))
    }
    selectedEventIds.value = new Set(selectedEventIds.value)
}

function clearSelection() {
    selectedEventIds.value.clear()
    selectedEventIds.value = new Set(selectedEventIds.value)
}

async function handleBulkEnable() {
    actionLoading.value = true
    try {
        // Bulk enable detections
        console.log('Bulk enable:', selectedEvents.value.map(e => e.soc_id))
        // Implementation would call detection enable API
    } finally {
        actionLoading.value = false
        clearSelection()
    }
}

async function handleBulkDisable() {
    actionLoading.value = true
    try {
        // Bulk disable detections
        console.log('Bulk disable:', selectedEvents.value.map(e => e.soc_id))
        // Implementation would call detection disable API
    } finally {
        actionLoading.value = false
        clearSelection()
    }
}

async function handleBulkDelete() {
    actionLoading.value = true
    try {
        // Bulk delete detections
        console.log('Bulk delete:', selectedEvents.value.map(e => e.soc_id))
        // Implementation would call detection delete API
    } finally {
        actionLoading.value = false
        clearSelection()
    }
}

// Playbook Handlers
function handlePlaybookHuntQuery(query: string, range: string) {
    setQuery(query)
    if (range) {
        // Parse and set the range
        // For now, just use relative time
    }
    hunt()
}

// =============================================================================
// Lifecycle
// =============================================================================

onMounted(async () => {
    // Fetch hunt parameters (eventFields config) from server
    await fetchParams()

    // Load saved settings
    loadTimeSettings(props.category)
    loadQuerySettings(props.category)

    // Set default query for category
    if (!query.value) {
        setQuery(categoryConfig.value.defaultQuery)
    }

    // Handle epoch time for detections
    if (categoryConfig.value.useEpochTime) {
        setEpochTime()
    }

    // Set default headers initially
    headers.value = [...defaultHeaders]

    // Auto-hunt on mount
    hunt()

    // Start auto-refresh if enabled
    if (autoRefreshInterval.value > 0) {
        startAutoRefresh(hunt)
    }
})

onUnmounted(() => {
    stopAutoRefresh()
    saveTimeSettings(props.category)
    saveQuerySettings(props.category)
})

// Watch for initialQuery changes (navigation from AI chat)
watch(() => props.initialQuery, (newQuery) => {
    if (newQuery) {
        setQuery(newQuery)
        hunt()
    }
}, { immediate: true })

// Watch for auto-refresh changes
watch(autoRefreshInterval, (newVal) => {
    if (newVal > 0) {
        startAutoRefresh(hunt)
    } else {
        stopAutoRefresh()
    }
})
</script>

<template>
    <div class="space-y-6 animate-in fade-in duration-500">
        <!-- Header -->
        <div class="flex items-center justify-between">
            <div>
                <h2 class="text-3xl font-bold tracking-tight capitalize">{{ category }}</h2>
                <p class="text-muted-foreground">
                    <span v-if="loaded">
                        Found {{ totalEvents.toLocaleString() }} {{ categoryConfig.eventsLabel.toLowerCase() }}
                        <span v-if="fetchTimeSecs > 0" class="text-xs">
                            ({{ fetchTimeSecs.toFixed(2) }}s)
                        </span>
                    </span>
                    <span v-else>Search and analyze security events.</span>
                </p>
            </div>
            <div class="flex items-center gap-2">
                <!-- Details Panel Toggle (alerts only) -->
                <button
                    v-if="categoryConfig.showDetailsPanel"
                    @click="showDetailsPanel = !showDetailsPanel"
                    :class="cn(
                        'p-2 rounded-md transition-colors',
                        showDetailsPanel ? 'bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-muted'
                    )"
                    :title="showDetailsPanel ? 'Hide details panel' : 'Show details panel'"
                >
                    <PanelRightClose v-if="showDetailsPanel" class="h-5 w-5" />
                    <PanelRightOpen v-else class="h-5 w-5" />
                </button>

                <!-- Options Toggle -->
                <button
                    @click="showOptions = !showOptions"
                    :class="cn(
                        'p-2 rounded-md transition-colors',
                        showOptions ? 'bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-muted'
                    )"
                >
                    <Settings2 class="h-5 w-5" />
                </button>

                <!-- Hunt Button -->
                <button
                    @click="hunt"
                    :disabled="hunting"
                    :class="cn(
                        'flex items-center gap-2 px-4 py-2 rounded-md font-medium transition-colors',
                        'bg-primary text-primary-foreground hover:bg-primary/90',
                        'disabled:opacity-50 disabled:cursor-not-allowed'
                    )"
                >
                    <Loader2 v-if="hunting" class="h-4 w-4 animate-spin" />
                    <Play v-else class="h-4 w-4" />
                    {{ categoryConfig.huntButtonLabel }}
                </button>
            </div>
        </div>

        <!-- Options Panel -->
        <div v-if="showOptions" class="p-4 rounded-lg bg-card border border-border space-y-4">
            <div class="flex flex-wrap items-center gap-4">
                <!-- Auto-hunt Toggle -->
                <label class="flex items-center gap-2 cursor-pointer">
                    <input
                        type="checkbox"
                        v-model="autohunt"
                        class="rounded border-border"
                    />
                    <span class="text-sm">Auto-hunt on change</span>
                </label>

                <!-- Auto-refresh -->
                <div class="flex items-center gap-2">
                    <span class="text-sm text-muted-foreground">Auto-refresh:</span>
                    <select
                        v-model="autoRefreshInterval"
                        @change="setAutoRefreshInterval(autoRefreshInterval)"
                        class="text-sm bg-muted border-0 rounded-md px-2 py-1"
                    >
                        <option v-for="opt in AUTO_REFRESH_OPTIONS" :key="opt.value" :value="opt.value">
                            {{ opt.label }}
                        </option>
                    </select>
                </div>
            </div>
        </div>

        <!-- Query Bar -->
        <div class="space-y-3">
            <div class="flex gap-2">
                <!-- Query Input -->
                <div class="flex-1 relative">
                    <div class="flex">
                        <div class="flex-1 relative">
                            <Search class="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                            <input
                                v-model="query"
                                @keydown="handleQueryKeydown"
                                type="text"
                                placeholder="Enter search query..."
                                class="w-full pl-10 pr-4 py-2 rounded-l-md border border-border bg-background focus:outline-none focus:ring-2 focus:ring-primary/50"
                            />
                        </div>
                        <button
                            @click="showQueryDropdown = !showQueryDropdown"
                            class="px-3 border-y border-r border-border rounded-r-md bg-muted hover:bg-muted/80 transition-colors"
                        >
                            <ChevronDown class="h-4 w-4" />
                        </button>
                    </div>

                    <!-- Query Dropdown -->
                    <div
                        v-if="showQueryDropdown && mruQueries.length > 0"
                        class="absolute top-full left-0 right-0 mt-1 bg-card border border-border rounded-md shadow-lg z-50 max-h-60 overflow-auto"
                    >
                        <div class="p-2 text-xs text-muted-foreground border-b border-border">
                            Recent Queries
                        </div>
                        <button
                            v-for="(q, idx) in mruQueries"
                            :key="idx"
                            @click="selectMruQuery(q)"
                            class="w-full text-left px-3 py-2 text-sm hover:bg-muted transition-colors truncate"
                        >
                            {{ q }}
                        </button>
                    </div>
                </div>

                <!-- Time Range (if enabled) -->
                <div v-if="categoryConfig.showTimeRange" class="flex items-center gap-2">
                    <Clock class="h-4 w-4 text-muted-foreground" />
                    <select
                        v-model="relativeTimeValue"
                        class="text-sm bg-muted border-0 rounded-md px-2 py-2"
                    >
                        <option v-for="n in [1, 5, 15, 30, 60]" :key="n" :value="n">{{ n }}</option>
                    </select>
                    <select
                        v-model="relativeTimeUnit"
                        class="text-sm bg-muted border-0 rounded-md px-2 py-2"
                    >
                        <option v-for="unit in RELATIVE_TIME_UNITS" :key="unit.value" :value="unit.value">
                            {{ unit.label }}
                        </option>
                    </select>
                </div>
            </div>

            <!-- Filter Chips -->
            <div v-if="hasFilters" class="flex flex-wrap gap-2">
                <!-- Query Filters -->
                <div
                    v-for="(filter, idx) in queryFilters"
                    :key="'filter-' + idx"
                    class="flex items-center gap-1 px-2 py-1 rounded-full bg-blue-500/10 text-blue-500 text-xs"
                >
                    <Filter class="h-3 w-3" />
                    <span class="max-w-[200px] truncate">{{ filter }}</span>
                    <button @click="handleRemoveFilter(filter)" class="hover:text-blue-700">
                        <X class="h-3 w-3" />
                    </button>
                </div>

                <!-- GroupBy Chips -->
                <div
                    v-for="(group, groupIdx) in queryGroupBys"
                    :key="'group-' + groupIdx"
                    class="flex items-center gap-1 px-2 py-1 rounded-full bg-purple-500/10 text-purple-500 text-xs"
                >
                    <BarChart3 class="h-3 w-3" />
                    <span>groupby {{ group.fields.join(', ') }}</span>
                    <button @click="handleRemoveGroupBy(groupIdx)" class="hover:text-purple-700">
                        <X class="h-3 w-3" />
                    </button>
                </div>

                <!-- SortBy Chips -->
                <div
                    v-for="(sortByField, idx) in querySortBys"
                    :key="'sort-' + idx"
                    class="flex items-center gap-1 px-2 py-1 rounded-full bg-green-500/10 text-green-500 text-xs"
                >
                    <Table class="h-3 w-3" />
                    <span>sortby {{ sortByField }}</span>
                    <button @click="handleRemoveSortBy(sortByField)" class="hover:text-green-700">
                        <X class="h-3 w-3" />
                    </button>
                </div>
            </div>
        </div>

        <!-- Loading State -->
        <div v-if="hunting && !loaded" class="flex items-center justify-center py-20">
            <div class="text-center">
                <Loader2 class="h-8 w-8 animate-spin text-primary mx-auto mb-4" />
                <p class="text-muted-foreground">Searching...</p>
            </div>
        </div>

        <!-- Error State -->
        <div v-else-if="apiError" class="p-6 rounded-lg bg-destructive/10 border border-destructive/20">
            <div class="flex items-center gap-2 text-destructive">
                <AlertTriangle class="h-5 w-5" />
                <span class="font-medium">Search failed</span>
            </div>
            <p class="mt-2 text-sm text-muted-foreground">{{ apiError }}</p>
        </div>

        <!-- Results -->
        <div v-else-if="loaded" class="flex gap-4">
            <!-- Main Content Area -->
            <div :class="cn('flex-1 space-y-4', showDetailsPanel && 'max-w-[calc(100%-380px)]')">
                <!-- Bulk Actions (detections only) -->
                <BulkActions
                    v-if="categoryConfig.multiSelectEnabled"
                    :selected-count="selectedCount"
                    :total-count="events.length"
                    :select-all-state="selectAllState"
                    :select-all-indeterminate="selectAllIndeterminate"
                    :loading="actionLoading"
                    @toggle-select-all="toggleSelectAll"
                    @clear-selection="clearSelection"
                    @bulk-enable="handleBulkEnable"
                    @bulk-disable="handleBulkDisable"
                    @bulk-delete="handleBulkDelete"
                />

                <!-- GroupBy Results -->
                <div v-if="groupBys.length > 0" class="space-y-4">
                    <div
                        v-for="(group, groupIdx) in groupBys"
                        :key="group.key"
                        class="rounded-xl border border-border bg-card overflow-hidden"
                    >
                        <!-- Group Header -->
                        <div class="flex items-center justify-between px-4 py-3 border-b border-border bg-muted/50">
                            <div class="flex items-center gap-2">
                                <BarChart3 class="h-4 w-4 text-purple-500" />
                                <h3 class="font-semibold">{{ group.title }}</h3>
                                <span class="text-sm text-muted-foreground">({{ group.data.length }} results)</span>
                            </div>
                        </div>

                        <!-- Group Table -->
                        <div class="overflow-x-auto">
                            <table class="w-full text-sm">
                                <thead class="bg-muted/30">
                                    <tr>
                                        <th
                                            v-for="header in group.headers"
                                            :key="header.value"
                                            class="px-4 py-3 text-left font-medium text-muted-foreground"
                                        >
                                            {{ header.title }}
                                        </th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr
                                        v-for="row in group.data"
                                        :key="row._row_idx_"
                                        class="border-t border-border hover:bg-muted/50 cursor-pointer transition-colors"
                                    >
                                        <td class="px-4 py-3 font-medium">
                                            {{ row.count.toLocaleString() }}
                                        </td>
                                        <td
                                            v-for="field in group.fields"
                                            :key="field"
                                            @click="showQuickAction($event, field, row[field])"
                                            class="px-4 py-3 hover:text-primary hover:underline"
                                        >
                                            {{ row[field] || '-' }}
                                        </td>
                                    </tr>
                                    <tr v-if="group.data.length === 0">
                                        <td :colspan="group.headers.length" class="px-4 py-8 text-center text-muted-foreground">
                                            No aggregation results
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- Events Table -->
                <div class="rounded-xl border border-border bg-card overflow-hidden">
                    <!-- Table Header -->
                    <div class="flex items-center justify-between px-4 py-3 border-b border-border bg-muted/50">
                        <h3 class="font-semibold">{{ categoryConfig.eventsLabel }}</h3>
                        <div class="flex items-center gap-2">
                            <span class="text-sm text-muted-foreground">
                                Showing {{ paginatedEvents.length }} of {{ events.length }}
                            </span>
                            <select
                                v-model="itemsPerPage"
                                class="text-sm bg-background border border-border rounded-md px-2 py-1"
                            >
                                <option v-for="opt in itemsPerPageOptions" :key="opt" :value="opt">
                                    {{ opt }} per page
                                </option>
                            </select>
                        </div>
                    </div>

                    <!-- Table -->
                    <div class="overflow-x-auto">
                        <table class="w-full text-sm">
                            <thead class="bg-muted/30">
                                <tr>
                                    <!-- Checkbox column (detections only) -->
                                    <th v-if="categoryConfig.multiSelectEnabled" class="w-8 px-4 py-3">
                                        <input
                                            type="checkbox"
                                            :checked="selectAllState"
                                            :indeterminate="selectAllIndeterminate"
                                            @change="toggleSelectAll"
                                            class="rounded border-border"
                                        />
                                    </th>
                                    <th class="w-8 px-4 py-3"></th>
                                    <th
                                        v-for="header in headers"
                                        :key="header.value"
                                        @click="header.sortable && handleSort(header.value)"
                                        :class="cn(
                                            'px-4 py-3 text-left font-medium text-muted-foreground',
                                            header.sortable && 'cursor-pointer hover:text-foreground'
                                        )"
                                    >
                                        <div class="flex items-center gap-1">
                                            {{ header.title }}
                                            <span v-if="getSortDirection(header.value)" class="text-primary">
                                                {{ getSortDirection(header.value) === 'asc' ? '↑' : '↓' }}
                                            </span>
                                        </div>
                                    </th>
                                    <!-- Actions column (alerts only) -->
                                    <th v-if="categoryConfig.ackEnabled" class="w-32 px-4 py-3 text-right font-medium text-muted-foreground">
                                        Actions
                                    </th>
                                </tr>
                            </thead>
                            <tbody>
                                <template v-for="event in paginatedEvents" :key="event.soc_id">
                                    <!-- Event Row -->
                                    <tr
                                        @click="toggleEventExpand(event.soc_id)"
                                        :class="cn(
                                            'border-t border-border hover:bg-muted/50 cursor-pointer transition-colors',
                                            selectedEvent?.soc_id === event.soc_id && 'bg-primary/5'
                                        )"
                                    >
                                        <!-- Checkbox cell (detections only) -->
                                        <td v-if="categoryConfig.multiSelectEnabled" class="px-4 py-3" @click.stop>
                                            <input
                                                type="checkbox"
                                                :checked="selectedEventIds.has(event.soc_id)"
                                                @change="toggleEventSelect(event.soc_id)"
                                                class="rounded border-border"
                                            />
                                        </td>
                                        <td class="px-4 py-3">
                                            <ChevronRight
                                                :class="cn(
                                                    'h-4 w-4 transition-transform',
                                                    isEventExpanded(event.soc_id) && 'rotate-90'
                                                )"
                                            />
                                        </td>
                                        <!-- Dynamic columns based on headers -->
                                        <td
                                            v-for="header in headers"
                                            :key="header.value"
                                            class="px-4 py-3"
                                            @click.stop="showQuickAction($event, header.value, event[header.value])"
                                        >
                                            <template v-if="header.value === 'soc_timestamp' || header.value === '@timestamp' || header.value.includes('timestamp')">
                                                {{ formatDate(event[header.value]) }}
                                            </template>
                                            <template v-else-if="header.value === 'soc_type' || header.value === 'event.module'">
                                                <span class="px-2 py-0.5 rounded-full bg-muted text-xs">
                                                    {{ event[header.value] || 'unknown' }}
                                                </span>
                                            </template>
                                            <template v-else-if="header.value === 'event.severity_label'">
                                                <span :class="cn(
                                                    'px-2 py-0.5 rounded-full text-xs',
                                                    getSeverityStyles(event[header.value])
                                                )">
                                                    {{ event[header.value] || '-' }}
                                                </span>
                                            </template>
                                            <template v-else>
                                                <span class="truncate max-w-[200px] inline-block hover:text-primary hover:underline cursor-pointer" :title="String(event[header.value] ?? '')">
                                                    {{ event[header.value] ?? '-' }}
                                                </span>
                                            </template>
                                        </td>
                                        <!-- Actions cell (alerts only) -->
                                        <td v-if="categoryConfig.ackEnabled" class="px-4 py-3" @click.stop>
                                            <div class="flex justify-end">
                                                <AlertActions
                                                    :event="event"
                                                    :ack-enabled="categoryConfig.ackEnabled"
                                                    :escalate-enabled="categoryConfig.escalateEnabled"
                                                    :investigate-enabled="categoryConfig.investigateEnabled"
                                                    :loading="actionLoading"
                                                    @acknowledge="handleAcknowledge"
                                                    @escalate="handleEscalate"
                                                    @investigate="handleInvestigate"
                                                    @view-info="handleViewInfo"
                                                />
                                            </div>
                                        </td>
                                    </tr>

                                    <!-- Expanded Row -->
                                    <tr v-if="isEventExpanded(event.soc_id)">
                                        <td :colspan="1 + headers.length + (categoryConfig.multiSelectEnabled ? 1 : 0) + (categoryConfig.ackEnabled ? 1 : 0)" class="px-4 py-4 bg-muted/30">
                                            <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
                                                <div
                                                    v-for="field in getEventFields(event)"
                                                    :key="field.key"
                                                    class="text-xs group"
                                                >
                                                    <div class="text-muted-foreground truncate">{{ field.key }}</div>
                                                    <div
                                                        @click.stop="showQuickAction($event, field.key, field.value)"
                                                        class="font-medium truncate cursor-pointer hover:text-primary hover:underline"
                                                        :title="String(field.value)"
                                                    >
                                                        {{ field.value }}
                                                    </div>
                                                </div>
                                            </div>
                                            <!-- Ask AI Button -->
                                            <div v-if="aiEnabled" class="mt-4 pt-3 border-t border-border">
                                                <button
                                                    @click.stop="askAiAboutEvent(event)"
                                                    class="flex items-center gap-2 px-3 py-1.5 text-sm rounded-md bg-purple-500/10 text-purple-500 hover:bg-purple-500/20 transition-colors"
                                                >
                                                    <Bot class="h-4 w-4" />
                                                    Ask AI about this event
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                </template>

                                <!-- Empty State -->
                                <tr v-if="events.length === 0">
                                    <td :colspan="1 + headers.length + (categoryConfig.multiSelectEnabled ? 1 : 0) + (categoryConfig.ackEnabled ? 1 : 0)" class="px-4 py-12 text-center text-muted-foreground">
                                        <Search class="h-8 w-8 mx-auto mb-2 opacity-20" />
                                        <p>No {{ categoryConfig.eventsLabel.toLowerCase() }} found.</p>
                                        <p class="text-sm">Try adjusting your search query or time range.</p>
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>

                    <!-- Pagination -->
                    <div v-if="totalPages > 1" class="flex items-center justify-between px-4 py-3 border-t border-border">
                        <button
                            @click="currentPage = Math.max(1, currentPage - 1)"
                            :disabled="currentPage === 1"
                            class="px-3 py-1 text-sm rounded-md bg-muted hover:bg-muted/80 disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                            Previous
                        </button>
                        <span class="text-sm text-muted-foreground">
                            Page {{ currentPage }} of {{ totalPages }}
                        </span>
                        <button
                            @click="currentPage = Math.min(totalPages, currentPage + 1)"
                            :disabled="currentPage === totalPages"
                            class="px-3 py-1 text-sm rounded-md bg-muted hover:bg-muted/80 disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                            Next
                        </button>
                    </div>
                </div>
            </div>

            <!-- Details Panel (alerts only) -->
            <div
                v-if="showDetailsPanel && categoryConfig.showDetailsPanel"
                class="w-[360px] flex-shrink-0 rounded-xl border border-border bg-card overflow-hidden"
            >
                <div class="flex items-center justify-between px-4 py-3 border-b border-border bg-muted/50">
                    <h3 class="font-semibold">Details</h3>
                    <button
                        @click="closeDetailsPanel"
                        class="p-1 text-muted-foreground hover:text-foreground hover:bg-muted rounded"
                    >
                        <X class="h-4 w-4" />
                    </button>
                </div>

                <div v-if="selectedEvent" class="p-4 space-y-4 max-h-[calc(100vh-200px)] overflow-y-auto">
                    <!-- Event Summary -->
                    <div class="space-y-2">
                        <h4 class="text-sm font-medium">Event Summary</h4>
                        <div class="text-xs space-y-1">
                            <div class="flex justify-between">
                                <span class="text-muted-foreground">Time:</span>
                                <span>{{ formatDate(selectedEvent.soc_timestamp) }}</span>
                            </div>
                            <div class="flex justify-between">
                                <span class="text-muted-foreground">Type:</span>
                                <span>{{ selectedEvent.soc_type || 'unknown' }}</span>
                            </div>
                            <div class="flex justify-between">
                                <span class="text-muted-foreground">Source:</span>
                                <span>{{ selectedEvent.soc_source || '-' }}</span>
                            </div>
                        </div>
                    </div>

                    <!-- Alert Actions -->
                    <div v-if="categoryConfig.ackEnabled" class="pt-2 border-t border-border">
                        <AlertActions
                            :event="selectedEvent"
                            :ack-enabled="categoryConfig.ackEnabled"
                            :escalate-enabled="categoryConfig.escalateEnabled"
                            :investigate-enabled="categoryConfig.investigateEnabled"
                            :loading="actionLoading"
                            @acknowledge="handleAcknowledge"
                            @escalate="handleEscalate"
                            @investigate="handleInvestigate"
                            @view-info="handleViewInfo"
                        />
                    </div>

                    <!-- Playbook Panel (alerts only) -->
                    <div v-if="categoryConfig.showPlaybooks" class="pt-2 border-t border-border">
                        <PlaybookPanel
                            :event="selectedEvent"
                            :visible="showDetailsPanel"
                            @hunt-query="handlePlaybookHuntQuery"
                        />
                    </div>
                </div>

                <div v-else class="p-8 text-center text-muted-foreground">
                    <Eye class="h-8 w-8 mx-auto mb-2 opacity-20" />
                    <p class="text-sm">Select an event to view details</p>
                </div>
            </div>
        </div>

        <!-- Quick Action Menu -->
        <QuickActionMenu
            :visible="quickActionVisible"
            :x="quickActionX"
            :y="quickActionY"
            :field="quickActionField"
            :value="quickActionValue"
            :is-numeric="quickActionIsNumeric"
            @close="closeQuickAction"
            @filter="handleQuickFilter"
            @group-by="handleQuickGroupBy"
            @group-by-new="handleQuickGroupByNew"
            @ask-ai="askAiAboutField"
        />

        <!-- Escalation Menu -->
        <EscalationMenu
            :visible="escalationMenuVisible"
            :x="escalationMenuX"
            :y="escalationMenuY"
            :event="escalationMenuEvent"
            :escalate-related-events="true"
            @close="closeEscalationMenu"
            @create-new="handleCreateNewCase"
            @add-to-case="handleAddToExistingCase"
        />
    </div>
</template>
