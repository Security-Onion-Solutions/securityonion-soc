<script setup lang="ts">
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

defineOptions({ name: 'Hunt' })

import { ref, computed, onMounted, onUnmounted, watch, defineAsyncComponent } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { Pie, Bar } from 'vue-chartjs'
import {
    Chart as ChartJS,
    ArcElement,
    BarElement,
    CategoryScale,
    LinearScale,
    Tooltip,
    Legend,
    Title
} from 'chart.js'
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
    MessageSquare,
    PieChart,
    Maximize2,
    Minimize2,
    Network
} from 'lucide-vue-next'

// Register Chart.js components
ChartJS.register(ArcElement, BarElement, CategoryScale, LinearScale, Tooltip, Legend, Title)
import { cn } from '../lib/utils'
import { useApi } from '../composables/useApi'
import { useFormatters } from '../composables/useFormatters'
import { useStatusStyles } from '../composables/useStatusStyles'
import { useTimeRange, RELATIVE_TIME_UNITS, AUTO_REFRESH_OPTIONS } from '../composables/useTimeRange'
import { useHuntQuery } from '../composables/useHuntQuery'
import { useHuntActions } from '../composables/useHuntActions'
import { useHuntParams } from '../composables/useHuntParams'
import { useChatWidget } from '../composables/useChatWidget'
import { useTheme } from '../composables/useTheme'
import QuickActionMenu from '../components/hunt/QuickActionMenu.vue'
import AlertActions from '../components/hunt/AlertActions.vue'
import EscalationMenu from '../components/hunt/EscalationMenu.vue'
import PlaybookPanel from '../components/hunt/PlaybookPanel.vue'
import BulkActions from '../components/hunt/BulkActions.vue'
import DateTimePicker from '../components/common/DateTimePicker.vue'
import type { SankeyLink } from '../types/dashboard'

// Lazy load SankeyWidget to avoid bundling with mermaid's d3-sankey
const SankeyWidget = defineAsyncComponent(() => import('../components/dashboards/widgets/SankeyWidget.vue'))
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

const route = useRoute()
const router = useRouter()

const { get, loading: apiLoading, error: apiError } = useApi()
const { formatDate, formatRelativeTime } = useFormatters()
const { getSeverityStyles } = useStatusStyles()
const { isDarkMode } = useTheme()

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
    saveToLocalStorage: saveTimeSettings,
    parseFromUrlParams: parseTimeFromUrl,
    serializeToUrlParams: serializeTimeToUrl
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
    saveToLocalStorage: saveQuerySettings,
    parseFromUrlParams: parseQueryFromUrl,
    serializeToUrlParams: serializeQueryToUrl
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
    getQueries,
    getParams,
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

// Query presets from server config
const queryPresets = computed(() => getQueries(props.category))

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

// Fetch limits
const eventLimit = ref(500)
const groupByLimit = ref(10)
const eventLimitOptions = [10, 25, 50, 100, 200, 500, 1000, 2000, 5000]
const groupByLimitOptions = [10, 25, 50, 100, 200, 500]

// Client-side filters (filter fetched results locally)
const eventFilter = ref('')
const groupByFilter = ref('')
const groupByItemsPerPage = ref(10)
const groupByCurrentPage = ref(1)

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

// Filter events based on eventFilter text
const filteredEvents = computed(() => {
    if (!eventFilter.value.trim()) {
        return events.value
    }
    const searchLower = eventFilter.value.toLowerCase()
    return events.value.filter(event => {
        // Search across all string/number fields
        for (const [key, value] of Object.entries(event)) {
            if (key.startsWith('_')) continue
            const strVal = String(value ?? '').toLowerCase()
            if (strVal.includes(searchLower)) {
                return true
            }
        }
        return false
    })
})

const paginatedEvents = computed(() => {
    const start = (currentPage.value - 1) * itemsPerPage.value
    const end = start + itemsPerPage.value
    return filteredEvents.value.slice(start, end)
})

const totalPages = computed(() => {
    return Math.ceil(filteredEvents.value.length / itemsPerPage.value)
})

// Combined group-by data - merges all group-by tables into one
const combinedGroupByData = computed(() => {
    const combined: any[] = []
    for (const group of groupBys.value) {
        for (const row of group.data) {
            // Create a new object with all the row's fields explicitly copied
            const combinedRow: Record<string, any> = {
                count: row.count,
                _row_idx_: row._row_idx_,
                _groupKey: group.key,
                _groupTitle: group.title,
                _groupFields: group.fields
            }
            // Copy each field value from the row
            for (const field of group.fields) {
                combinedRow[field] = row[field]
            }
            combined.push(combinedRow)
        }
    }
    return combined
})

// Get all unique fields across all group-bys for headers
const combinedGroupByFields = computed(() => {
    const fieldsSet = new Set<string>()
    for (const group of groupBys.value) {
        for (const field of group.fields) {
            fieldsSet.add(field)
        }
    }
    return Array.from(fieldsSet)
})

// Helper to get field value from a row (handles missing fields)
function getGroupByFieldValue(row: any, field: string): string {
    // Check if this field belongs to this row's group
    if (row._groupFields && !row._groupFields.includes(field)) {
        return '-'
    }
    const val = row[field]
    if (val === undefined || val === null || val === '') {
        return '-'
    }
    return String(val)
}

// Filter combined group-by data
const filteredGroupByData = computed(() => {
    if (!groupByFilter.value.trim()) {
        return combinedGroupByData.value
    }
    const searchLower = groupByFilter.value.toLowerCase()
    return combinedGroupByData.value.filter(row => {
        for (const [key, value] of Object.entries(row)) {
            if (key.startsWith('_')) continue
            const strVal = String(value ?? '').toLowerCase()
            if (strVal.includes(searchLower)) {
                return true
            }
        }
        return false
    })
})

// Paginated combined group-by data
const paginatedGroupByData = computed(() => {
    const start = (groupByCurrentPage.value - 1) * groupByItemsPerPage.value
    const end = start + groupByItemsPerPage.value
    return filteredGroupByData.value.slice(start, end)
})

// Total pages for combined group-by
const groupByTotalPages = computed(() => {
    return Math.ceil(filteredGroupByData.value.length / groupByItemsPerPage.value)
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
            metricLimit: categoryConfig.value.showMetrics ? groupByLimit.value.toString() : '0',
            eventLimit: eventLimit.value.toString()
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

            // Sync state to URL after successful hunt
            syncToUrl()
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

function selectPresetQuery(preset: { name: string; query: string; description?: string }) {
    setQuery(preset.query)
    showQueryDropdown.value = false
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

/**
 * Find the longest metric key for a given groupby index
 * Example: For groupby_0, prefer "groupby_0|foo|bar" over "groupby_0|foo"
 */
function lookupGroupByMetricKey(metrics: Record<string, ChartMetric[]>, groupIdx: number, longest: boolean = true): string | null {
    let desiredKey: string | null = null
    const prefix = `groupby_${groupIdx}|`

    for (const key of Object.keys(metrics)) {
        if (key.startsWith(prefix)) {
            if (desiredKey === null) {
                desiredKey = key
            } else if (longest && key.length > desiredKey.length) {
                desiredKey = key
            } else if (!longest && key.length < desiredKey.length) {
                desiredKey = key
            }
        }
    }

    return desiredKey
}

/**
 * Localize a value for display
 * Handles special cases like empty strings, nulls, etc.
 */
function localizeValue(value: any): string {
    if (value === null || value === undefined) {
        return ''
    }
    if (value === '') {
        return '(empty)'
    }
    return String(value)
}

/**
 * Resolve SOC-specific IDs in a record
 * Looks up fields starting with "soc_" for display names
 */
function lookupSocIds(record: Record<string, any>) {
    for (const key of Object.keys(record)) {
        if (key.startsWith('soc_') && key !== 'soc_id') {
            // For now, just ensure string conversion
            // Future: Add user ID resolution, etc.
            record[key] = localizeValue(record[key])
        }
    }
}

/**
 * Construct groupby table rows from raw metrics
 */
function constructGroupByRows(fields: string[], data: ChartMetric[]): any[] {
    const records: any[] = []

    data.forEach((row, index) => {
        const record: Record<string, any> = {
            count: row.value,
            _row_idx_: index
        }
        fields.forEach((field, i) => {
            record[field] = localizeValue(row.keys[i])
        })
        lookupSocIds(record)
        records.push(record)
    })

    return records
}

/**
 * Construct chart-specific metrics with aggregation for "Other" category
 */
function constructChartMetrics(data: ChartMetric[], fieldSeparator: string, otherLimit: number): ChartMetric[] {
    const records: ChartMetric[] = []
    let other = 0

    data.forEach((row) => {
        const record: ChartMetric = {
            value: row.value,
            keys: [row.keys.join(fieldSeparator)]
        }
        if (records.length >= otherLimit) {
            other += row.value
        } else {
            records.push(record)
        }
    })

    if (other > 0) {
        records.push({ value: other, keys: ['Other'] })
    }

    return records
}

/**
 * Determine chart type from query options
 */
function getChartTypeFromOptions(options: string[]): 'table' | 'pie' | 'bar' | 'sankey' {
    if (options.includes('pie')) return 'pie'
    if (options.includes('bar')) return 'bar'
    if (options.includes('sankey')) return 'sankey'
    return 'table'
}

/**
 * Build chart data for pie/bar charts
 */
function buildChartData(chartMetrics: ChartMetric[], chartType: 'pie' | 'bar' | 'sankey' | 'table') {
    if (chartType === 'table') return null

    const labels = chartMetrics.map(m => m.keys[0] || '(empty)')
    const values = chartMetrics.map(m => m.value)

    // Color palette
    const colors = [
        'rgba(59, 130, 246, 0.8)',   // blue
        'rgba(16, 185, 129, 0.8)',   // green
        'rgba(249, 115, 22, 0.8)',   // orange
        'rgba(139, 92, 246, 0.8)',   // purple
        'rgba(236, 72, 153, 0.8)',   // pink
        'rgba(245, 158, 11, 0.8)',   // amber
        'rgba(6, 182, 212, 0.8)',    // cyan
        'rgba(239, 68, 68, 0.8)',    // red
        'rgba(107, 114, 128, 0.8)',  // gray
        'rgba(34, 197, 94, 0.8)'     // lime
    ]

    if (chartType === 'pie') {
        return {
            labels,
            datasets: [{
                data: values,
                backgroundColor: colors.slice(0, values.length),
                borderWidth: 1
            }]
        }
    }

    if (chartType === 'bar') {
        return {
            labels,
            datasets: [{
                label: 'Count',
                data: values,
                backgroundColor: colors[0],
                borderWidth: 1
            }]
        }
    }

    return null
}

/**
 * Build sankey data from chart metrics
 * Requires at least 2 fields in the groupby (source and target)
 */
function buildSankeyData(chartMetrics: ChartMetric[], fields: string[]): SankeyLink[] {
    if (fields.length < 2 || !chartMetrics.length) return []

    const links: SankeyLink[] = []

    for (const metric of chartMetrics) {
        if (metric.keys.length >= 2) {
            links.push({
                source: metric.keys[0] || '(empty)',
                target: metric.keys[1] || '(empty)',
                value: metric.value
            })
        }
    }

    return links
}

/**
 * Build chart options based on chart type
 */
function buildChartOptions(chartType: 'pie' | 'bar' | 'sankey' | 'table', showLegend: boolean) {
    if (chartType === 'table') return null

    // Use theme-aware colors
    const textColor = isDarkMode.value ? '#e5e7eb' : '#374151'
    const mutedTextColor = isDarkMode.value ? '#9ca3af' : '#6b7280'
    const gridColor = isDarkMode.value ? 'rgba(75, 85, 99, 0.3)' : 'rgba(209, 213, 219, 0.5)'

    const baseOptions = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                display: showLegend,
                position: 'right' as const,
                labels: {
                    boxWidth: 12,
                    padding: 8,
                    font: {
                        size: 11
                    },
                    color: textColor
                }
            }
        }
    }

    if (chartType === 'bar') {
        return {
            ...baseOptions,
            indexAxis: 'y' as const,
            scales: {
                x: {
                    beginAtZero: true,
                    ticks: {
                        color: mutedTextColor,
                        font: {
                            size: 10
                        }
                    },
                    grid: {
                        color: gridColor
                    }
                },
                y: {
                    ticks: {
                        color: mutedTextColor,
                        font: {
                            size: 10
                        }
                    },
                    grid: {
                        display: false
                    }
                }
            }
        }
    }

    return baseOptions
}

function processMetrics(metrics: Record<string, ChartMetric[]>) {
    groupBys.value = []

    // Get params for chart settings
    const huntParams = getParams(props.category)
    const fieldSeparator = huntParams?.chartLabelFieldSeparator || ', '
    const otherLimit = huntParams?.chartLabelOtherLimit || 10

    // Get query groupby options for chart types
    const queryGroupByOpts = queryGroupBys.value

    // Process each groupby index by finding the longest key
    let groupIdx = 0
    while (true) {
        const key = lookupGroupByMetricKey(metrics, groupIdx, true)
        if (!key) break

        const data = metrics[key]
        if (!data) break

        // Parse the key format: "groupby_N|field1|field2"
        const parts = key.split('|')
        if (parts.length < 2) {
            groupIdx++
            continue
        }

        const fields = parts.slice(1)
        const title = fields.join(fieldSeparator)

        // Construct table rows
        const records = constructGroupByRows(fields, data)

        // Construct chart metrics with Other aggregation
        const chartMetrics = constructChartMetrics(data, fieldSeparator, otherLimit)

        // Get chart type from query options
        const options = queryGroupByOpts[groupIdx]?.options || []
        const chartType = getChartTypeFromOptions(options)
        const showLegend = !options.includes('nolegend')
        const maximized = options.includes('maximize')

        // Build chart data if needed
        const chartData = buildChartData(chartMetrics, chartType)
        const chartOptions = buildChartOptions(chartType, showLegend)

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
            chartType,
            chartMetrics,
            chartData,
            chartOptions,
            sortBy: [{ key: 'count', order: 'desc' }],
            maximized,
            isIncomplete: false,
            filter: '',
            currentPage: 1,
            itemsPerPage: groupByItemsPerPage.value
        })

        groupIdx++
    }
}

/**
 * Set the chart type for a specific groupby
 */
function setGroupByChartType(groupIdx: number, chartType: 'table' | 'pie' | 'bar' | 'sankey') {
    if (groupIdx < 0 || groupIdx >= groupBys.value.length) return

    const group = groupBys.value[groupIdx]
    group.chartType = chartType

    // Rebuild chart data when switching to a chart type
    if (chartType !== 'table' && group.chartMetrics) {
        group.chartData = buildChartData(group.chartMetrics, chartType)
        group.chartOptions = buildChartOptions(chartType, true)
    }
}

/**
 * Toggle maximize state for a specific groupby
 */
function toggleGroupByMaximize(groupIdx: number) {
    if (groupIdx < 0 || groupIdx >= groupBys.value.length) return
    groupBys.value[groupIdx].maximized = !groupBys.value[groupIdx].maximized
}

/**
 * Get paged data for a specific groupby
 */
function getGroupByPagedData(group: GroupByData): any[] {
    const page = group.currentPage || 1
    const perPage = group.itemsPerPage || 10
    const start = (page - 1) * perPage
    const end = start + perPage
    return group.data.slice(start, end)
}

/**
 * Get total pages for a specific groupby
 */
function getGroupByTotalPages(group: GroupByData): number {
    const perPage = group.itemsPerPage || 10
    return Math.ceil(group.data.length / perPage)
}

/**
 * Set the current page for a specific groupby
 */
function setGroupByPage(groupIdx: number, page: number) {
    if (groupIdx < 0 || groupIdx >= groupBys.value.length) return
    const group = groupBys.value[groupIdx]
    const totalPages = getGroupByTotalPages(group)
    group.currentPage = Math.max(1, Math.min(page, totalPages))
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
        // TODO: Bulk enable detections - call detection enable API
    } finally {
        actionLoading.value = false
        clearSelection()
    }
}

async function handleBulkDisable() {
    actionLoading.value = true
    try {
        // TODO: Bulk disable detections - call detection disable API
    } finally {
        actionLoading.value = false
        clearSelection()
    }
}

async function handleBulkDelete() {
    actionLoading.value = true
    try {
        // TODO: Bulk delete detections - call detection delete API
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
// URL Sync
// =============================================================================

/**
 * Parse URL params and load state from URL (higher priority than localStorage)
 */
function loadFromUrl(): boolean {
    const params = new URLSearchParams(route.query as Record<string, string>)
    const timeFromUrl = parseTimeFromUrl(params)
    const queryFromUrl = parseQueryFromUrl(params)

    // Parse fetch limits (el = eventLimit, gl = groupByLimit)
    let limitsFromUrl = false
    const elParam = params.get('el')
    const glParam = params.get('gl')
    if (elParam) {
        const el = parseInt(elParam, 10)
        if (eventLimitOptions.includes(el)) {
            eventLimit.value = el
            limitsFromUrl = true
        }
    }
    if (glParam) {
        const gl = parseInt(glParam, 10)
        if (groupByLimitOptions.includes(gl)) {
            groupByLimit.value = gl
            limitsFromUrl = true
        }
    }

    return timeFromUrl || queryFromUrl || limitsFromUrl
}

/**
 * Sync current state to URL params
 */
function syncToUrl() {
    const queryParams: Record<string, string> = {
        ...serializeTimeToUrl(),
        ...serializeQueryToUrl()
    }

    // Add fetch limits to URL
    queryParams.el = eventLimit.value.toString()
    queryParams.gl = groupByLimit.value.toString()

    // Only update URL if params actually changed
    const currentParams = new URLSearchParams(route.query as Record<string, string>)
    const newParams = new URLSearchParams(queryParams)

    if (currentParams.toString() !== newParams.toString()) {
        router.replace({ query: queryParams })
    }
}

// =============================================================================
// Lifecycle
// =============================================================================

onMounted(async () => {
    // Fetch hunt parameters (eventFields config) from server
    await fetchParams()

    // Try to load from URL params first (higher priority)
    const loadedFromUrl = loadFromUrl()

    // Fall back to localStorage if no URL params
    if (!loadedFromUrl) {
        loadTimeSettings(props.category)
        loadQuerySettings(props.category)
    }

    // Set default query for category if still empty
    if (!query.value) {
        setQuery(categoryConfig.value.defaultQuery)
    }

    // Handle epoch time for detections
    if (categoryConfig.value.useEpochTime) {
        setEpochTime()
    }

    // Set default headers initially
    headers.value = [...defaultHeaders]

    // Sync initial state to URL
    syncToUrl()

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
                        v-if="showQueryDropdown && (queryPresets.length > 0 || mruQueries.length > 0)"
                        class="absolute top-full left-0 right-0 mt-1 bg-card border border-border rounded-md shadow-lg z-50 max-h-80 overflow-auto"
                    >
                        <!-- Default Searches from config -->
                        <template v-if="queryPresets.length > 0">
                            <div class="p-2 text-xs text-muted-foreground border-b border-border font-medium">
                                Default Searches
                            </div>
                            <button
                                v-for="(preset, idx) in queryPresets"
                                :key="'preset-' + idx"
                                @click.stop="selectPresetQuery(preset)"
                                class="w-full text-left px-3 py-2 hover:bg-muted transition-colors group"
                            >
                                <div class="text-sm font-medium">{{ preset.name }}</div>
                                <div v-if="preset.description" class="text-xs text-muted-foreground truncate">{{ preset.description }}</div>
                            </button>
                        </template>

                        <!-- Recent Queries -->
                        <template v-if="mruQueries.length > 0">
                            <div class="p-2 text-xs text-muted-foreground border-b border-border font-medium" :class="{ 'border-t': queryPresets.length > 0 }">
                                Recent Queries
                            </div>
                            <button
                                v-for="(q, idx) in mruQueries"
                                :key="'mru-' + idx"
                                @click.stop="selectMruQuery(q)"
                                class="w-full text-left px-3 py-2 text-sm hover:bg-muted transition-colors truncate"
                            >
                                {{ q }}
                            </button>
                        </template>
                    </div>
                </div>

                <!-- Time Range (if enabled) -->
                <DateTimePicker
                    v-if="categoryConfig.showTimeRange"
                    :show-auto-refresh="true"
                    @change="autohunt && hunt()"
                />

                <!-- Fetch Limits -->
                <div class="flex items-center gap-2 border-l border-border pl-4">
                    <span class="text-xs text-muted-foreground">Events:</span>
                    <select
                        v-model="eventLimit"
                        class="text-sm bg-muted border-0 rounded-md px-2 py-2"
                    >
                        <option v-for="n in eventLimitOptions" :key="n" :value="n">{{ n }}</option>
                    </select>
                    <span class="text-xs text-muted-foreground">Groups:</span>
                    <select
                        v-model="groupByLimit"
                        class="text-sm bg-muted border-0 rounded-md px-2 py-2"
                    >
                        <option v-for="n in groupByLimitOptions" :key="n" :value="n">{{ n }}</option>
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

                <!-- GroupBy Results (Individual Cards) -->
                <div v-if="groupBys.length > 0" class="space-y-4">
                    <div
                        v-for="(group, groupIdx) in groupBys"
                        :key="group.key"
                        :class="cn(
                            'rounded-xl border border-border bg-card overflow-hidden',
                            group.maximized && 'col-span-full'
                        )"
                    >
                        <!-- Header -->
                        <div class="flex items-center justify-between px-4 py-3 border-b border-border bg-muted/50">
                            <div class="flex items-center gap-3">
                                <component
                                    :is="group.chartType === 'pie' ? PieChart : group.chartType === 'bar' ? BarChart3 : group.chartType === 'sankey' ? Network : Table"
                                    class="h-4 w-4 text-purple-500"
                                />
                                <h3 class="font-semibold text-sm">{{ group.title }}</h3>
                                <span class="text-xs text-muted-foreground">
                                    ({{ group.data.length }} results)
                                </span>
                            </div>
                            <div class="flex items-center gap-2">
                                <!-- View toggle buttons -->
                                <div class="flex items-center border border-border rounded-md overflow-hidden">
                                    <button
                                        @click="setGroupByChartType(groupIdx, 'table')"
                                        :class="cn(
                                            'p-1.5 transition-colors',
                                            group.chartType === 'table' ? 'bg-primary text-primary-foreground' : 'hover:bg-muted'
                                        )"
                                        title="Table view"
                                    >
                                        <Table class="h-3.5 w-3.5" />
                                    </button>
                                    <button
                                        @click="setGroupByChartType(groupIdx, 'pie')"
                                        :class="cn(
                                            'p-1.5 transition-colors',
                                            group.chartType === 'pie' ? 'bg-primary text-primary-foreground' : 'hover:bg-muted'
                                        )"
                                        title="Pie chart"
                                    >
                                        <PieChart class="h-3.5 w-3.5" />
                                    </button>
                                    <button
                                        @click="setGroupByChartType(groupIdx, 'bar')"
                                        :class="cn(
                                            'p-1.5 transition-colors',
                                            group.chartType === 'bar' ? 'bg-primary text-primary-foreground' : 'hover:bg-muted'
                                        )"
                                        title="Bar chart"
                                    >
                                        <BarChart3 class="h-3.5 w-3.5" />
                                    </button>
                                    <button
                                        v-if="group.fields.length >= 2"
                                        @click="setGroupByChartType(groupIdx, 'sankey')"
                                        :class="cn(
                                            'p-1.5 transition-colors',
                                            group.chartType === 'sankey' ? 'bg-primary text-primary-foreground' : 'hover:bg-muted'
                                        )"
                                        title="Sankey diagram (flow visualization)"
                                    >
                                        <Network class="h-3.5 w-3.5" />
                                    </button>
                                </div>
                                <!-- Maximize/Minimize toggle -->
                                <button
                                    @click="toggleGroupByMaximize(groupIdx)"
                                    class="p-1.5 hover:bg-muted rounded-md transition-colors"
                                    :title="group.maximized ? 'Minimize' : 'Maximize'"
                                >
                                    <component :is="group.maximized ? Minimize2 : Maximize2" class="h-3.5 w-3.5" />
                                </button>
                            </div>
                        </div>

                        <!-- Chart View (Pie/Bar) -->
                        <div v-if="group.chartType === 'pie' || group.chartType === 'bar'" class="p-4">
                            <div :class="cn('relative', group.maximized ? 'h-96' : 'h-64')">
                                <Pie
                                    v-if="group.chartType === 'pie' && group.chartData"
                                    :data="group.chartData"
                                    :options="group.chartOptions"
                                />
                                <Bar
                                    v-else-if="group.chartType === 'bar' && group.chartData"
                                    :data="group.chartData"
                                    :options="group.chartOptions"
                                />
                                <div v-else class="flex items-center justify-center h-full text-muted-foreground">
                                    No chart data available
                                </div>
                            </div>
                        </div>

                        <!-- Sankey View -->
                        <div v-else-if="group.chartType === 'sankey'" class="p-4">
                            <div :class="cn('relative', group.maximized ? 'h-96' : 'h-64')">
                                <SankeyWidget
                                    v-if="group.chartMetrics && group.fields.length >= 2"
                                    :data="{
                                        id: `sankey-${group.key}`,
                                        name: group.title,
                                        type: 'sankey',
                                        size: 'lg',
                                        links: buildSankeyData(group.chartMetrics, group.fields)
                                    }"
                                />
                                <div v-else class="flex items-center justify-center h-full text-muted-foreground">
                                    Sankey requires at least 2 groupby fields
                                </div>
                            </div>
                        </div>

                        <!-- Table View -->
                        <div v-else class="overflow-x-auto">
                            <table class="w-full text-sm">
                                <thead class="bg-muted/30">
                                    <tr>
                                        <th class="px-4 py-2 text-left font-medium text-muted-foreground text-xs">Count</th>
                                        <th
                                            v-for="field in group.fields"
                                            :key="field"
                                            class="px-4 py-2 text-left font-medium text-muted-foreground text-xs"
                                        >
                                            {{ field }}
                                        </th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr
                                        v-for="row in getGroupByPagedData(group)"
                                        :key="`${group.key}-${row._row_idx_}`"
                                        class="border-t border-border hover:bg-muted/50 transition-colors"
                                    >
                                        <td class="px-4 py-2 font-medium text-xs">
                                            {{ row.count.toLocaleString() }}
                                        </td>
                                        <td
                                            v-for="field in group.fields"
                                            :key="field"
                                            @click="showQuickAction($event, field, row[field])"
                                            class="px-4 py-2 text-xs hover:text-primary hover:underline cursor-pointer"
                                        >
                                            {{ row[field] || '-' }}
                                        </td>
                                    </tr>
                                    <tr v-if="group.data.length === 0">
                                        <td :colspan="1 + group.fields.length" class="px-4 py-6 text-center text-muted-foreground text-xs">
                                            No aggregation results
                                        </td>
                                    </tr>
                                </tbody>
                            </table>

                            <!-- Pagination for individual group -->
                            <div v-if="getGroupByTotalPages(group) > 1" class="flex items-center justify-between px-4 py-2 border-t border-border">
                                <button
                                    @click="setGroupByPage(groupIdx, (group.currentPage || 1) - 1)"
                                    :disabled="(group.currentPage || 1) === 1"
                                    class="px-2 py-0.5 text-xs rounded bg-muted hover:bg-muted/80 disabled:opacity-50 disabled:cursor-not-allowed"
                                >
                                    Prev
                                </button>
                                <span class="text-xs text-muted-foreground">
                                    {{ group.currentPage || 1 }} / {{ getGroupByTotalPages(group) }}
                                </span>
                                <button
                                    @click="setGroupByPage(groupIdx, (group.currentPage || 1) + 1)"
                                    :disabled="(group.currentPage || 1) === getGroupByTotalPages(group)"
                                    class="px-2 py-0.5 text-xs rounded bg-muted hover:bg-muted/80 disabled:opacity-50 disabled:cursor-not-allowed"
                                >
                                    Next
                                </button>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Events Table -->
                <div class="rounded-xl border border-border bg-card overflow-hidden">
                    <!-- Table Header -->
                    <div class="flex items-center justify-between px-4 py-3 border-b border-border bg-muted/50">
                        <div class="flex items-center gap-3">
                            <h3 class="font-semibold">{{ categoryConfig.eventsLabel }}</h3>
                            <span class="text-sm text-muted-foreground">
                                ({{ filteredEvents.length }}{{ eventFilter ? ' filtered' : '' }} of {{ events.length }})
                            </span>
                        </div>
                        <div class="flex items-center gap-3">
                            <!-- Event Filter -->
                            <div class="relative">
                                <Filter class="absolute left-2.5 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                                <input
                                    v-model="eventFilter"
                                    @input="currentPage = 1"
                                    type="text"
                                    placeholder="Filter results..."
                                    class="w-48 pl-8 pr-8 py-1.5 text-sm rounded-md border border-border bg-background focus:outline-none focus:ring-2 focus:ring-primary/50"
                                />
                                <button
                                    v-if="eventFilter"
                                    @click="eventFilter = ''; currentPage = 1"
                                    class="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                                >
                                    <X class="h-4 w-4" />
                                </button>
                            </div>
                            <span class="text-sm text-muted-foreground">
                                Showing {{ paginatedEvents.length }} of {{ filteredEvents.length }}
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
