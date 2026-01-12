// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

// =============================================================================
// Constants
// =============================================================================

export const RELATIVE_TIME_SECONDS = 10
export const RELATIVE_TIME_MINUTES = 20
export const RELATIVE_TIME_HOURS = 30
export const RELATIVE_TIME_DAYS = 40
export const RELATIVE_TIME_WEEKS = 50
export const RELATIVE_TIME_MONTHS = 60

export type RelativeTimeUnit =
    | typeof RELATIVE_TIME_SECONDS
    | typeof RELATIVE_TIME_MINUTES
    | typeof RELATIVE_TIME_HOURS
    | typeof RELATIVE_TIME_DAYS
    | typeof RELATIVE_TIME_WEEKS
    | typeof RELATIVE_TIME_MONTHS

export const FILTER_INCLUDE = 'INCLUDE'
export const FILTER_EXCLUDE = 'EXCLUDE'
export const FILTER_EXACT = 'EXACT'
export const FILTER_DRILLDOWN = 'DRILLDOWN'

export type FilterMode =
    | typeof FILTER_INCLUDE
    | typeof FILTER_EXCLUDE
    | typeof FILTER_EXACT
    | typeof FILTER_DRILLDOWN

// =============================================================================
// Hunt Categories
// =============================================================================

export type HuntCategory = 'hunt' | 'alerts' | 'detections'

export interface CategoryConfig {
    // Query defaults
    defaultQuery: string
    queryBaseFilter: string

    // Time behavior
    showTimeRange: boolean
    useEpochTime: boolean // detections uses epoch-to-now

    // UI features
    showMetrics: boolean
    showEvents: boolean
    showDetailsPanel: boolean
    showPlaybooks: boolean

    // Actions
    ackEnabled: boolean
    escalateEnabled: boolean
    investigateEnabled: boolean
    multiSelectEnabled: boolean
    aggregationActionsEnabled: boolean

    // Specific features
    showManualSync: boolean // detections only

    // Labels
    huntButtonLabel: string
    eventsLabel: string
}

// =============================================================================
// Query Types
// =============================================================================

export interface QueryPreset {
    name: string
    query: string
    description?: string
}

export interface FilterToggle {
    name: string
    filter: string
    enabled: boolean
    exclusive?: boolean
    enablesToggles?: string[]
    disablesToggles?: string[]
}

export interface GroupBySegment {
    fields: string[]
    options: string[] // 'pie', 'bar', 'sankey', 'legend', 'nolegend', 'maximize'
}

export interface ParsedQuery {
    search: string           // The main search portion before |
    filters: string[]        // Individual filter segments
    groupBys: GroupBySegment[]
    sortBys: string[]
    tableFields: string[]
    tableOptions: string[]
    remainder: string        // Everything after search (for reconstruction)
}

// =============================================================================
// Time Range Types
// =============================================================================

export interface TimeRangeState {
    isRelative: boolean
    relativeValue: number
    relativeUnit: RelativeTimeUnit
    dateRange: string // "startDate - endDate" format for absolute
    zone: string
}

export interface AutoRefreshOption {
    label: string
    value: number // seconds, 0 = disabled
}

// =============================================================================
// Event Types
// =============================================================================

export interface EventRecord {
    soc_id: string
    soc_timestamp?: string
    soc_score?: number
    soc_type?: string
    soc_source?: string
    _row_idx_?: number
    _isSelected?: boolean
    _aiInvestigated?: boolean
    _aiInvestigationData?: AIInvestigation
    [key: string]: any // Dynamic payload fields
}

export interface EventHeader {
    title: string
    value: string
    sortable?: boolean
    sort?: (a: any, b: any) => number
}

export interface SortConfig {
    key: string
    order: 'asc' | 'desc'
}

// =============================================================================
// GroupBy / Aggregation Types
// =============================================================================

export type ChartType = 'table' | 'pie' | 'bar' | 'sankey'

export interface GroupByData {
    key: string
    title: string
    fields: string[]
    data: GroupByRecord[]
    headers: EventHeader[]
    chartType: ChartType
    chartMetrics: ChartMetric[]
    chartData: any
    chartOptions: any
    sortBy: SortConfig[]
    maximized: boolean
    isIncomplete?: boolean
}

export interface GroupByRecord {
    count: number
    _row_idx_: number
    [field: string]: any
}

export interface ChartMetric {
    value: number
    keys: string[]
}

// =============================================================================
// Chart Types
// =============================================================================

export interface ChartConfig {
    type: ChartType
    options: ChartOptions
    data: ChartData
    key: number // For forcing re-renders
}

export interface ChartOptions {
    responsive: boolean
    maintainAspectRatio: boolean
    onClick?: (e: any, elements: any[], chart: any) => void
    plugins: {
        legend: { display: boolean; position?: string }
        title: { display: boolean; text: string }
    }
    scales?: Record<string, any>
}

export interface ChartData {
    labels: string[]
    datasets: ChartDataset[]
    key?: number
    flowMax?: number // For sankey
}

export interface ChartDataset {
    label: string
    data: any[]
    backgroundColor: string | string[]
    borderColor?: string | string[]
    fill?: boolean
    pointRadius?: number
}

// =============================================================================
// Action Types
// =============================================================================

export interface ActionConfig {
    name: string
    description?: string
    icon?: string
    link?: string
    linkFormatted?: string
    body?: string
    bodyFormatted?: string
    method?: string
    target?: string
    background?: boolean
    backgroundSuccessLink?: string
    backgroundFailureLink?: string
    fields?: string[]
    categories?: HuntCategory[]
    enabled?: boolean
}

export interface QuickActionState {
    visible: boolean
    target: HTMLElement | null
    event: EventRecord | null
    groupIdx: number
    field: string
    value: any
    isNumeric: boolean
    detectionId: string | null
}

export interface EscalationState {
    visible: boolean
    target: HTMLElement | null
    item: EventRecord | null
    groupIdx: number
}

// =============================================================================
// AI Investigation Types
// =============================================================================

export interface AIInvestigation {
    chatSessionId: string
    socId: string
    ruleUuid?: string
    timestamp: string
}

// =============================================================================
// Playbook Types
// =============================================================================

export interface PlaybookQuestion {
    question: string
    context: string
    oqlQuery: string
    range?: string
    fields: string[]
    queryResults?: any[]
    loading?: boolean
    error?: boolean
    isAggregate?: boolean
}

// =============================================================================
// Detection Types
// =============================================================================

export interface Detection {
    id: string
    publicId: string
    title: string
    description: string
    severity: string
    engine: string
    author: string
    isEnabled: boolean
    isReporting: boolean
    language: string
    ruleset: string
    overrides?: any[]
}

// =============================================================================
// API Response Types
// =============================================================================

export interface EventSearchResponse {
    createTime?: string
    completeTime?: string
    elapsedMs?: number
    totalEvents: number
    events: EventRecord[]
    metrics?: Record<string, ChartMetric[]>
    errors?: string[]
}

export interface QueryTransformResponse {
    query: string
}

export interface AckResponse {
    success: boolean
    message?: string
}

// =============================================================================
// Hunt State Types
// =============================================================================

export interface HuntParams {
    groupItemsPerPage: number
    groupFetchLimit: number
    eventItemsPerPage: number
    eventFetchLimit: number
    relativeTimeValue: number
    relativeTimeUnit: RelativeTimeUnit
    mostRecentlyUsedLimit: number
    safeStringMaxLength: number
    queryBaseFilter: string
    queries: QueryPreset[]
    queryToggleFilters: FilterToggle[]
    eventFields: Record<string, string[]>
    advanced: boolean
    ackEnabled: boolean
    escalateEnabled: boolean
    escalateRelatedEventsEnabled: boolean
    aggregationActionsEnabled: boolean
    viewEnabled: boolean
    createLink: string
    chartLabelMaxLength: number
    chartLabelOtherLimit: number
    chartLabelFieldSeparator: string
    presets: Record<string, any>
    actions: ActionConfig[]
    maxBulkEscalateEvents: number
    detectionEngineStatusQueries?: Record<string, string>
}

export interface HuntState {
    category: HuntCategory
    params: HuntParams | null
    loaded: boolean
    loading: boolean
    huntPending: boolean
    advanced: boolean
    autohunt: boolean
    showFullQuery: boolean

    // Results
    totalEvents: number
    fetchTimeSecs: number
    roundTripTimeSecs: number

    // Error handling
    error: string | null
}

// =============================================================================
// Local Settings Types
// =============================================================================

export interface HuntLocalSettings {
    advanced: boolean
    autohunt: boolean
    showFullQuery: boolean
    relativeTimeEnabled: boolean
    relativeTimeValue: number
    relativeTimeUnit: RelativeTimeUnit
    zone: string
    itemsPerPage: number
    eventLimit: number
    groupByLimit: number
    sortBy: SortConfig[]
    collapsedSections: string[]
    showDetailsPanel: boolean
    filterToggles: Record<string, boolean>
}
