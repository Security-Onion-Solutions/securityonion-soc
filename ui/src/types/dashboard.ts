// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

// =============================================================================
// Widget Types
// =============================================================================

export type WidgetType = 'count' | 'pie' | 'bar' | 'line' | 'table' | 'donut' | 'sankey' | 'map' | 'alertMap' | 'connectionMap'

export type WidgetSize = 'sm' | 'md' | 'lg' | 'wide'

export interface WidgetPosition {
    x: number
    y: number
    w: number
    h: number
}

export interface Widget {
    id: string
    name: string
    type: WidgetType
    size: WidgetSize
    query?: string
    groupBy?: string
    position?: WidgetPosition
    refreshInterval?: number
    colorScheme?: string
}

// =============================================================================
// Count Widget Data
// =============================================================================

export interface CountWidgetData extends Widget {
    type: 'count'
    value: number | string
    previousValue?: number
    trend?: 'up' | 'down' | 'flat'
    trendPercent?: number
    icon?: string
    color?: 'default' | 'success' | 'warning' | 'danger' | 'info'
}

// =============================================================================
// Chart Widget Data
// =============================================================================

export interface ChartDataPoint {
    label: string
    value: number
    color?: string
}

export interface TimeSeriesDataPoint {
    timestamp: string
    value: number
}

export interface PieWidgetData extends Widget {
    type: 'pie' | 'donut'
    data: ChartDataPoint[]
}

export interface BarWidgetData extends Widget {
    type: 'bar'
    data: ChartDataPoint[]
    orientation?: 'horizontal' | 'vertical'
}

export interface LineWidgetData extends Widget {
    type: 'line'
    data: TimeSeriesDataPoint[]
    showArea?: boolean
}

// =============================================================================
// Table Widget Data
// =============================================================================

export interface TableColumn {
    key: string
    label: string
    sortable?: boolean
    width?: string
}

export interface TableWidgetData extends Widget {
    type: 'table'
    columns: TableColumn[]
    rows: Record<string, any>[]
    maxRows?: number
}

// =============================================================================
// Sankey Widget Data
// =============================================================================

export interface SankeyLink {
    source: string
    target: string
    value: number
    color?: string
}

export interface SankeyWidgetData extends Widget {
    type: 'sankey'
    links: SankeyLink[]
}

// =============================================================================
// Map Widget Data (Pew Pew Map)
// =============================================================================

export type MapConnectionType = 'attack' | 'blocked' | 'allowed' | 'scan' | 'alert'

// Map display modes
export type MapMode = 'alerts' | 'connections'

// Geographic point with coordinates
export interface GeoPoint {
    lat: number
    lng: number
    label?: string        // Country, city, or custom label
    country?: string      // Country code or name
    city?: string         // City name
}

// A marker on the map (for alert geo mode)
export interface MapMarker {
    location: GeoPoint
    count: number         // Number of events at this location
    type?: MapConnectionType
    color?: string
}

// A connection between two points (for connection mode)
export interface MapConnection {
    from: string | GeoPoint   // Location key or coordinates
    to: string | GeoPoint     // Location key or coordinates
    count: number             // Number of connections
    type?: MapConnectionType
    color?: string
}

export interface MapWidgetData extends Widget {
    type: 'map'
    mapMode: MapMode           // 'alerts' for geo markers, 'connections' for flows
    connections?: MapConnection[]  // For connection mode
    markers?: MapMarker[]          // For alert geo mode
    showLegend?: boolean
    centerLat?: number         // Optional map center
    centerLng?: number
    zoom?: number
}

// =============================================================================
// Union Type for All Widget Data
// =============================================================================

export type WidgetData =
    | CountWidgetData
    | PieWidgetData
    | BarWidgetData
    | LineWidgetData
    | TableWidgetData
    | SankeyWidgetData
    | MapWidgetData

// =============================================================================
// Dashboard Types
// =============================================================================

export interface Dashboard {
    id: string
    name: string
    description?: string
    ownerId?: string
    isShared: boolean
    isDefault: boolean
    widgets: WidgetData[]
    createdAt?: string
    updatedAt?: string
}

export interface DashboardListItem {
    id: string
    name: string
    description?: string
    isShared: boolean
    isDefault: boolean
    widgetCount: number
}

// =============================================================================
// Dashboard State Types
// =============================================================================

export interface DashboardState {
    dashboards: DashboardListItem[]
    currentDashboard: Dashboard | null
    loading: boolean
    error: string | null
    editMode: boolean
}

// =============================================================================
// Widget Editor Types
// =============================================================================

export interface WidgetEditorState {
    visible: boolean
    mode: 'create' | 'edit'
    widget: Partial<WidgetData> | null
}

// =============================================================================
// Color Palettes
// =============================================================================

export const CHART_COLORS = [
    'hsl(207, 90%, 54%)',   // Primary blue
    'hsl(142, 71%, 45%)',   // Green
    'hsl(38, 92%, 50%)',    // Orange
    'hsl(340, 82%, 52%)',   // Pink
    'hsl(262, 83%, 58%)',   // Purple
    'hsl(187, 85%, 43%)',   // Cyan
    'hsl(45, 93%, 47%)',    // Yellow
    'hsl(4, 90%, 58%)',     // Red
    'hsl(217, 19%, 35%)',   // Gray
    'hsl(174, 72%, 40%)',   // Teal
] as const

export const SEVERITY_COLORS = {
    critical: 'hsl(0, 84%, 60%)',
    high: 'hsl(25, 95%, 53%)',
    medium: 'hsl(45, 93%, 47%)',
    low: 'hsl(207, 90%, 54%)',
    info: 'hsl(217, 19%, 45%)',
} as const
