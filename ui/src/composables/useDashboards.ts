// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

import { ref, computed } from 'vue'
import type {
    Dashboard,
    DashboardListItem,
    WidgetData,
    WidgetType,
    WidgetSize,
    ChartDataPoint,
    SankeyLink,
    TableColumn,
    MapMarker,
    MapConnection,
    GeoPoint
} from '../types/dashboard'

// =============================================================================
// Types
// =============================================================================

export interface DashboardConfig {
    id: string
    name: string
    description?: string
    isDefault: boolean
    isShared: boolean
    widgets: WidgetConfig[]
}

export interface WidgetConfig {
    id: string
    name: string
    type: WidgetType
    size: WidgetSize
    query: string
}

interface ChartMetric {
    value: number
    keys: string[]
}

interface EventSearchResponse {
    totalEvents?: number
    elapsedMs?: number
    events?: any[]
    metrics?: Record<string, ChartMetric[]>
}

// =============================================================================
// Default Dashboards
// =============================================================================

const DEFAULT_DASHBOARDS: DashboardConfig[] = [
    {
        id: 'security-overview',
        name: 'Security Overview',
        description: 'High-level view of security events and data flows',
        isDefault: true,
        isShared: true,
        widgets: [
            { id: 'w1', name: 'Event Categories', type: 'pie', size: 'md', query: '* | groupby event.category' },
            { id: 'w2', name: 'Category to Module', type: 'sankey', size: 'lg', query: '* | groupby event.category event.module' },
            { id: 'w3', name: 'Event Modules', type: 'bar', size: 'md', query: '* | groupby event.module' },
            { id: 'w4', name: 'Module to Dataset', type: 'sankey', size: 'lg', query: '* | groupby event.module event.dataset' },
            { id: 'w5', name: 'Datasets', type: 'pie', size: 'md', query: '* | groupby event.dataset' },
            { id: 'w6', name: 'Observers', type: 'bar', size: 'md', query: '* | groupby observer.name' },
            { id: 'w7', name: 'Top Hosts', type: 'table', size: 'md', query: '* | groupby host.name' },
            { id: 'w8', name: 'Source IPs', type: 'table', size: 'md', query: '* | groupby source.ip' },
            { id: 'w9', name: 'Destination IPs', type: 'table', size: 'md', query: '* | groupby destination.ip' },
            { id: 'w10', name: 'Destination Ports', type: 'pie', size: 'md', query: '* | groupby destination.port' }
        ]
    },
    {
        id: 'network-flows',
        name: 'Network Flows',
        description: 'Network traffic and connection analysis',
        isDefault: true,
        isShared: true,
        widgets: [
            { id: 'nf1', name: 'Source to Destination', type: 'sankey', size: 'wide', query: '* | groupby source.ip destination.ip' },
            { id: 'nf2', name: 'Protocol Distribution', type: 'pie', size: 'md', query: '* | groupby network.protocol' },
            { id: 'nf3', name: 'Top Ports', type: 'bar', size: 'md', query: '* | groupby destination.port' },
            { id: 'nf4', name: 'Transport Protocols', type: 'donut', size: 'sm', query: '* | groupby network.transport' },
            { id: 'nf5', name: 'Top Source IPs', type: 'bar', size: 'md', query: '* | groupby source.ip' },
            { id: 'nf6', name: 'Top Destination IPs', type: 'bar', size: 'md', query: '* | groupby destination.ip' }
        ]
    },
    {
        id: 'alerts-overview',
        name: 'Alerts Overview',
        description: 'Security alerts and detections summary',
        isDefault: true,
        isShared: true,
        widgets: [
            { id: 'ao1', name: 'Alert Severity', type: 'pie', size: 'md', query: 'event.kind:alert | groupby rule.severity' },
            { id: 'ao2', name: 'Top Rules', type: 'bar', size: 'lg', query: 'event.kind:alert | groupby rule.name' },
            { id: 'ao3', name: 'Alert Origins', type: 'alertMap', size: 'lg', query: 'event.kind:alert | groupby source.geo.country_name' },
            { id: 'ao4', name: 'Alert Sources', type: 'pie', size: 'md', query: 'event.kind:alert | groupby source.ip' },
            { id: 'ao5', name: 'Alert Targets', type: 'bar', size: 'md', query: 'event.kind:alert | groupby destination.ip' },
            { id: 'ao6', name: 'Alerts by Category', type: 'donut', size: 'md', query: 'event.kind:alert | groupby event.category' }
        ]
    },
    {
        id: 'geo-maps',
        name: 'Geographic Maps',
        description: 'Visualize geographic distribution of alerts and network flows',
        isDefault: true,
        isShared: true,
        widgets: [
            { id: 'gm1', name: 'Alert Origins by Country', type: 'alertMap', size: 'lg', query: 'event.kind:alert | groupby source.geo.country_name' },
            { id: 'gm2', name: 'Alert Targets by Country', type: 'alertMap', size: 'lg', query: 'event.kind:alert | groupby destination.geo.country_name' },
            { id: 'gm3', name: 'Connection Flows', type: 'connectionMap', size: 'wide', query: '* | groupby source.geo.country_name destination.geo.country_name' },
            { id: 'gm4', name: 'Top Source Countries', type: 'bar', size: 'md', query: '* | groupby source.geo.country_name' },
            { id: 'gm5', name: 'Top Destination Countries', type: 'bar', size: 'md', query: '* | groupby destination.geo.country_name' },
            { id: 'gm6', name: 'Alert Flow by Country', type: 'connectionMap', size: 'wide', query: 'event.kind:alert | groupby source.geo.country_name destination.geo.country_name' }
        ]
    }
]

// =============================================================================
// Local Storage Keys
// =============================================================================

const STORAGE_KEY_CUSTOM_DASHBOARDS = 'dashboards.custom'
const STORAGE_KEY_SELECTED_DASHBOARD = 'dashboards.selected'

// =============================================================================
// Country Coordinates Lookup
// =============================================================================

const COUNTRY_COORDS: Record<string, { lat: number; lng: number }> = {
    // North America
    'United States': { lat: 39.8283, lng: -98.5795 },
    'USA': { lat: 39.8283, lng: -98.5795 },
    'US': { lat: 39.8283, lng: -98.5795 },
    'Canada': { lat: 56.1304, lng: -106.3468 },
    'CA': { lat: 56.1304, lng: -106.3468 },
    'Mexico': { lat: 23.6345, lng: -102.5528 },
    'MX': { lat: 23.6345, lng: -102.5528 },

    // Europe
    'United Kingdom': { lat: 55.3781, lng: -3.4360 },
    'UK': { lat: 55.3781, lng: -3.4360 },
    'GB': { lat: 55.3781, lng: -3.4360 },
    'Germany': { lat: 51.1657, lng: 10.4515 },
    'DE': { lat: 51.1657, lng: 10.4515 },
    'France': { lat: 46.2276, lng: 2.2137 },
    'FR': { lat: 46.2276, lng: 2.2137 },
    'Netherlands': { lat: 52.1326, lng: 5.2913 },
    'NL': { lat: 52.1326, lng: 5.2913 },
    'Russia': { lat: 61.5240, lng: 105.3188 },
    'Russian Federation': { lat: 61.5240, lng: 105.3188 },
    'RU': { lat: 61.5240, lng: 105.3188 },
    'Italy': { lat: 41.8719, lng: 12.5674 },
    'IT': { lat: 41.8719, lng: 12.5674 },
    'Spain': { lat: 40.4637, lng: -3.7492 },
    'ES': { lat: 40.4637, lng: -3.7492 },
    'Poland': { lat: 51.9194, lng: 19.1451 },
    'PL': { lat: 51.9194, lng: 19.1451 },
    'Ukraine': { lat: 48.3794, lng: 31.1656 },
    'UA': { lat: 48.3794, lng: 31.1656 },
    'Romania': { lat: 45.9432, lng: 24.9668 },
    'RO': { lat: 45.9432, lng: 24.9668 },
    'Sweden': { lat: 60.1282, lng: 18.6435 },
    'SE': { lat: 60.1282, lng: 18.6435 },
    'Norway': { lat: 60.4720, lng: 8.4689 },
    'NO': { lat: 60.4720, lng: 8.4689 },
    'Finland': { lat: 61.9241, lng: 25.7482 },
    'FI': { lat: 61.9241, lng: 25.7482 },
    'Switzerland': { lat: 46.8182, lng: 8.2275 },
    'CH': { lat: 46.8182, lng: 8.2275 },
    'Austria': { lat: 47.5162, lng: 14.5501 },
    'AT': { lat: 47.5162, lng: 14.5501 },
    'Belgium': { lat: 50.5039, lng: 4.4699 },
    'BE': { lat: 50.5039, lng: 4.4699 },
    'Czechia': { lat: 49.8175, lng: 15.4730 },
    'Czech Republic': { lat: 49.8175, lng: 15.4730 },
    'CZ': { lat: 49.8175, lng: 15.4730 },
    'Ireland': { lat: 53.1424, lng: -7.6921 },
    'IE': { lat: 53.1424, lng: -7.6921 },
    'Portugal': { lat: 39.3999, lng: -8.2245 },
    'PT': { lat: 39.3999, lng: -8.2245 },
    'Greece': { lat: 39.0742, lng: 21.8243 },
    'GR': { lat: 39.0742, lng: 21.8243 },
    'Hungary': { lat: 47.1625, lng: 19.5033 },
    'HU': { lat: 47.1625, lng: 19.5033 },
    'Denmark': { lat: 56.2639, lng: 9.5018 },
    'DK': { lat: 56.2639, lng: 9.5018 },

    // Asia
    'China': { lat: 35.8617, lng: 104.1954 },
    'CN': { lat: 35.8617, lng: 104.1954 },
    'Japan': { lat: 36.2048, lng: 138.2529 },
    'JP': { lat: 36.2048, lng: 138.2529 },
    'South Korea': { lat: 35.9078, lng: 127.7669 },
    'Korea, Republic of': { lat: 35.9078, lng: 127.7669 },
    'KR': { lat: 35.9078, lng: 127.7669 },
    'North Korea': { lat: 40.3399, lng: 127.5101 },
    'Korea, Democratic People\'s Republic of': { lat: 40.3399, lng: 127.5101 },
    'KP': { lat: 40.3399, lng: 127.5101 },
    'India': { lat: 20.5937, lng: 78.9629 },
    'IN': { lat: 20.5937, lng: 78.9629 },
    'Indonesia': { lat: -0.7893, lng: 113.9213 },
    'ID': { lat: -0.7893, lng: 113.9213 },
    'Vietnam': { lat: 14.0583, lng: 108.2772 },
    'VN': { lat: 14.0583, lng: 108.2772 },
    'Thailand': { lat: 15.8700, lng: 100.9925 },
    'TH': { lat: 15.8700, lng: 100.9925 },
    'Malaysia': { lat: 4.2105, lng: 101.9758 },
    'MY': { lat: 4.2105, lng: 101.9758 },
    'Singapore': { lat: 1.3521, lng: 103.8198 },
    'SG': { lat: 1.3521, lng: 103.8198 },
    'Philippines': { lat: 12.8797, lng: 121.7740 },
    'PH': { lat: 12.8797, lng: 121.7740 },
    'Taiwan': { lat: 23.6978, lng: 120.9605 },
    'TW': { lat: 23.6978, lng: 120.9605 },
    'Hong Kong': { lat: 22.3193, lng: 114.1694 },
    'HK': { lat: 22.3193, lng: 114.1694 },
    'Pakistan': { lat: 30.3753, lng: 69.3451 },
    'PK': { lat: 30.3753, lng: 69.3451 },
    'Bangladesh': { lat: 23.6850, lng: 90.3563 },
    'BD': { lat: 23.6850, lng: 90.3563 },

    // Middle East
    'Iran': { lat: 32.4279, lng: 53.6880 },
    'Iran, Islamic Republic of': { lat: 32.4279, lng: 53.6880 },
    'IR': { lat: 32.4279, lng: 53.6880 },
    'Israel': { lat: 31.0461, lng: 34.8516 },
    'IL': { lat: 31.0461, lng: 34.8516 },
    'United Arab Emirates': { lat: 23.4241, lng: 53.8478 },
    'AE': { lat: 23.4241, lng: 53.8478 },
    'Saudi Arabia': { lat: 23.8859, lng: 45.0792 },
    'SA': { lat: 23.8859, lng: 45.0792 },
    'Turkey': { lat: 38.9637, lng: 35.2433 },
    'TR': { lat: 38.9637, lng: 35.2433 },
    'Iraq': { lat: 33.2232, lng: 43.6793 },
    'IQ': { lat: 33.2232, lng: 43.6793 },

    // South America
    'Brazil': { lat: -14.2350, lng: -51.9253 },
    'BR': { lat: -14.2350, lng: -51.9253 },
    'Argentina': { lat: -38.4161, lng: -63.6167 },
    'AR': { lat: -38.4161, lng: -63.6167 },
    'Colombia': { lat: 4.5709, lng: -74.2973 },
    'CO': { lat: 4.5709, lng: -74.2973 },
    'Chile': { lat: -35.6751, lng: -71.5430 },
    'CL': { lat: -35.6751, lng: -71.5430 },
    'Peru': { lat: -9.1900, lng: -75.0152 },
    'PE': { lat: -9.1900, lng: -75.0152 },
    'Venezuela': { lat: 6.4238, lng: -66.5897 },
    'VE': { lat: 6.4238, lng: -66.5897 },

    // Africa
    'South Africa': { lat: -30.5595, lng: 22.9375 },
    'ZA': { lat: -30.5595, lng: 22.9375 },
    'Nigeria': { lat: 9.0820, lng: 8.6753 },
    'NG': { lat: 9.0820, lng: 8.6753 },
    'Egypt': { lat: 26.8206, lng: 30.8025 },
    'EG': { lat: 26.8206, lng: 30.8025 },
    'Kenya': { lat: -0.0236, lng: 37.9062 },
    'KE': { lat: -0.0236, lng: 37.9062 },
    'Morocco': { lat: 31.7917, lng: -7.0926 },
    'MA': { lat: 31.7917, lng: -7.0926 },

    // Oceania
    'Australia': { lat: -25.2744, lng: 133.7751 },
    'AU': { lat: -25.2744, lng: 133.7751 },
    'New Zealand': { lat: -40.9006, lng: 174.8860 },
    'NZ': { lat: -40.9006, lng: 174.8860 },

    // Default/Unknown - center of map
    'Unknown': { lat: 0, lng: 0 },
    'Private': { lat: 0, lng: 0 },
    '': { lat: 0, lng: 0 }
}

// Convert country name to coordinates
function countryToCoords(country: string): { lat: number; lng: number } {
    if (!country) return { lat: 0, lng: 0 }
    // Try exact match first, then try uppercase
    return COUNTRY_COORDS[country] || COUNTRY_COORDS[country.toUpperCase()] || { lat: 0, lng: 0 }
}

// =============================================================================
// State
// =============================================================================

const customDashboards = ref<DashboardConfig[]>([])
const selectedDashboardId = ref<string | null>(null)
const widgetData = ref<Map<string, WidgetData>>(new Map())
const widgetLoading = ref<Map<string, boolean>>(new Map())
const widgetErrors = ref<Map<string, string | null>>(new Map())
const initialized = ref(false)

// =============================================================================
// Composable
// =============================================================================

export function useDashboards() {
    // Load custom dashboards from localStorage
    function loadCustomDashboards() {
        try {
            const stored = localStorage.getItem(STORAGE_KEY_CUSTOM_DASHBOARDS)
            if (stored) {
                customDashboards.value = JSON.parse(stored)
            }
            const selectedId = localStorage.getItem(STORAGE_KEY_SELECTED_DASHBOARD)
            if (selectedId) {
                selectedDashboardId.value = selectedId
            }
            initialized.value = true
        } catch (e) {
            console.error('Failed to load custom dashboards:', e)
            customDashboards.value = []
        }
    }

    // Save custom dashboards to localStorage
    function saveCustomDashboards() {
        try {
            localStorage.setItem(STORAGE_KEY_CUSTOM_DASHBOARDS, JSON.stringify(customDashboards.value))
        } catch (e) {
            console.error('Failed to save custom dashboards:', e)
        }
    }

    // Save selected dashboard ID
    function saveSelectedDashboard() {
        if (selectedDashboardId.value) {
            localStorage.setItem(STORAGE_KEY_SELECTED_DASHBOARD, selectedDashboardId.value)
        } else {
            localStorage.removeItem(STORAGE_KEY_SELECTED_DASHBOARD)
        }
    }

    // Get all dashboards (default + custom)
    const allDashboards = computed((): DashboardConfig[] => {
        return [...DEFAULT_DASHBOARDS, ...customDashboards.value]
    })

    // Get dashboard list items for sidebar
    const dashboardList = computed((): DashboardListItem[] => {
        return allDashboards.value.map(d => ({
            id: d.id,
            name: d.name,
            description: d.description,
            isShared: d.isShared,
            isDefault: d.isDefault,
            widgetCount: d.widgets.length
        }))
    })

    // Get selected dashboard
    const selectedDashboard = computed((): DashboardConfig | null => {
        if (!selectedDashboardId.value) return allDashboards.value[0] || null
        return allDashboards.value.find(d => d.id === selectedDashboardId.value) || allDashboards.value[0] || null
    })

    // Select a dashboard
    function selectDashboard(id: string) {
        selectedDashboardId.value = id
        saveSelectedDashboard()
    }

    // Create a new custom dashboard
    function createDashboard(name: string, description?: string): DashboardConfig {
        const id = `custom-${Date.now()}`
        const newDashboard: DashboardConfig = {
            id,
            name,
            description,
            isDefault: false,
            isShared: false,
            widgets: []
        }
        customDashboards.value.push(newDashboard)
        saveCustomDashboards()
        return newDashboard
    }

    // Clone a dashboard
    function cloneDashboard(sourceId: string, newName: string): DashboardConfig | null {
        const source = allDashboards.value.find(d => d.id === sourceId)
        if (!source) return null

        const id = `custom-${Date.now()}`
        const cloned: DashboardConfig = {
            ...source,
            id,
            name: newName,
            isDefault: false,
            isShared: false,
            widgets: source.widgets.map((w, idx) => ({
                ...w,
                id: `${id}-w${idx}`
            }))
        }
        customDashboards.value.push(cloned)
        saveCustomDashboards()
        return cloned
    }

    // Update a custom dashboard
    function updateDashboard(id: string, updates: Partial<DashboardConfig>): boolean {
        const idx = customDashboards.value.findIndex(d => d.id === id)
        if (idx === -1) return false

        customDashboards.value[idx] = {
            ...customDashboards.value[idx],
            ...updates,
            id // Don't allow changing ID
        }
        saveCustomDashboards()
        return true
    }

    // Delete a custom dashboard
    function deleteDashboard(id: string): boolean {
        const dashboard = allDashboards.value.find(d => d.id === id)
        if (!dashboard || dashboard.isDefault) return false

        const idx = customDashboards.value.findIndex(d => d.id === id)
        if (idx === -1) return false

        customDashboards.value.splice(idx, 1)
        saveCustomDashboards()

        // Select another dashboard if the deleted one was selected
        if (selectedDashboardId.value === id) {
            selectedDashboardId.value = allDashboards.value[0]?.id || null
            saveSelectedDashboard()
        }

        return true
    }

    // Add widget to a dashboard
    function addWidget(dashboardId: string, widget: WidgetConfig): boolean {
        const idx = customDashboards.value.findIndex(d => d.id === dashboardId)
        if (idx === -1) return false

        customDashboards.value[idx].widgets.push(widget)
        saveCustomDashboards()
        return true
    }

    // Update widget in a dashboard
    function updateWidget(dashboardId: string, widgetId: string, updates: Partial<WidgetConfig>): boolean {
        const dashboardIdx = customDashboards.value.findIndex(d => d.id === dashboardId)
        if (dashboardIdx === -1) return false

        const widgetIdx = customDashboards.value[dashboardIdx].widgets.findIndex(w => w.id === widgetId)
        if (widgetIdx === -1) return false

        customDashboards.value[dashboardIdx].widgets[widgetIdx] = {
            ...customDashboards.value[dashboardIdx].widgets[widgetIdx],
            ...updates,
            id: widgetId
        }
        saveCustomDashboards()
        return true
    }

    // Remove widget from a dashboard
    function removeWidget(dashboardId: string, widgetId: string): boolean {
        const dashboardIdx = customDashboards.value.findIndex(d => d.id === dashboardId)
        if (dashboardIdx === -1) return false

        const widgetIdx = customDashboards.value[dashboardIdx].widgets.findIndex(w => w.id === widgetId)
        if (widgetIdx === -1) return false

        customDashboards.value[dashboardIdx].widgets.splice(widgetIdx, 1)
        saveCustomDashboards()
        return true
    }

    // Parse query to extract groupby fields
    function parseQueryFields(query: string): string[] {
        const match = query.match(/groupby\s+([^\|]+)/i)
        if (!match) return []
        return match[1].trim().split(/\s+/).filter(f => f && !f.startsWith('-'))
    }

    // Execute a widget query and return widget data
    async function executeWidgetQuery(
        widget: WidgetConfig,
        timeRange: { dateRange: string; dateRangeMinutes: number },
        zone: string = 'UTC'
    ): Promise<WidgetData | null> {
        const widgetKey = `${widget.id}-${timeRange.dateRange}`
        widgetLoading.value.set(widget.id, true)
        widgetErrors.value.set(widget.id, null)

        try {
            const params = new URLSearchParams({
                query: widget.query,
                range: timeRange.dateRange,
                zone,
                metricLimit: '20',
                eventLimit: '0'
            })

            const response = await fetch(`/api/events/?${params.toString()}`)
            if (!response.ok) {
                throw new Error(`Query failed: ${response.status}`)
            }

            const data: EventSearchResponse = await response.json()

            // Transform metrics to widget data
            const widgetDataResult = transformMetricsToWidgetData(widget, data.metrics || {})
            widgetData.value.set(widget.id, widgetDataResult)

            return widgetDataResult
        } catch (e: any) {
            widgetErrors.value.set(widget.id, e.message || 'Query failed')
            console.error(`Error executing widget query for ${widget.name}:`, e)
            return null
        } finally {
            widgetLoading.value.set(widget.id, false)
        }
    }

    // Find the longest metric key for a given groupby index
    // For sankey widgets, we need keys with multiple fields (e.g., groupby_0|field1|field2)
    function findLongestMetricKey(metrics: Record<string, ChartMetric[]>, groupIdx: number = 0): string | null {
        const prefix = `groupby_${groupIdx}|`
        let longestKey: string | null = null

        for (const key of Object.keys(metrics)) {
            if (key.startsWith(prefix)) {
                if (longestKey === null || key.length > longestKey.length) {
                    longestKey = key
                }
            }
        }

        return longestKey
    }

    // Transform API metrics to widget data format
    function transformMetricsToWidgetData(widget: WidgetConfig, metrics: Record<string, ChartMetric[]>): WidgetData {
        // Find the metrics for this widget - use longest key to get all fields
        const metricsKey = findLongestMetricKey(metrics, 0)
        const metricData = metricsKey ? metrics[metricsKey] : []

        const fields = parseQueryFields(widget.query)

        // Build base widget data
        const baseData = {
            id: widget.id,
            name: widget.name,
            size: widget.size
        }

        switch (widget.type) {
            case 'count':
                const totalCount = metricData.reduce((sum, m) => sum + m.value, 0)
                return {
                    ...baseData,
                    type: 'count' as const,
                    value: totalCount
                }

            case 'pie':
            case 'donut':
                return {
                    ...baseData,
                    type: widget.type as 'pie' | 'donut',
                    data: metricData.slice(0, 10).map(m => ({
                        label: m.keys[0] || '(empty)',
                        value: m.value
                    }))
                }

            case 'bar':
                return {
                    ...baseData,
                    type: 'bar' as const,
                    data: metricData.slice(0, 10).map(m => ({
                        label: m.keys[0] || '(empty)',
                        value: m.value
                    })),
                    orientation: 'horizontal' as const
                }

            case 'sankey':
                const links: SankeyLink[] = metricData
                    .filter(m => m.keys.length >= 2)
                    .slice(0, 20)
                    .map(m => ({
                        source: m.keys[0] || '(empty)',
                        target: m.keys[1] || '(empty)',
                        value: m.value
                    }))
                return {
                    ...baseData,
                    type: 'sankey' as const,
                    links
                }

            case 'table':
                const columns: TableColumn[] = [
                    { key: 'count', label: 'Count', sortable: true },
                    ...fields.map(f => ({ key: f, label: f, sortable: true }))
                ]
                const rows = metricData.slice(0, 20).map((m, idx) => {
                    const row: Record<string, any> = { count: m.value, _idx: idx }
                    fields.forEach((f, i) => {
                        row[f] = m.keys[i] || ''
                    })
                    return row
                })
                return {
                    ...baseData,
                    type: 'table' as const,
                    columns,
                    rows
                }

            case 'line':
                // Line charts need time series data - simplified for now
                return {
                    ...baseData,
                    type: 'line' as const,
                    data: [],
                    showArea: false
                }

            case 'map':
                return {
                    ...baseData,
                    type: 'map' as const,
                    mapMode: 'connections' as const,
                    connections: []
                }

            case 'alertMap':
                // Alert map shows geographic distribution of alerts
                // Query should group by source.geo.country_name or similar
                const alertMarkers: MapMarker[] = metricData
                    .filter(m => m.keys[0] && m.keys[0] !== '(empty)')
                    .slice(0, 50)
                    .map(m => {
                        const countryName = m.keys[0]
                        const coords = countryToCoords(countryName)
                        return {
                            location: {
                                lat: coords.lat,
                                lng: coords.lng,
                                label: countryName,
                                country: countryName
                            },
                            count: m.value,
                            type: 'alert' as const
                        }
                    })
                    .filter(m => m.location.lat !== 0 || m.location.lng !== 0)
                return {
                    ...baseData,
                    type: 'map' as const,
                    mapMode: 'alerts' as const,
                    markers: alertMarkers
                }

            case 'connectionMap':
                // Connection map shows flows between source and destination
                // Query should group by source.geo.country_name destination.geo.country_name
                const mapConnections: MapConnection[] = metricData
                    .filter(m => m.keys.length >= 2 && m.keys[0] && m.keys[1])
                    .slice(0, 30)
                    .map(m => {
                        const fromCountry = m.keys[0]
                        const toCountry = m.keys[1]
                        const fromCoords = countryToCoords(fromCountry)
                        const toCoords = countryToCoords(toCountry)
                        return {
                            from: {
                                lat: fromCoords.lat,
                                lng: fromCoords.lng,
                                label: fromCountry,
                                country: fromCountry
                            },
                            to: {
                                lat: toCoords.lat,
                                lng: toCoords.lng,
                                label: toCountry,
                                country: toCountry
                            },
                            count: m.value,
                            type: 'attack' as const
                        }
                    })
                    .filter(c => {
                        const from = c.from as GeoPoint
                        const to = c.to as GeoPoint
                        return (from.lat !== 0 || from.lng !== 0) && (to.lat !== 0 || to.lng !== 0)
                    })
                return {
                    ...baseData,
                    type: 'map' as const,
                    mapMode: 'connections' as const,
                    connections: mapConnections
                }

            default:
                return {
                    ...baseData,
                    type: 'count' as const,
                    value: 0
                }
        }
    }

    // Execute all widget queries for a dashboard
    async function refreshDashboard(
        dashboard: DashboardConfig,
        timeRange: { dateRange: string; dateRangeMinutes: number },
        zone: string = 'UTC'
    ): Promise<void> {
        const promises = dashboard.widgets.map(widget =>
            executeWidgetQuery(widget, timeRange, zone)
        )
        await Promise.all(promises)
    }

    // Get cached widget data
    function getWidgetData(widgetId: string): WidgetData | undefined {
        return widgetData.value.get(widgetId)
    }

    // Check if widget is loading
    function isWidgetLoading(widgetId: string): boolean {
        return widgetLoading.value.get(widgetId) || false
    }

    // Get widget error
    function getWidgetError(widgetId: string): string | null {
        return widgetErrors.value.get(widgetId) || null
    }

    // Clear all cached widget data
    function clearWidgetCache() {
        widgetData.value.clear()
        widgetLoading.value.clear()
        widgetErrors.value.clear()
    }

    // Initialize on first use
    if (!initialized.value) {
        loadCustomDashboards()
    }

    return {
        // State
        allDashboards,
        dashboardList,
        selectedDashboard,
        customDashboards,

        // Dashboard operations
        selectDashboard,
        createDashboard,
        cloneDashboard,
        updateDashboard,
        deleteDashboard,

        // Widget operations
        addWidget,
        updateWidget,
        removeWidget,

        // Query operations
        executeWidgetQuery,
        refreshDashboard,
        getWidgetData,
        isWidgetLoading,
        getWidgetError,
        clearWidgetCache,

        // Utilities
        parseQueryFields,
        loadCustomDashboards
    }
}
