<script setup lang="ts">
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

import { ref, computed } from 'vue'
import {
    Plus,
    Settings,
    RefreshCw,
    Clock,
    ChevronDown
} from 'lucide-vue-next'
import DashboardSidebar from '../components/dashboards/DashboardSidebar.vue'
import DashboardGrid from '../components/dashboards/DashboardGrid.vue'
import type {
    Dashboard,
    DashboardListItem,
    WidgetData,
    CountWidgetData,
    PieWidgetData,
    BarWidgetData,
    LineWidgetData,
    TableWidgetData,
    SankeyWidgetData,
    MapWidgetData
} from '../types/dashboard'

// =============================================================================
// State
// =============================================================================

const editMode = ref(false)
const selectedDashboardId = ref<string>('security-overview')
const autoRefreshInterval = ref(0) // 0 = disabled
const showTimeRangeMenu = ref(false)
const selectedTimeRange = ref('24h')

const timeRangeOptions = [
    { label: 'Last 15 minutes', value: '15m' },
    { label: 'Last 1 hour', value: '1h' },
    { label: 'Last 4 hours', value: '4h' },
    { label: 'Last 24 hours', value: '24h' },
    { label: 'Last 7 days', value: '7d' },
    { label: 'Last 30 days', value: '30d' }
]

const autoRefreshOptions = [
    { label: 'Off', value: 0 },
    { label: '30s', value: 30 },
    { label: '1m', value: 60 },
    { label: '5m', value: 300 },
    { label: '15m', value: 900 }
]

// =============================================================================
// Mock Data
// =============================================================================

// Generate time series data for the last 24 hours
const generateTimeSeriesData = () => {
    const data = []
    const now = new Date()
    for (let i = 23; i >= 0; i--) {
        const timestamp = new Date(now.getTime() - i * 60 * 60 * 1000)
        data.push({
            timestamp: timestamp.toISOString(),
            value: Math.floor(Math.random() * 2000) + 500
        })
    }
    return data
}

const mockDashboardList: DashboardListItem[] = [
    { id: 'security-overview', name: 'Security Overview', isShared: false, isDefault: true, widgetCount: 10 },
    { id: 'network-traffic', name: 'Network Traffic', isShared: false, isDefault: false, widgetCount: 8 },
    { id: 'endpoint-health', name: 'Endpoint Health', isShared: false, isDefault: false, widgetCount: 5 },
    { id: 'team-dashboard', name: 'SOC Team Dashboard', isShared: true, isDefault: false, widgetCount: 4 },
    { id: 'pew-pew', name: 'Pew Pew Map', isShared: true, isDefault: false, widgetCount: 8 }
]

const mockDashboards: Record<string, Dashboard> = {
    'security-overview': {
        id: 'security-overview',
        name: 'Security Overview',
        description: 'High-level security metrics and alerts',
        isShared: false,
        isDefault: true,
        widgets: [
            // Count widgets (row 1)
            {
                id: 'w1',
                name: 'Total Events',
                type: 'count',
                size: 'sm',
                value: 127453,
                trend: 'up',
                trendPercent: 12
            } as CountWidgetData,
            {
                id: 'w2',
                name: 'Alerts Today',
                type: 'count',
                size: 'sm',
                value: 89,
                color: 'warning',
                trend: 'up',
                trendPercent: 5
            } as CountWidgetData,
            {
                id: 'w3',
                name: 'Open Cases',
                type: 'count',
                size: 'sm',
                value: 7,
                color: 'info'
            } as CountWidgetData,
            {
                id: 'w4',
                name: 'Active Nodes',
                type: 'count',
                size: 'sm',
                value: '12/12',
                color: 'success'
            } as CountWidgetData,

            // Line chart (full width)
            {
                id: 'w5',
                name: 'Events Over Time',
                type: 'line',
                size: 'lg',
                data: generateTimeSeriesData(),
                showArea: true
            } as LineWidgetData,

            // Charts row
            {
                id: 'w6',
                name: 'Top Alert Rules',
                type: 'bar',
                size: 'md',
                data: [
                    { label: 'ET MALWARE Generic Trojan', value: 145 },
                    { label: 'ET SCAN Potential SSH Scan', value: 98 },
                    { label: 'GPL ATTACK_RESPONSE id check', value: 67 },
                    { label: 'ET POLICY PE EXE Download', value: 45 },
                    { label: 'ET INFO Executable Download', value: 32 }
                ],
                orientation: 'horizontal'
            } as BarWidgetData,
            {
                id: 'w7',
                name: 'Events by Protocol',
                type: 'pie',
                size: 'md',
                data: [
                    { label: 'HTTP', value: 45230 },
                    { label: 'DNS', value: 32100 },
                    { label: 'TLS', value: 28450 },
                    { label: 'SSH', value: 8920 },
                    { label: 'SMB', value: 4530 },
                    { label: 'Other', value: 8223 }
                ]
            } as PieWidgetData,

            // Sankey: Alert category to severity flow
            {
                id: 'w9',
                name: 'Alert Category → Severity',
                type: 'sankey',
                size: 'md',
                links: [
                    { source: 'Malware', target: 'Critical', value: 45 },
                    { source: 'Malware', target: 'High', value: 78 },
                    { source: 'Malware', target: 'Medium', value: 22 },
                    { source: 'Exploit', target: 'Critical', value: 12 },
                    { source: 'Exploit', target: 'High', value: 34 },
                    { source: 'Scan/Recon', target: 'Medium', value: 156 },
                    { source: 'Scan/Recon', target: 'Low', value: 89 },
                    { source: 'Policy', target: 'Medium', value: 67 },
                    { source: 'Policy', target: 'Low', value: 234 },
                    { source: 'Suspicious', target: 'High', value: 45 },
                    { source: 'Suspicious', target: 'Medium', value: 112 }
                ]
            } as SankeyWidgetData,

            // Sankey: Source network to destination
            {
                id: 'w10',
                name: 'Alert Source → Destination',
                type: 'sankey',
                size: 'md',
                links: [
                    { source: '192.168.1.0/24', target: 'External IPs', value: 145 },
                    { source: '192.168.1.0/24', target: '10.0.0.0/8', value: 67 },
                    { source: '192.168.1.0/24', target: 'DMZ', value: 23 },
                    { source: '10.0.0.0/8', target: 'External IPs', value: 89 },
                    { source: '10.0.0.0/8', target: '192.168.1.0/24', value: 34 },
                    { source: 'External IPs', target: '192.168.1.0/24', value: 178 },
                    { source: 'External IPs', target: 'DMZ', value: 56 }
                ]
            } as SankeyWidgetData,

            // Table (full width)
            {
                id: 'w8',
                name: 'Recent High Severity Alerts',
                type: 'table',
                size: 'lg',
                columns: [
                    { key: 'timestamp', label: 'Time', width: '140px' },
                    { key: 'rule', label: 'Rule' },
                    { key: 'source', label: 'Source IP', width: '130px' },
                    { key: 'dest', label: 'Dest IP', width: '130px' },
                    { key: 'severity', label: 'Severity', width: '80px' }
                ],
                rows: [
                    { timestamp: '2025-01-13 14:32:15', rule: 'ET MALWARE Generic Trojan Activity', source: '192.168.1.105', dest: '203.0.113.42', severity: 'High' },
                    { timestamp: '2025-01-13 14:28:44', rule: 'ET SCAN Potential SSH Scan OUTBOUND', source: '192.168.1.22', dest: '10.0.0.0/8', severity: 'Medium' },
                    { timestamp: '2025-01-13 14:25:11', rule: 'GPL ATTACK_RESPONSE id check returned root', source: '192.168.1.50', dest: '192.168.1.1', severity: 'High' },
                    { timestamp: '2025-01-13 14:22:08', rule: 'ET POLICY PE EXE or DLL Windows file download', source: '192.168.1.88', dest: '151.101.1.140', severity: 'Low' },
                    { timestamp: '2025-01-13 14:18:55', rule: 'ET INFO Executable Download from dotted-quad Host', source: '192.168.1.33', dest: '45.33.32.156', severity: 'Medium' }
                ],
                maxRows: 5
            } as TableWidgetData
        ]
    },
    'network-traffic': {
        id: 'network-traffic',
        name: 'Network Traffic',
        description: 'Network traffic analysis and monitoring',
        isShared: false,
        isDefault: false,
        widgets: [
            {
                id: 'n1',
                name: 'Total Connections',
                type: 'count',
                size: 'sm',
                value: 2847563,
                trend: 'up',
                trendPercent: 8
            } as CountWidgetData,
            {
                id: 'n2',
                name: 'Unique Source IPs',
                type: 'count',
                size: 'sm',
                value: 1247
            } as CountWidgetData,
            {
                id: 'n3',
                name: 'Unique Dest IPs',
                type: 'count',
                size: 'sm',
                value: 3892
            } as CountWidgetData,
            {
                id: 'n4',
                name: 'Bytes Transferred',
                type: 'count',
                size: 'sm',
                value: '1.2 TB'
            } as CountWidgetData,
            {
                id: 'n5',
                name: 'Traffic by Protocol',
                type: 'pie',
                size: 'md',
                data: [
                    { label: 'TCP', value: 78 },
                    { label: 'UDP', value: 18 },
                    { label: 'ICMP', value: 3 },
                    { label: 'Other', value: 1 }
                ]
            } as PieWidgetData,
            {
                id: 'n6',
                name: 'Top Destination Ports',
                type: 'bar',
                size: 'md',
                data: [
                    { label: '443 (HTTPS)', value: 125000 },
                    { label: '80 (HTTP)', value: 45000 },
                    { label: '53 (DNS)', value: 32000 },
                    { label: '22 (SSH)', value: 8500 },
                    { label: '3389 (RDP)', value: 2100 }
                ],
                orientation: 'horizontal'
            } as BarWidgetData,

            // Sankey: Source IP to Destination Port flow
            {
                id: 'n7',
                name: 'Source IP → Destination Port',
                type: 'sankey',
                size: 'md',
                links: [
                    { source: '192.168.1.10', target: 'HTTPS (443)', value: 45000 },
                    { source: '192.168.1.10', target: 'HTTP (80)', value: 12000 },
                    { source: '192.168.1.10', target: 'DNS (53)', value: 8000 },
                    { source: '192.168.1.22', target: 'HTTPS (443)', value: 32000 },
                    { source: '192.168.1.22', target: 'SSH (22)', value: 5500 },
                    { source: '192.168.1.50', target: 'HTTPS (443)', value: 28000 },
                    { source: '192.168.1.50', target: 'HTTP (80)', value: 18000 },
                    { source: '192.168.1.50', target: 'DNS (53)', value: 15000 },
                    { source: '192.168.1.88', target: 'HTTP (80)', value: 15000 },
                    { source: '192.168.1.88', target: 'RDP (3389)', value: 2100 }
                ]
            } as SankeyWidgetData,

            // Sankey: Internal to External traffic flow
            {
                id: 'n8',
                name: 'Network Zone Traffic Flow',
                type: 'sankey',
                size: 'md',
                links: [
                    { source: 'Workstations', target: 'Internet', value: 125000 },
                    { source: 'Workstations', target: 'DMZ', value: 45000 },
                    { source: 'Workstations', target: 'Servers', value: 78000 },
                    { source: 'Servers', target: 'Internet', value: 32000 },
                    { source: 'Servers', target: 'DMZ', value: 18000 },
                    { source: 'DMZ', target: 'Internet', value: 95000 },
                    { source: 'IoT Devices', target: 'Internet', value: 8500 },
                    { source: 'IoT Devices', target: 'Servers', value: 3200 }
                ]
            } as SankeyWidgetData
        ]
    },
    'endpoint-health': {
        id: 'endpoint-health',
        name: 'Endpoint Health',
        description: 'Endpoint status and health metrics',
        isShared: false,
        isDefault: false,
        widgets: [
            {
                id: 'e1',
                name: 'Total Endpoints',
                type: 'count',
                size: 'sm',
                value: 156
            } as CountWidgetData,
            {
                id: 'e2',
                name: 'Online',
                type: 'count',
                size: 'sm',
                value: 148,
                color: 'success'
            } as CountWidgetData,
            {
                id: 'e3',
                name: 'Offline',
                type: 'count',
                size: 'sm',
                value: 8,
                color: 'danger'
            } as CountWidgetData,
            {
                id: 'e4',
                name: 'Pending Updates',
                type: 'count',
                size: 'sm',
                value: 23,
                color: 'warning'
            } as CountWidgetData,
            {
                id: 'e5',
                name: 'Endpoint Status',
                type: 'donut',
                size: 'md',
                data: [
                    { label: 'Healthy', value: 132 },
                    { label: 'Warning', value: 16 },
                    { label: 'Critical', value: 8 }
                ]
            } as PieWidgetData
        ]
    },
    'team-dashboard': {
        id: 'team-dashboard',
        name: 'SOC Team Dashboard',
        description: 'Shared dashboard for the SOC team',
        isShared: true,
        isDefault: false,
        widgets: [
            {
                id: 't1',
                name: 'Alerts Pending Review',
                type: 'count',
                size: 'sm',
                value: 34,
                color: 'warning'
            } as CountWidgetData,
            {
                id: 't2',
                name: 'Cases In Progress',
                type: 'count',
                size: 'sm',
                value: 12
            } as CountWidgetData,
            {
                id: 't3',
                name: 'Resolved Today',
                type: 'count',
                size: 'sm',
                value: 47,
                color: 'success'
            } as CountWidgetData,
            {
                id: 't4',
                name: 'Avg Response Time',
                type: 'count',
                size: 'sm',
                value: '14m'
            } as CountWidgetData
        ]
    },
    'pew-pew': {
        id: 'pew-pew',
        name: 'Pew Pew Map',
        description: 'Real-time global threat visualization',
        isShared: true,
        isDefault: false,
        widgets: [
            // Stats row
            {
                id: 'pp1',
                name: 'Attacks Detected',
                type: 'count',
                size: 'sm',
                value: 12847,
                color: 'danger',
                trend: 'up',
                trendPercent: 23
            } as CountWidgetData,
            {
                id: 'pp2',
                name: 'Attacks Blocked',
                type: 'count',
                size: 'sm',
                value: 11923,
                color: 'success'
            } as CountWidgetData,
            {
                id: 'pp3',
                name: 'Unique Sources',
                type: 'count',
                size: 'sm',
                value: 847
            } as CountWidgetData,
            {
                id: 'pp4',
                name: 'Target Countries',
                type: 'count',
                size: 'sm',
                value: 12
            } as CountWidgetData,

            // Main Pew Pew Map - Full Width
            {
                id: 'pp5',
                name: 'Global Threat Map',
                type: 'map',
                size: 'lg',
                connections: [
                    // Attacks from Russia
                    { from: 'russia-west', to: 'us-east', count: 2340, type: 'attack' },
                    { from: 'russia-west', to: 'germany', count: 1890, type: 'attack' },
                    { from: 'russia-west', to: 'uk', count: 1245, type: 'attack' },
                    { from: 'russia-east', to: 'japan', count: 890, type: 'scan' },

                    // Attacks from China
                    { from: 'china', to: 'us-west', count: 3210, type: 'attack' },
                    { from: 'china', to: 'us-east', count: 2890, type: 'attack' },
                    { from: 'china', to: 'australia', count: 1567, type: 'scan' },
                    { from: 'china', to: 'japan', count: 1234, type: 'attack' },
                    { from: 'china', to: 'india', count: 890, type: 'scan' },

                    // Attacks from Iran
                    { from: 'iran', to: 'israel', count: 2100, type: 'attack' },
                    { from: 'iran', to: 'uae', count: 780, type: 'attack' },
                    { from: 'iran', to: 'us-east', count: 1560, type: 'attack' },

                    // Attacks from North Korea
                    { from: 'korea', to: 'us-west', count: 1890, type: 'attack' },
                    { from: 'korea', to: 'japan', count: 2340, type: 'attack' },
                    { from: 'korea', to: 'korea', count: 450, type: 'scan' },

                    // Scans from various locations
                    { from: 'brazil', to: 'us-east', count: 670, type: 'scan' },
                    { from: 'nigeria', to: 'uk', count: 890, type: 'scan' },
                    { from: 'netherlands', to: 'us-east', count: 1230, type: 'blocked' },

                    // Blocked attacks
                    { from: 'russia-west', to: 'us-central', count: 3400, type: 'blocked' },
                    { from: 'china', to: 'germany', count: 2100, type: 'blocked' }
                ]
            } as MapWidgetData,

            // Attack source breakdown
            {
                id: 'pp6',
                name: 'Top Attack Sources',
                type: 'bar',
                size: 'md',
                data: [
                    { label: 'China', value: 8791 },
                    { label: 'Russia', value: 5475 },
                    { label: 'Iran', value: 4440 },
                    { label: 'North Korea', value: 4680 },
                    { label: 'Brazil', value: 670 }
                ],
                orientation: 'horizontal'
            } as BarWidgetData,

            // Attack type distribution
            {
                id: 'pp7',
                name: 'Attack Types',
                type: 'pie',
                size: 'md',
                data: [
                    { label: 'DDoS', value: 4230 },
                    { label: 'Brute Force', value: 3890 },
                    { label: 'SQL Injection', value: 2340 },
                    { label: 'XSS', value: 1245 },
                    { label: 'Port Scan', value: 1142 }
                ]
            } as PieWidgetData,

            // Flow from source to attack type
            {
                id: 'pp8',
                name: 'Source → Attack Type',
                type: 'sankey',
                size: 'lg',
                links: [
                    { source: 'China', target: 'DDoS', value: 2500 },
                    { source: 'China', target: 'Brute Force', value: 3200 },
                    { source: 'China', target: 'SQL Injection', value: 1890 },
                    { source: 'Russia', target: 'DDoS', value: 1200 },
                    { source: 'Russia', target: 'Brute Force', value: 890 },
                    { source: 'Russia', target: 'XSS', value: 780 },
                    { source: 'Iran', target: 'DDoS', value: 530 },
                    { source: 'Iran', target: 'SQL Injection', value: 450 },
                    { source: 'N. Korea', target: 'DDoS', value: 2100 },
                    { source: 'N. Korea', target: 'Port Scan', value: 1142 }
                ]
            } as SankeyWidgetData
        ]
    }
}

// =============================================================================
// Computed
// =============================================================================

const currentDashboard = computed(() => {
    return mockDashboards[selectedDashboardId.value] || null
})

const currentTimeRangeLabel = computed(() => {
    return timeRangeOptions.find(o => o.value === selectedTimeRange.value)?.label || 'Select time range'
})

// =============================================================================
// Methods
// =============================================================================

const selectDashboard = (id: string) => {
    selectedDashboardId.value = id
}

const createDashboard = () => {
    // Mockup - would open a modal
    console.log('Create dashboard clicked')
    alert('Create Dashboard modal would open here')
}

const handleWidgetEdit = (widget: WidgetData) => {
    console.log('Edit widget:', widget)
    alert(`Edit widget: ${widget.name}`)
}

const handleWidgetDelete = (widget: WidgetData) => {
    console.log('Delete widget:', widget)
    alert(`Delete widget: ${widget.name}`)
}

const handleWidgetMaximize = (widget: WidgetData) => {
    console.log('Maximize widget:', widget)
    alert(`Maximize widget: ${widget.name}`)
}

const handleWidgetRefresh = (widget: WidgetData) => {
    console.log('Refresh widget:', widget)
}

const selectTimeRange = (value: string) => {
    selectedTimeRange.value = value
    showTimeRangeMenu.value = false
}
</script>

<template>
    <div class="flex h-[calc(100vh-64px)] bg-background">
        <!-- Sidebar -->
        <DashboardSidebar
            :dashboards="mockDashboardList"
            :selected-id="selectedDashboardId"
            @select="selectDashboard"
            @create="createDashboard"
        />

        <!-- Main Content -->
        <div class="flex-1 flex flex-col overflow-hidden">
            <!-- Header Bar -->
            <div class="flex items-center justify-between px-6 py-4 border-b border-border bg-card/50">
                <div>
                    <h1 class="text-xl font-semibold">{{ currentDashboard?.name }}</h1>
                    <p v-if="currentDashboard?.description" class="text-sm text-muted-foreground">
                        {{ currentDashboard.description }}
                    </p>
                </div>

                <div class="flex items-center gap-3">
                    <!-- Time Range Selector -->
                    <div class="relative">
                        <button
                            @click="showTimeRangeMenu = !showTimeRangeMenu"
                            class="flex items-center gap-2 px-3 py-2 rounded-md border border-border bg-background text-sm hover:bg-muted transition-colors"
                        >
                            <Clock class="h-4 w-4 text-muted-foreground" />
                            {{ currentTimeRangeLabel }}
                            <ChevronDown class="h-4 w-4 text-muted-foreground" />
                        </button>

                        <div
                            v-if="showTimeRangeMenu"
                            @click="showTimeRangeMenu = false"
                            class="fixed inset-0 z-40"
                        />

                        <div
                            v-if="showTimeRangeMenu"
                            class="absolute right-0 top-full mt-1 w-48 rounded-md border border-border bg-popover shadow-lg z-50"
                        >
                            <div class="py-1">
                                <button
                                    v-for="option in timeRangeOptions"
                                    :key="option.value"
                                    @click="selectTimeRange(option.value)"
                                    :class="[
                                        'w-full px-3 py-2 text-sm text-left transition-colors',
                                        selectedTimeRange === option.value
                                            ? 'bg-primary text-primary-foreground'
                                            : 'text-foreground hover:bg-muted'
                                    ]"
                                >
                                    {{ option.label }}
                                </button>
                            </div>
                        </div>
                    </div>

                    <!-- Auto Refresh -->
                    <select
                        v-model="autoRefreshInterval"
                        class="px-3 py-2 rounded-md border border-border bg-background text-sm focus:outline-none focus:ring-2 focus:ring-primary"
                    >
                        <option v-for="opt in autoRefreshOptions" :key="opt.value" :value="opt.value">
                            {{ opt.value === 0 ? 'Auto-refresh: Off' : `Refresh: ${opt.label}` }}
                        </option>
                    </select>

                    <!-- Add Widget Button -->
                    <button
                        @click="editMode = !editMode"
                        :class="[
                            'flex items-center gap-2 px-3 py-2 rounded-md text-sm font-medium transition-colors',
                            editMode
                                ? 'bg-primary text-primary-foreground'
                                : 'border border-border hover:bg-muted'
                        ]"
                    >
                        <Settings class="h-4 w-4" />
                        {{ editMode ? 'Done Editing' : 'Edit Dashboard' }}
                    </button>

                    <button
                        v-if="editMode"
                        class="flex items-center gap-2 px-3 py-2 rounded-md bg-primary text-primary-foreground text-sm font-medium hover:bg-primary/90 transition-colors"
                    >
                        <Plus class="h-4 w-4" />
                        Add Widget
                    </button>
                </div>
            </div>

            <!-- Dashboard Grid -->
            <div class="flex-1 overflow-auto p-6">
                <DashboardGrid
                    v-if="currentDashboard"
                    :widgets="currentDashboard.widgets"
                    :edit-mode="editMode"
                    @edit-widget="handleWidgetEdit"
                    @delete-widget="handleWidgetDelete"
                    @maximize-widget="handleWidgetMaximize"
                    @refresh-widget="handleWidgetRefresh"
                />

                <!-- No Dashboard Selected -->
                <div
                    v-else
                    class="flex flex-col items-center justify-center h-full text-muted-foreground"
                >
                    <div class="text-lg font-medium mb-2">Select a dashboard</div>
                    <div class="text-sm">Choose a dashboard from the sidebar or create a new one</div>
                </div>
            </div>
        </div>
    </div>
</template>
