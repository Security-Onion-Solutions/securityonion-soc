<script setup lang="ts">
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

import { ref, computed, watch, onMounted, onUnmounted } from 'vue'
import {
    Plus,
    Settings,
    RefreshCw,
    Clock,
    ChevronDown,
    Copy,
    Trash2,
    Loader2
} from 'lucide-vue-next'
import DashboardSidebar from '../components/dashboards/DashboardSidebar.vue'
import DashboardGrid from '../components/dashboards/DashboardGrid.vue'
import { useDashboards, type DashboardConfig, type WidgetConfig } from '../composables/useDashboards'
import type { WidgetData } from '../types/dashboard'

// =============================================================================
// Composables
// =============================================================================

const {
    dashboardList,
    selectedDashboard,
    selectDashboard: selectDashboardFromComposable,
    createDashboard,
    cloneDashboard,
    deleteDashboard,
    refreshDashboard,
    getWidgetData,
    isWidgetLoading,
    getWidgetError,
    clearWidgetCache
} = useDashboards()

// =============================================================================
// State
// =============================================================================

const editMode = ref(false)
const showTimeRangeMenu = ref(false)
const selectedTimeRange = ref('24h')
const loading = ref(false)
const refreshTimer = ref<ReturnType<typeof setInterval> | null>(null)
const autoRefreshInterval = ref(0) // 0 = disabled

const timeRangeOptions = [
    { label: 'Last 15 minutes', value: '15m', minutes: 15 },
    { label: 'Last 1 hour', value: '1h', minutes: 60 },
    { label: 'Last 4 hours', value: '4h', minutes: 240 },
    { label: 'Last 24 hours', value: '24h', minutes: 1440 },
    { label: 'Last 7 days', value: '7d', minutes: 10080 },
    { label: 'Last 30 days', value: '30d', minutes: 43200 }
]

const autoRefreshOptions = [
    { label: 'Off', value: 0 },
    { label: '30s', value: 30 },
    { label: '1m', value: 60 },
    { label: '5m', value: 300 },
    { label: '15m', value: 900 }
]

// Dialog state
const showCreateDialog = ref(false)
const showCloneDialog = ref(false)
const newDashboardName = ref('')
const cloneSourceId = ref('')

// =============================================================================
// Computed
// =============================================================================

const currentTimeRangeLabel = computed(() => {
    return timeRangeOptions.find(o => o.value === selectedTimeRange.value)?.label || 'Select time range'
})

const currentTimeRangeMinutes = computed(() => {
    return timeRangeOptions.find(o => o.value === selectedTimeRange.value)?.minutes || 1440
})

// Build widgets with real data
const dashboardWidgets = computed((): WidgetData[] => {
    if (!selectedDashboard.value) return []

    return selectedDashboard.value.widgets.map(widgetConfig => {
        const cachedData = getWidgetData(widgetConfig.id)
        if (cachedData) {
            return cachedData
        }

        // Return a placeholder widget while loading
        // Determine the base type for rendering
        const getPlaceholderType = (type: string) => {
            if (type === 'alertMap' || type === 'connectionMap') return 'map'
            if (type === 'sankey') return 'sankey'
            if (type === 'table') return 'table'
            if (type === 'bar') return 'bar'
            if (type === 'pie' || type === 'donut') return 'pie'
            return 'count'
        }

        return {
            id: widgetConfig.id,
            name: widgetConfig.name,
            type: getPlaceholderType(widgetConfig.type),
            size: widgetConfig.size,
            // Type-specific placeholders
            ...(widgetConfig.type === 'count' ? { value: '...' } : {}),
            ...(widgetConfig.type === 'pie' || widgetConfig.type === 'donut' ? { data: [] } : {}),
            ...(widgetConfig.type === 'bar' ? { data: [], orientation: 'horizontal' as const } : {}),
            ...(widgetConfig.type === 'sankey' ? { links: [] } : {}),
            ...(widgetConfig.type === 'table' ? { columns: [], rows: [] } : {}),
            ...(widgetConfig.type === 'line' ? { data: [], showArea: false } : {}),
            ...(widgetConfig.type === 'map' ? { mapMode: 'connections' as const, connections: [] } : {}),
            ...(widgetConfig.type === 'alertMap' ? { mapMode: 'alerts' as const, markers: [] } : {}),
            ...(widgetConfig.type === 'connectionMap' ? { mapMode: 'connections' as const, connections: [] } : {})
        } as WidgetData
    })
})

// =============================================================================
// Methods
// =============================================================================

const handleSelectDashboard = (id: string) => {
    selectDashboardFromComposable(id)
    loadDashboard()
}

const loadDashboard = async () => {
    if (!selectedDashboard.value) return

    loading.value = true
    try {
        await refreshDashboard(
            selectedDashboard.value,
            {
                dateRange: selectedTimeRange.value,
                dateRangeMinutes: currentTimeRangeMinutes.value
            }
        )
    } catch (e) {
        console.error('Failed to load dashboard:', e)
    } finally {
        loading.value = false
    }
}

const handleRefresh = async () => {
    clearWidgetCache()
    await loadDashboard()
}

const handleCreateDashboard = () => {
    if (!newDashboardName.value.trim()) return

    const dashboard = createDashboard(newDashboardName.value.trim())
    selectDashboardFromComposable(dashboard.id)
    newDashboardName.value = ''
    showCreateDialog.value = false
}

const handleCloneDashboard = () => {
    if (!newDashboardName.value.trim() || !selectedDashboard.value) return

    const cloned = cloneDashboard(selectedDashboard.value.id, newDashboardName.value.trim())
    if (cloned) {
        selectDashboardFromComposable(cloned.id)
    }
    newDashboardName.value = ''
    showCloneDialog.value = false
}

const handleDeleteDashboard = () => {
    if (!selectedDashboard.value || selectedDashboard.value.isDefault) return

    if (confirm(`Delete dashboard "${selectedDashboard.value.name}"?`)) {
        deleteDashboard(selectedDashboard.value.id)
    }
}

const handleWidgetEdit = (widget: WidgetData) => {
    console.log('Edit widget:', widget)
    alert(`Edit widget: ${widget.name}\n\nWidget editing UI coming soon.`)
}

const handleWidgetDelete = (widget: WidgetData) => {
    console.log('Delete widget:', widget)
    alert(`Delete widget: ${widget.name}`)
}

const handleWidgetMaximize = (widget: WidgetData) => {
    console.log('Maximize widget:', widget)
}

const handleWidgetRefresh = async (widget: WidgetData) => {
    if (!selectedDashboard.value) return

    const widgetConfig = selectedDashboard.value.widgets.find(w => w.id === widget.id)
    if (!widgetConfig) return

    const { executeWidgetQuery } = useDashboards()
    await executeWidgetQuery(widgetConfig, {
        dateRange: selectedTimeRange.value,
        dateRangeMinutes: currentTimeRangeMinutes.value
    })
}

const selectTimeRange = (value: string) => {
    selectedTimeRange.value = value
    showTimeRangeMenu.value = false
    clearWidgetCache()
    loadDashboard()
}

const setupAutoRefresh = () => {
    if (refreshTimer.value) {
        clearInterval(refreshTimer.value)
        refreshTimer.value = null
    }

    if (autoRefreshInterval.value > 0) {
        refreshTimer.value = setInterval(() => {
            loadDashboard()
        }, autoRefreshInterval.value * 1000)
    }
}

// =============================================================================
// Watchers
// =============================================================================

watch(autoRefreshInterval, () => {
    setupAutoRefresh()
})

watch(selectedDashboard, () => {
    loadDashboard()
})

// =============================================================================
// Lifecycle
// =============================================================================

onMounted(() => {
    loadDashboard()
})

onUnmounted(() => {
    if (refreshTimer.value) {
        clearInterval(refreshTimer.value)
    }
})
</script>

<template>
    <div class="flex h-[calc(100vh-64px)] bg-background">
        <!-- Sidebar -->
        <DashboardSidebar
            :dashboards="dashboardList"
            :selected-id="selectedDashboard?.id || ''"
            @select="handleSelectDashboard"
            @create="showCreateDialog = true"
        />

        <!-- Main Content -->
        <div class="flex-1 flex flex-col overflow-hidden">
            <!-- Header Bar -->
            <div class="flex items-center justify-between px-6 py-4 border-b border-border bg-card/50">
                <div class="flex items-center gap-3">
                    <div>
                        <h1 class="text-xl font-semibold">{{ selectedDashboard?.name }}</h1>
                        <p v-if="selectedDashboard?.description" class="text-sm text-muted-foreground">
                            {{ selectedDashboard.description }}
                        </p>
                    </div>
                    <Loader2 v-if="loading" class="h-4 w-4 animate-spin text-muted-foreground" />
                </div>

                <div class="flex items-center gap-3">
                    <!-- Refresh Button -->
                    <button
                        @click="handleRefresh"
                        :disabled="loading"
                        class="flex items-center gap-2 px-3 py-2 rounded-md border border-border hover:bg-muted transition-colors disabled:opacity-50"
                        title="Refresh dashboard"
                    >
                        <RefreshCw :class="['h-4 w-4', loading && 'animate-spin']" />
                    </button>

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

                    <!-- Clone Dashboard Button (for default dashboards) -->
                    <button
                        v-if="selectedDashboard?.isDefault"
                        @click="showCloneDialog = true"
                        class="flex items-center gap-2 px-3 py-2 rounded-md border border-border hover:bg-muted text-sm transition-colors"
                        title="Clone this dashboard to customize it"
                    >
                        <Copy class="h-4 w-4" />
                        Clone
                    </button>

                    <!-- Delete Dashboard Button (for custom dashboards) -->
                    <button
                        v-if="selectedDashboard && !selectedDashboard.isDefault"
                        @click="handleDeleteDashboard"
                        class="flex items-center gap-2 px-3 py-2 rounded-md border border-destructive text-destructive hover:bg-destructive hover:text-destructive-foreground text-sm transition-colors"
                        title="Delete this dashboard"
                    >
                        <Trash2 class="h-4 w-4" />
                    </button>

                    <!-- Edit Dashboard Button -->
                    <button
                        v-if="selectedDashboard && !selectedDashboard.isDefault"
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
                    v-if="selectedDashboard"
                    :widgets="dashboardWidgets"
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

        <!-- Create Dashboard Dialog -->
        <div
            v-if="showCreateDialog"
            class="fixed inset-0 z-50 flex items-center justify-center bg-black/50"
        >
            <div class="bg-card rounded-lg shadow-lg w-full max-w-md p-6 border border-border">
                <h2 class="text-lg font-semibold mb-4">Create New Dashboard</h2>
                <div class="space-y-4">
                    <div>
                        <label class="block text-sm font-medium mb-1">Dashboard Name</label>
                        <input
                            v-model="newDashboardName"
                            type="text"
                            class="w-full px-3 py-2 rounded-md border border-border bg-background text-sm focus:outline-none focus:ring-2 focus:ring-primary"
                            placeholder="My Dashboard"
                            @keyup.enter="handleCreateDashboard"
                        />
                    </div>
                    <div class="flex justify-end gap-2">
                        <button
                            @click="showCreateDialog = false; newDashboardName = ''"
                            class="px-4 py-2 rounded-md border border-border hover:bg-muted text-sm transition-colors"
                        >
                            Cancel
                        </button>
                        <button
                            @click="handleCreateDashboard"
                            :disabled="!newDashboardName.trim()"
                            class="px-4 py-2 rounded-md bg-primary text-primary-foreground text-sm font-medium hover:bg-primary/90 transition-colors disabled:opacity-50"
                        >
                            Create
                        </button>
                    </div>
                </div>
            </div>
        </div>

        <!-- Clone Dashboard Dialog -->
        <div
            v-if="showCloneDialog"
            class="fixed inset-0 z-50 flex items-center justify-center bg-black/50"
        >
            <div class="bg-card rounded-lg shadow-lg w-full max-w-md p-6 border border-border">
                <h2 class="text-lg font-semibold mb-4">Clone Dashboard</h2>
                <p class="text-sm text-muted-foreground mb-4">
                    Create a copy of "{{ selectedDashboard?.name }}" that you can customize.
                </p>
                <div class="space-y-4">
                    <div>
                        <label class="block text-sm font-medium mb-1">New Dashboard Name</label>
                        <input
                            v-model="newDashboardName"
                            type="text"
                            class="w-full px-3 py-2 rounded-md border border-border bg-background text-sm focus:outline-none focus:ring-2 focus:ring-primary"
                            :placeholder="`${selectedDashboard?.name} (Copy)`"
                            @keyup.enter="handleCloneDashboard"
                        />
                    </div>
                    <div class="flex justify-end gap-2">
                        <button
                            @click="showCloneDialog = false; newDashboardName = ''"
                            class="px-4 py-2 rounded-md border border-border hover:bg-muted text-sm transition-colors"
                        >
                            Cancel
                        </button>
                        <button
                            @click="handleCloneDashboard"
                            :disabled="!newDashboardName.trim()"
                            class="px-4 py-2 rounded-md bg-primary text-primary-foreground text-sm font-medium hover:bg-primary/90 transition-colors disabled:opacity-50"
                        >
                            Clone
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>
</template>
