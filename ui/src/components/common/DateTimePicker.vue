<script setup lang="ts">
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

import { ref, computed, watch } from 'vue'
import { Clock, Calendar, ChevronDown, RefreshCw, X } from 'lucide-vue-next'
import { cn } from '../../lib/utils'
import {
    useTimeRange,
    RELATIVE_TIME_UNITS,
    AUTO_REFRESH_OPTIONS
} from '../../composables/useTimeRange'
import { formatDateForApi } from '../../composables/useFormatters'

const props = withDefaults(defineProps<{
    showAutoRefresh?: boolean
    compact?: boolean
    showModeToggle?: boolean
}>(), {
    showAutoRefresh: false,
    compact: false,
    showModeToggle: true
})

const emit = defineEmits<{
    'change': []
}>()

const {
    isRelativeTime,
    relativeTimeValue,
    relativeTimeUnit,
    dateRange,
    autoRefreshInterval,
    rangeDescription,
    setRelativeTime,
    setAbsoluteTime,
    setAutoRefreshInterval,
    toggleTimeMode
} = useTimeRange()

// Local state for dropdown
const showDropdown = ref(false)
const dropdownRef = ref<HTMLElement | null>(null)

// Absolute time inputs
const absoluteStartDate = ref('')
const absoluteStartTime = ref('')
const absoluteEndDate = ref('')
const absoluteEndTime = ref('')

// Common relative presets
const relativePresets = [
    { label: 'Last 15 minutes', value: 15, unit: 20 }, // RELATIVE_TIME_MINUTES = 20
    { label: 'Last 30 minutes', value: 30, unit: 20 },
    { label: 'Last 1 hour', value: 1, unit: 30 }, // RELATIVE_TIME_HOURS = 30
    { label: 'Last 4 hours', value: 4, unit: 30 },
    { label: 'Last 24 hours', value: 24, unit: 30 },
    { label: 'Last 7 days', value: 7, unit: 40 }, // RELATIVE_TIME_DAYS = 40
    { label: 'Last 30 days', value: 30, unit: 40 }
]

// Sync absolute time inputs when switching to absolute mode
watch(isRelativeTime, (isRelative) => {
    if (!isRelative && dateRange.value) {
        const [startPart, endPart] = dateRange.value.split(' - ')
        if (startPart && endPart) {
            const startDate = new Date(startPart)
            const endDate = new Date(endPart)
            if (!isNaN(startDate.getTime()) && !isNaN(endDate.getTime())) {
                absoluteStartDate.value = startDate.toISOString().split('T')[0]
                absoluteStartTime.value = startDate.toTimeString().slice(0, 5)
                absoluteEndDate.value = endDate.toISOString().split('T')[0]
                absoluteEndTime.value = endDate.toTimeString().slice(0, 5)
            }
        }
    }
})

// Initialize absolute time fields on component mount
function initAbsoluteFields() {
    const now = new Date()
    const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000)
    absoluteStartDate.value = yesterday.toISOString().split('T')[0]
    absoluteStartTime.value = yesterday.toTimeString().slice(0, 5)
    absoluteEndDate.value = now.toISOString().split('T')[0]
    absoluteEndTime.value = now.toTimeString().slice(0, 5)
}
initAbsoluteFields()

function handlePresetClick(preset: { value: number; unit: number }) {
    setRelativeTime(preset.value, preset.unit as any)
    showDropdown.value = false
    emit('change')
}

function handleRelativeValueChange(e: Event) {
    const value = parseInt((e.target as HTMLInputElement).value, 10)
    if (!isNaN(value) && value > 0) {
        setRelativeTime(value, relativeTimeUnit.value)
        emit('change')
    }
}

function handleRelativeUnitChange(e: Event) {
    const unit = parseInt((e.target as HTMLSelectElement).value, 10)
    setRelativeTime(relativeTimeValue.value, unit as any)
    emit('change')
}

function handleApplyAbsolute() {
    if (absoluteStartDate.value && absoluteEndDate.value) {
        const startDateTime = absoluteStartTime.value || '00:00'
        const endDateTime = absoluteEndTime.value || '23:59'

        const start = new Date(`${absoluteStartDate.value}T${startDateTime}:00`)
        const end = new Date(`${absoluteEndDate.value}T${endDateTime}:59`)

        if (!isNaN(start.getTime()) && !isNaN(end.getTime())) {
            setAbsoluteTime(start, end)
            showDropdown.value = false
            emit('change')
        }
    }
}

function handleModeToggle() {
    toggleTimeMode()
    emit('change')
}

function handleAutoRefreshChange(e: Event) {
    const value = parseInt((e.target as HTMLSelectElement).value, 10)
    setAutoRefreshInterval(value)
}

// Close dropdown when clicking outside
function handleClickOutside(e: MouseEvent) {
    if (dropdownRef.value && !dropdownRef.value.contains(e.target as Node)) {
        showDropdown.value = false
    }
}

// Attach/detach click outside listener
watch(showDropdown, (isOpen) => {
    if (isOpen) {
        setTimeout(() => {
            document.addEventListener('click', handleClickOutside)
        }, 0)
    } else {
        document.removeEventListener('click', handleClickOutside)
    }
})
</script>

<template>
    <div ref="dropdownRef" class="relative">
        <!-- Trigger Button -->
        <button
            @click.stop="showDropdown = !showDropdown"
            :class="cn(
                'flex items-center gap-2 rounded-md border border-border bg-background transition-colors hover:bg-muted',
                compact ? 'px-2 py-1.5 text-xs' : 'px-3 py-2 text-sm'
            )"
        >
            <component :is="isRelativeTime ? Clock : Calendar" :class="cn('text-muted-foreground', compact ? 'h-3.5 w-3.5' : 'h-4 w-4')" />
            <span class="font-medium">{{ rangeDescription }}</span>
            <ChevronDown :class="cn('text-muted-foreground transition-transform', compact ? 'h-3.5 w-3.5' : 'h-4 w-4', showDropdown && 'rotate-180')" />
        </button>

        <!-- Dropdown Panel -->
        <Transition
            enter-active-class="transition duration-100 ease-out"
            enter-from-class="opacity-0 scale-95"
            enter-to-class="opacity-100 scale-100"
            leave-active-class="transition duration-75 ease-in"
            leave-from-class="opacity-100 scale-100"
            leave-to-class="opacity-0 scale-95"
        >
            <div
                v-if="showDropdown"
                class="absolute right-0 mt-2 z-50 w-80 rounded-lg border border-border bg-card shadow-lg overflow-hidden"
            >
                <!-- Mode Toggle -->
                <div v-if="showModeToggle" class="flex border-b border-border">
                    <button
                        @click="isRelativeTime = true"
                        :class="cn(
                            'flex-1 px-4 py-2.5 text-sm font-medium transition-colors',
                            isRelativeTime
                                ? 'bg-primary text-primary-foreground'
                                : 'bg-muted/50 text-muted-foreground hover:text-foreground'
                        )"
                    >
                        <Clock class="inline h-4 w-4 mr-1.5" />
                        Relative
                    </button>
                    <button
                        @click="isRelativeTime = false"
                        :class="cn(
                            'flex-1 px-4 py-2.5 text-sm font-medium transition-colors',
                            !isRelativeTime
                                ? 'bg-primary text-primary-foreground'
                                : 'bg-muted/50 text-muted-foreground hover:text-foreground'
                        )"
                    >
                        <Calendar class="inline h-4 w-4 mr-1.5" />
                        Absolute
                    </button>
                </div>

                <!-- Content -->
                <div class="p-4">
                    <!-- Relative Time Mode -->
                    <div v-if="isRelativeTime" class="space-y-4">
                        <!-- Quick Presets -->
                        <div class="grid grid-cols-2 gap-2">
                            <button
                                v-for="preset in relativePresets"
                                :key="preset.label"
                                @click="handlePresetClick(preset)"
                                class="px-3 py-1.5 text-xs font-medium rounded-md border border-border hover:bg-muted transition-colors text-left"
                            >
                                {{ preset.label }}
                            </button>
                        </div>

                        <div class="border-t border-border pt-4">
                            <label class="text-xs font-medium text-muted-foreground block mb-2">Custom relative time</label>
                            <div class="flex items-center gap-2">
                                <span class="text-sm">Last</span>
                                <input
                                    type="number"
                                    min="1"
                                    :value="relativeTimeValue"
                                    @change="handleRelativeValueChange"
                                    class="w-20 px-2 py-1.5 text-sm bg-background border border-border rounded-md focus:outline-none focus:ring-2 focus:ring-primary/50"
                                />
                                <select
                                    :value="relativeTimeUnit"
                                    @change="handleRelativeUnitChange"
                                    class="flex-1 px-2 py-1.5 text-sm bg-background border border-border rounded-md focus:outline-none focus:ring-2 focus:ring-primary/50"
                                >
                                    <option v-for="unit in RELATIVE_TIME_UNITS" :key="unit.value" :value="unit.value">
                                        {{ unit.label.toLowerCase() }}
                                    </option>
                                </select>
                            </div>
                        </div>
                    </div>

                    <!-- Absolute Time Mode -->
                    <div v-else class="space-y-4">
                        <div class="space-y-3">
                            <div>
                                <label class="text-xs font-medium text-muted-foreground block mb-1.5">Start</label>
                                <div class="flex gap-2">
                                    <input
                                        type="date"
                                        v-model="absoluteStartDate"
                                        class="flex-1 px-2 py-1.5 text-sm bg-background border border-border rounded-md focus:outline-none focus:ring-2 focus:ring-primary/50"
                                    />
                                    <input
                                        type="time"
                                        v-model="absoluteStartTime"
                                        class="w-28 px-2 py-1.5 text-sm bg-background border border-border rounded-md focus:outline-none focus:ring-2 focus:ring-primary/50"
                                    />
                                </div>
                            </div>
                            <div>
                                <label class="text-xs font-medium text-muted-foreground block mb-1.5">End</label>
                                <div class="flex gap-2">
                                    <input
                                        type="date"
                                        v-model="absoluteEndDate"
                                        class="flex-1 px-2 py-1.5 text-sm bg-background border border-border rounded-md focus:outline-none focus:ring-2 focus:ring-primary/50"
                                    />
                                    <input
                                        type="time"
                                        v-model="absoluteEndTime"
                                        class="w-28 px-2 py-1.5 text-sm bg-background border border-border rounded-md focus:outline-none focus:ring-2 focus:ring-primary/50"
                                    />
                                </div>
                            </div>
                        </div>

                        <button
                            @click="handleApplyAbsolute"
                            class="w-full px-4 py-2 bg-primary text-primary-foreground text-sm font-medium rounded-md hover:bg-primary/90 transition-colors"
                        >
                            Apply
                        </button>
                    </div>

                    <!-- Auto-refresh -->
                    <div v-if="showAutoRefresh" class="border-t border-border mt-4 pt-4">
                        <label class="text-xs font-medium text-muted-foreground block mb-2">Auto-refresh</label>
                        <div class="flex items-center gap-2">
                            <RefreshCw class="h-4 w-4 text-muted-foreground" />
                            <select
                                :value="autoRefreshInterval"
                                @change="handleAutoRefreshChange"
                                class="flex-1 px-2 py-1.5 text-sm bg-background border border-border rounded-md focus:outline-none focus:ring-2 focus:ring-primary/50"
                            >
                                <option v-for="opt in AUTO_REFRESH_OPTIONS" :key="opt.value" :value="opt.value">
                                    {{ opt.label }}
                                </option>
                            </select>
                        </div>
                    </div>
                </div>
            </div>
        </Transition>
    </div>
</template>
