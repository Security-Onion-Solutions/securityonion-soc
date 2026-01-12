// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

import { ref, computed } from 'vue'
import {
    RELATIVE_TIME_SECONDS,
    RELATIVE_TIME_MINUTES,
    RELATIVE_TIME_HOURS,
    RELATIVE_TIME_DAYS,
    RELATIVE_TIME_WEEKS,
    RELATIVE_TIME_MONTHS,
    type RelativeTimeUnit,
    type AutoRefreshOption
} from '../types/hunt'
import { formatDateForApi } from './useFormatters'

// =============================================================================
// Module-level state (shared across components)
// =============================================================================

const isRelativeTime = ref(true)
const relativeTimeValue = ref(24)
const relativeTimeUnit = ref<RelativeTimeUnit>(RELATIVE_TIME_HOURS)
const dateRange = ref('')
const zone = ref(Intl.DateTimeFormat().resolvedOptions().timeZone)
const autoRefreshInterval = ref(0)

let autoRefreshTimer: ReturnType<typeof setTimeout> | null = null
let autoRefreshCallback: (() => void) | null = null

// =============================================================================
// Constants
// =============================================================================

export const RELATIVE_TIME_UNITS: { label: string; value: RelativeTimeUnit }[] = [
    { label: 'Seconds', value: RELATIVE_TIME_SECONDS },
    { label: 'Minutes', value: RELATIVE_TIME_MINUTES },
    { label: 'Hours', value: RELATIVE_TIME_HOURS },
    { label: 'Days', value: RELATIVE_TIME_DAYS },
    { label: 'Weeks', value: RELATIVE_TIME_WEEKS },
    { label: 'Months', value: RELATIVE_TIME_MONTHS }
]

export const AUTO_REFRESH_OPTIONS: AutoRefreshOption[] = [
    { label: 'Off', value: 0 },
    { label: '5s', value: 5 },
    { label: '10s', value: 10 },
    { label: '15s', value: 15 },
    { label: '30s', value: 30 },
    { label: '1m', value: 60 },
    { label: '2m', value: 120 },
    { label: '5m', value: 300 },
    { label: '10m', value: 600 },
    { label: '30m', value: 1800 },
    { label: '1h', value: 3600 }
]

// =============================================================================
// Helper functions
// =============================================================================

function getRelativeTimeUnitString(unit: RelativeTimeUnit): string {
    switch (unit) {
        case RELATIVE_TIME_SECONDS:
            return 'seconds'
        case RELATIVE_TIME_MINUTES:
            return 'minutes'
        case RELATIVE_TIME_HOURS:
            return 'hours'
        case RELATIVE_TIME_DAYS:
            return 'days'
        case RELATIVE_TIME_WEEKS:
            return 'weeks'
        case RELATIVE_TIME_MONTHS:
            return 'months'
        default:
            return 'hours'
    }
}

function subtractTime(date: Date, value: number, unit: RelativeTimeUnit): Date {
    const result = new Date(date)
    switch (unit) {
        case RELATIVE_TIME_SECONDS:
            result.setSeconds(result.getSeconds() - value)
            break
        case RELATIVE_TIME_MINUTES:
            result.setMinutes(result.getMinutes() - value)
            break
        case RELATIVE_TIME_HOURS:
            result.setHours(result.getHours() - value)
            break
        case RELATIVE_TIME_DAYS:
            result.setDate(result.getDate() - value)
            break
        case RELATIVE_TIME_WEEKS:
            result.setDate(result.getDate() - (value * 7))
            break
        case RELATIVE_TIME_MONTHS:
            result.setMonth(result.getMonth() - value)
            break
    }
    return result
}

function parseDateRange(range: string): { start: Date; end: Date } | null {
    if (!range || !range.includes(' - ')) return null
    const pieces = range.split(' - ')
    if (pieces.length !== 2) return null

    const start = new Date(pieces[0])
    const end = new Date(pieces[1])

    if (isNaN(start.getTime()) || isNaN(end.getTime())) return null

    return { start, end }
}

// =============================================================================
// Composable
// =============================================================================

export function useTimeRange() {
    // Computed: Get start date based on relative or absolute time
    const startDate = computed<Date>(() => {
        if (isRelativeTime.value) {
            return subtractTime(new Date(), relativeTimeValue.value, relativeTimeUnit.value)
        }

        const parsed = parseDateRange(dateRange.value)
        return parsed ? parsed.start : subtractTime(new Date(), 24, RELATIVE_TIME_HOURS)
    })

    // Computed: Get end date based on relative or absolute time
    const endDate = computed<Date>(() => {
        if (isRelativeTime.value) {
            return new Date()
        }

        const parsed = parseDateRange(dateRange.value)
        return parsed ? parsed.end : new Date()
    })

    // Computed: Format date range for API calls
    const formattedRange = computed<string>(() => {
        return `${formatDateForApi(startDate.value)} - ${formatDateForApi(endDate.value)}`
    })

    // Computed: Human readable time range description
    const rangeDescription = computed<string>(() => {
        if (isRelativeTime.value) {
            const unitStr = getRelativeTimeUnitString(relativeTimeUnit.value)
            return `Last ${relativeTimeValue.value} ${unitStr}`
        }
        return dateRange.value || 'Custom range'
    })

    // Set relative time
    function setRelativeTime(value: number, unit: RelativeTimeUnit) {
        isRelativeTime.value = true
        relativeTimeValue.value = value
        relativeTimeUnit.value = unit
        dateRange.value = ''
    }

    // Set absolute time range
    function setAbsoluteTime(start: Date, end: Date) {
        isRelativeTime.value = false
        dateRange.value = `${formatDateForApi(start)} - ${formatDateForApi(end)}`
    }

    // Set epoch time (for detections - from epoch 0 to now)
    function setEpochTime() {
        isRelativeTime.value = false
        const epochStart = new Date(0)
        const now = new Date()
        dateRange.value = `${formatDateForApi(epochStart)} - ${formatDateForApi(now)}`
    }

    // Toggle between relative and absolute
    function toggleTimeMode() {
        if (isRelativeTime.value) {
            // Switching to absolute - set current computed range
            setAbsoluteTime(startDate.value, endDate.value)
        } else {
            // Switching to relative - restore defaults
            setRelativeTime(24, RELATIVE_TIME_HOURS)
        }
    }

    // Auto-refresh management
    function startAutoRefresh(callback: () => void) {
        stopAutoRefresh()

        if (autoRefreshInterval.value <= 0) return

        autoRefreshCallback = callback
        autoRefreshTimer = setInterval(() => {
            if (autoRefreshCallback) {
                autoRefreshCallback()
            }
        }, autoRefreshInterval.value * 1000)
    }

    function stopAutoRefresh() {
        if (autoRefreshTimer) {
            clearInterval(autoRefreshTimer)
            autoRefreshTimer = null
        }
        autoRefreshCallback = null
    }

    function resetAutoRefresh(callback: () => void) {
        if (autoRefreshInterval.value > 0 && autoRefreshCallback) {
            startAutoRefresh(callback)
        }
    }

    function setAutoRefreshInterval(seconds: number) {
        autoRefreshInterval.value = seconds
        if (seconds <= 0) {
            stopAutoRefresh()
        } else if (autoRefreshCallback) {
            startAutoRefresh(autoRefreshCallback)
        }
    }

    // URL parameter handling
    function parseFromUrlParams(params: URLSearchParams): boolean {
        let changed = false

        // Check for relative time (rt parameter)
        const rtParam = params.get('rt')
        const ruParam = params.get('ru')
        const tParam = params.get('t')

        if (rtParam) {
            isRelativeTime.value = true
            relativeTimeValue.value = parseInt(rtParam, 10) || 24
            if (ruParam) {
                const unit = parseInt(ruParam, 10)
                if ([10, 20, 30, 40, 50, 60].includes(unit)) {
                    relativeTimeUnit.value = unit as RelativeTimeUnit
                }
            }
            changed = true
        } else if (tParam) {
            isRelativeTime.value = false
            dateRange.value = tParam
            changed = true
        }

        const zoneParam = params.get('z')
        if (zoneParam) {
            zone.value = zoneParam
            changed = true
        }

        return changed
    }

    function serializeToUrlParams(): Record<string, string> {
        const params: Record<string, string> = {}

        if (isRelativeTime.value) {
            params.rt = relativeTimeValue.value.toString()
            params.ru = relativeTimeUnit.value.toString()
        } else {
            params.t = dateRange.value
        }

        if (zone.value && zone.value !== Intl.DateTimeFormat().resolvedOptions().timeZone) {
            params.z = zone.value
        }

        return params
    }

    // Local storage persistence
    function saveToLocalStorage(category: string) {
        const key = `hunt.${category}.timeRange`
        const data = {
            isRelative: isRelativeTime.value,
            relativeValue: relativeTimeValue.value,
            relativeUnit: relativeTimeUnit.value,
            zone: zone.value,
            autoRefreshInterval: autoRefreshInterval.value
        }
        localStorage.setItem(key, JSON.stringify(data))
    }

    function loadFromLocalStorage(category: string) {
        const key = `hunt.${category}.timeRange`
        const stored = localStorage.getItem(key)

        if (stored) {
            try {
                const data = JSON.parse(stored)
                if (data.isRelative !== undefined) isRelativeTime.value = data.isRelative
                if (data.relativeValue !== undefined) relativeTimeValue.value = data.relativeValue
                if (data.relativeUnit !== undefined) relativeTimeUnit.value = data.relativeUnit
                if (data.zone !== undefined) zone.value = data.zone
                if (data.autoRefreshInterval !== undefined) autoRefreshInterval.value = data.autoRefreshInterval
            } catch (e) {
                console.error('Failed to parse time range settings:', e)
            }
        }
    }

    // Reset to defaults
    function reset() {
        isRelativeTime.value = true
        relativeTimeValue.value = 24
        relativeTimeUnit.value = RELATIVE_TIME_HOURS
        dateRange.value = ''
        zone.value = Intl.DateTimeFormat().resolvedOptions().timeZone
        autoRefreshInterval.value = 0
        stopAutoRefresh()
    }

    return {
        // State
        isRelativeTime,
        relativeTimeValue,
        relativeTimeUnit,
        dateRange,
        zone,
        autoRefreshInterval,

        // Computed
        startDate,
        endDate,
        formattedRange,
        rangeDescription,

        // Constants
        RELATIVE_TIME_UNITS,
        AUTO_REFRESH_OPTIONS,

        // Methods
        setRelativeTime,
        setAbsoluteTime,
        setEpochTime,
        toggleTimeMode,
        startAutoRefresh,
        stopAutoRefresh,
        resetAutoRefresh,
        setAutoRefreshInterval,
        parseFromUrlParams,
        serializeToUrlParams,
        saveToLocalStorage,
        loadFromLocalStorage,
        reset
    }
}
