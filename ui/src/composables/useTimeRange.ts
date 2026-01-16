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

// Default/global scope state (shared between Hunt, Alerts, etc.)
const isRelativeTime = ref(true)
const relativeTimeValue = ref(24)
const relativeTimeUnit = ref<RelativeTimeUnit>(RELATIVE_TIME_HOURS)
const dateRange = ref('')
const zone = ref(Intl.DateTimeFormat().resolvedOptions().timeZone)
const autoRefreshInterval = ref(0)

// Track if the time range has been initialized (prevents re-loading from localStorage on navigation)
let isInitialized = false

let autoRefreshTimer: ReturnType<typeof setTimeout> | null = null
let autoRefreshCallback: (() => void) | null = null

// =============================================================================
// Scoped state for independent time ranges (e.g., Cases)
// =============================================================================

interface ScopedTimeState {
    isRelativeTime: ReturnType<typeof ref<boolean>>
    relativeTimeValue: ReturnType<typeof ref<number>>
    relativeTimeUnit: ReturnType<typeof ref<RelativeTimeUnit>>
    dateRange: ReturnType<typeof ref<string>>
    zone: ReturnType<typeof ref<string>>
    autoRefreshInterval: ReturnType<typeof ref<number>>
    isInitialized: boolean
}

const scopedStates = new Map<string, ScopedTimeState>()

function getOrCreateScopedState(scope: string): ScopedTimeState {
    if (!scopedStates.has(scope)) {
        scopedStates.set(scope, {
            isRelativeTime: ref(true),
            relativeTimeValue: ref(24),
            relativeTimeUnit: ref(RELATIVE_TIME_HOURS as RelativeTimeUnit),
            dateRange: ref(''),
            zone: ref(Intl.DateTimeFormat().resolvedOptions().timeZone),
            autoRefreshInterval: ref(0),
            isInitialized: false
        })
    }
    return scopedStates.get(scope)!
}

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

export interface UseTimeRangeOptions {
    scope?: string  // Optional scope for independent time range state (e.g., 'cases')
}

export function useTimeRange(options: UseTimeRangeOptions = {}) {
    // Determine which state to use based on scope
    const scopedState = options.scope ? getOrCreateScopedState(options.scope) : null

    // Use scoped state or global state
    const _isRelativeTime = scopedState?.isRelativeTime ?? isRelativeTime
    const _relativeTimeValue = scopedState?.relativeTimeValue ?? relativeTimeValue
    const _relativeTimeUnit = scopedState?.relativeTimeUnit ?? relativeTimeUnit
    const _dateRange = scopedState?.dateRange ?? dateRange
    const _zone = scopedState?.zone ?? zone
    const _autoRefreshInterval = scopedState?.autoRefreshInterval ?? autoRefreshInterval

    // Track initialization for scoped state
    const getIsInitialized = () => scopedState ? scopedState.isInitialized : isInitialized
    const setIsInitialized = (value: boolean) => {
        if (scopedState) {
            scopedState.isInitialized = value
        } else {
            isInitialized = value
        }
    }

    // Computed: Get start date based on relative or absolute time
    const startDate = computed<Date>(() => {
        if (_isRelativeTime.value) {
            return subtractTime(new Date(), _relativeTimeValue.value, _relativeTimeUnit.value)
        }

        const parsed = parseDateRange(_dateRange.value)
        return parsed ? parsed.start : subtractTime(new Date(), 24, RELATIVE_TIME_HOURS)
    })

    // Computed: Get end date based on relative or absolute time
    const endDate = computed<Date>(() => {
        if (_isRelativeTime.value) {
            return new Date()
        }

        const parsed = parseDateRange(_dateRange.value)
        return parsed ? parsed.end : new Date()
    })

    // Computed: Format date range for API calls
    const formattedRange = computed<string>(() => {
        return `${formatDateForApi(startDate.value)} - ${formatDateForApi(endDate.value)}`
    })

    // Computed: Human readable time range description
    const rangeDescription = computed<string>(() => {
        if (_isRelativeTime.value) {
            const unitStr = getRelativeTimeUnitString(_relativeTimeUnit.value)
            return `Last ${_relativeTimeValue.value} ${unitStr}`
        }
        return _dateRange.value || 'Custom range'
    })

    // Set relative time
    function setRelativeTime(value: number, unit: RelativeTimeUnit) {
        _isRelativeTime.value = true
        _relativeTimeValue.value = value
        _relativeTimeUnit.value = unit
        _dateRange.value = ''
        setIsInitialized(true)
    }

    // Set absolute time range
    function setAbsoluteTime(start: Date, end: Date) {
        _isRelativeTime.value = false
        _dateRange.value = `${formatDateForApi(start)} - ${formatDateForApi(end)}`
        setIsInitialized(true)
    }

    // Set epoch time (for detections - from epoch 0 to now)
    function setEpochTime() {
        _isRelativeTime.value = false
        const epochStart = new Date(0)
        const now = new Date()
        _dateRange.value = `${formatDateForApi(epochStart)} - ${formatDateForApi(now)}`
        setIsInitialized(true)
    }

    // Toggle between relative and absolute
    function toggleTimeMode() {
        if (_isRelativeTime.value) {
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

        if (_autoRefreshInterval.value <= 0) return

        autoRefreshCallback = callback
        autoRefreshTimer = setInterval(() => {
            if (autoRefreshCallback) {
                autoRefreshCallback()
            }
        }, _autoRefreshInterval.value * 1000)
    }

    function stopAutoRefresh() {
        if (autoRefreshTimer) {
            clearInterval(autoRefreshTimer)
            autoRefreshTimer = null
        }
        autoRefreshCallback = null
    }

    function resetAutoRefresh(callback: () => void) {
        if (_autoRefreshInterval.value > 0 && autoRefreshCallback) {
            startAutoRefresh(callback)
        }
    }

    function setAutoRefreshInterval(seconds: number) {
        _autoRefreshInterval.value = seconds
        if (seconds <= 0) {
            stopAutoRefresh()
        } else if (autoRefreshCallback) {
            startAutoRefresh(autoRefreshCallback)
        }
    }

    // URL parameter handling (compatible with old UI: q, rt, rtu, t, z, el, gl, ar)
    function parseFromUrlParams(params: URLSearchParams): boolean {
        let changed = false

        // Check for relative time (rt parameter)
        const rtParam = params.get('rt')
        const rtuParam = params.get('rtu')  // Old UI uses 'rtu' for relative time unit
        const tParam = params.get('t')

        if (rtParam) {
            _isRelativeTime.value = true
            _relativeTimeValue.value = parseInt(rtParam, 10) || 24
            if (rtuParam) {
                const unit = parseInt(rtuParam, 10)
                if ([10, 20, 30, 40, 50, 60].includes(unit)) {
                    _relativeTimeUnit.value = unit as RelativeTimeUnit
                }
            }
            changed = true
        } else if (tParam) {
            _isRelativeTime.value = false
            _dateRange.value = tParam
            changed = true
        }

        const zoneParam = params.get('z')
        if (zoneParam) {
            _zone.value = zoneParam
            changed = true
        }

        // Auto-refresh interval (ar parameter from old UI)
        const arParam = params.get('ar')
        if (arParam) {
            _autoRefreshInterval.value = parseInt(arParam, 10) || 0
            changed = true
        }

        if (changed) {
            setIsInitialized(true)
        }

        return changed
    }

    function serializeToUrlParams(): Record<string, string> {
        const params: Record<string, string> = {}

        if (_isRelativeTime.value) {
            params.rt = _relativeTimeValue.value.toString()
            params.rtu = _relativeTimeUnit.value.toString()  // Old UI uses 'rtu'
        } else if (_dateRange.value) {
            params.t = _dateRange.value
        }

        if (_zone.value && _zone.value !== Intl.DateTimeFormat().resolvedOptions().timeZone) {
            params.z = _zone.value
        }

        if (_autoRefreshInterval.value > 0) {
            params.ar = _autoRefreshInterval.value.toString()
        }

        return params
    }

    // Local storage persistence
    function saveToLocalStorage(category: string) {
        const key = `hunt.${category}.timeRange`
        const data = {
            isRelative: _isRelativeTime.value,
            relativeValue: _relativeTimeValue.value,
            relativeUnit: _relativeTimeUnit.value,
            zone: _zone.value,
            autoRefreshInterval: _autoRefreshInterval.value
        }
        localStorage.setItem(key, JSON.stringify(data))
    }

    function loadFromLocalStorage(category: string) {
        // Skip if already initialized (navigating within app, not fresh page load)
        if (getIsInitialized()) {
            return
        }

        const key = `hunt.${category}.timeRange`
        const stored = localStorage.getItem(key)

        if (stored) {
            try {
                const data = JSON.parse(stored)
                if (data.isRelative !== undefined) _isRelativeTime.value = data.isRelative
                if (data.relativeValue !== undefined) _relativeTimeValue.value = data.relativeValue
                if (data.relativeUnit !== undefined) _relativeTimeUnit.value = data.relativeUnit
                if (data.zone !== undefined) _zone.value = data.zone
                if (data.autoRefreshInterval !== undefined) _autoRefreshInterval.value = data.autoRefreshInterval
            } catch (e) {
                console.error('Failed to parse time range settings:', e)
            }
        }

        setIsInitialized(true)
    }

    // Reset to defaults
    function reset() {
        _isRelativeTime.value = true
        _relativeTimeValue.value = 24
        _relativeTimeUnit.value = RELATIVE_TIME_HOURS
        _dateRange.value = ''
        _zone.value = Intl.DateTimeFormat().resolvedOptions().timeZone
        _autoRefreshInterval.value = 0
        stopAutoRefresh()
    }

    return {
        // State (uses scoped state if scope was provided)
        isRelativeTime: _isRelativeTime,
        relativeTimeValue: _relativeTimeValue,
        relativeTimeUnit: _relativeTimeUnit,
        dateRange: _dateRange,
        zone: _zone,
        autoRefreshInterval: _autoRefreshInterval,

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
