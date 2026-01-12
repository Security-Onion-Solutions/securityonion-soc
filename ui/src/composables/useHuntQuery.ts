// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

import { ref, computed, watch } from 'vue'
import { useApi } from './useApi'
import {
    FILTER_INCLUDE,
    FILTER_EXCLUDE,
    FILTER_EXACT,
    FILTER_DRILLDOWN,
    type FilterMode,
    type ParsedQuery,
    type GroupBySegment,
    type QueryPreset,
    type FilterToggle,
    type QueryTransformResponse,
    type HuntCategory
} from '../types/hunt'

// =============================================================================
// Module-level state (can be shared or per-instance based on usage)
// =============================================================================

const query = ref('')
const queryBaseFilter = ref('')
const queryPresets = ref<QueryPreset[]>([])
const filterToggles = ref<FilterToggle[]>([])
const mruQueries = ref<string[]>([])

// =============================================================================
// Composable
// =============================================================================

export function useHuntQuery() {
    const { get } = useApi()

    // =========================================================================
    // Parsed Query State (computed from query string)
    // =========================================================================

    const parsedQuery = computed<ParsedQuery>(() => {
        return parseQueryString(query.value)
    })

    const queryFilters = computed(() => parsedQuery.value.filters)
    const queryGroupBys = computed(() => parsedQuery.value.groupBys)
    const querySortBys = computed(() => parsedQuery.value.sortBys)
    const querySearch = computed(() => parsedQuery.value.search)
    const isComplexQuery = computed(() => parsedQuery.value.search ? checkIsComplexQuery(parsedQuery.value.search) : false)

    // =========================================================================
    // Query Parsing Functions
    // =========================================================================

    /**
     * Check if a query contains complex parentheses that would break simple AND splitting
     */
    function checkIsComplexQuery(queryStr: string): boolean {
        let insideQuote = false
        let escaping = false
        for (let i = 0; i < queryStr.length; i++) {
            const ch = queryStr[i]
            if (ch === '"' && !escaping) {
                insideQuote = !insideQuote
            } else if ((ch === '(' || ch === ')') && !insideQuote && !escaping) {
                return true
            }
            if (ch === '\\') {
                escaping = !escaping
            } else {
                escaping = false
            }
        }
        return false
    }

    /**
     * Parse a query string into its component parts
     */
    function parseQueryString(queryStr: string): ParsedQuery {
        const result: ParsedQuery = {
            search: '',
            filters: [],
            groupBys: [],
            sortBys: [],
            tableFields: [],
            tableOptions: [],
            remainder: ''
        }

        if (!queryStr) return result

        queryStr = queryStr.trim()

        // Find the first pipe delimiter that's not inside quotes
        let insideQuote = false
        let escaping = false
        let segmentDelimIdx = -1

        for (let i = 0; i < queryStr.length; i++) {
            const ch = queryStr[i]
            if (ch === '|' && !insideQuote && !escaping) {
                segmentDelimIdx = i
                break
            } else if (ch === '"' && !escaping) {
                insideQuote = !insideQuote
            } else if (ch === '\\' && !escaping) {
                escaping = true
            } else {
                escaping = false
            }
        }

        let segments: string[] = []

        if (segmentDelimIdx > -1 && queryStr.length > segmentDelimIdx + 1) {
            // Split on pipe for segments after the first one
            segments = queryStr.substring(segmentDelimIdx + 1).split('|')
            segments.unshift(queryStr.substring(0, segmentDelimIdx))
        } else {
            segments = [queryStr]
        }

        if (segments.length > 0) {
            result.search = segments[0].trim()

            if (segments.length > 1) {
                result.remainder = queryStr.substring(segmentDelimIdx)
            }

            // Parse filters from search if not complex
            if (!checkIsComplexQuery(result.search)) {
                result.search.split(' AND ').forEach((item) => {
                    item = item.trim()
                    if (item.length > 0 && item !== '*') {
                        result.filters.push(item)
                    }
                })
            }
        }

        // Parse remaining segments (groupby, sortby, table)
        if (segments.length > 1) {
            for (let segmentIdx = 1; segmentIdx < segments.length; segmentIdx++) {
                let segment = segments[segmentIdx].trim().replace(/,/g, ' ')

                if (segment.startsWith('groupby')) {
                    const fields: string[] = []
                    const options: string[] = []

                    segment.split(' ').forEach((item, index) => {
                        if (item.startsWith('-')) {
                            options.push(item.substring(1))
                        } else if (index > 0 && item.trim().length > 0) {
                            // Skip quoted items with spaces for now
                            if (item.split('"').length % 2 === 1) {
                                fields.push(item)
                            }
                        }
                    })

                    result.groupBys.push({ fields, options })
                }

                if (segment.startsWith('table')) {
                    segment.split(' ').forEach((item, index) => {
                        if (item.startsWith('-')) {
                            result.tableOptions.push(item.substring(1))
                        } else if (index > 0 && item.trim().length > 0) {
                            if (item.split('"').length % 2 === 1) {
                                result.tableFields.push(item)
                            }
                        }
                    })
                }

                if (segment.startsWith('sortby')) {
                    segment.split(' ').forEach((item, index) => {
                        if (index > 0 && item.trim().length > 0) {
                            if (item.split('"').length % 2 === 1) {
                                result.sortBys.push(item)
                            }
                        }
                    })
                }
            }
        }

        return result
    }

    // =========================================================================
    // Query Manipulation Functions
    // =========================================================================

    /**
     * Set the full query string
     */
    function setQuery(newQuery: string) {
        query.value = newQuery.trim()
    }

    /**
     * Add a filter to the query using the API
     */
    async function addFilter(
        field: string,
        value: any,
        mode: FilterMode = FILTER_INCLUDE,
        scalar: boolean = false
    ): Promise<string> {
        const params: Record<string, string> = {
            query: query.value || '*',
            field,
            value: String(value),
            mode,
            scalar: scalar ? 'true' : 'false',
            condense: 'true'
        }

        try {
            const response = await get<QueryTransformResponse>('/api/query/filtered', params)
            if (response?.query) {
                query.value = response.query
                return response.query
            }
        } catch (e) {
            console.error('Failed to add filter:', e)
        }

        return query.value
    }

    /**
     * Remove a filter from the query (client-side)
     */
    function removeFilter(filter: string) {
        let newQuery = query.value.replace(' AND ' + filter, '')
        if (newQuery === query.value) {
            newQuery = query.value.replace(filter + ' AND ', '')
            if (newQuery === query.value) {
                newQuery = query.value.replace(filter, '')
            }
        }

        newQuery = newQuery.trim()
        if (newQuery.startsWith('|')) {
            newQuery = '* ' + newQuery
        }
        if (newQuery.length === 0) {
            newQuery = '*'
        }

        query.value = newQuery
    }

    /**
     * Add a groupby to the query using the API
     */
    async function addGroupBy(field: string, groupIndex?: number): Promise<string> {
        const params: Record<string, string> = {
            query: query.value || '*',
            field
        }

        if (groupIndex !== undefined) {
            params.group = groupIndex.toString()
        }

        try {
            const response = await get<QueryTransformResponse>('/api/query/grouped', params)
            if (response?.query) {
                query.value = response.query
                return response.query
            }
        } catch (e) {
            console.error('Failed to add groupby:', e)
        }

        return query.value
    }

    /**
     * Remove a groupby from the query (client-side)
     */
    function removeGroupBy(groupIdx: number, fieldIdx?: number) {
        const groups = parsedQuery.value.groupBys
        if (groupIdx < 0 || groupIdx >= groups.length) return

        const group = groups[groupIdx]
        const field = fieldIdx !== undefined && fieldIdx >= 0 ? group.fields[fieldIdx] : null

        const segments = query.value.split('|')
        let newQuery = segments[0]
        let currentGroupIdx = 0

        for (let i = 1; i < segments.length; i++) {
            if (segments[i].trim().startsWith('groupby')) {
                if (currentGroupIdx++ === groupIdx) {
                    if (field) {
                        segments[i] = segments[i].replace(' ' + field, '')
                    }
                    // Remove entire groupby if single field or removing whole group
                    if (group.fields.length === 1 || !field) {
                        segments[i] = ''
                    }
                }
            }
            if (segments[i].length > 0) {
                newQuery = newQuery.trim() + ' | ' + segments[i].trim()
            }
        }

        query.value = newQuery.trim()
    }

    /**
     * Add a sortby to the query using the API
     */
    async function addSortBy(field: string): Promise<string> {
        const params: Record<string, string> = {
            query: query.value || '*',
            field
        }

        try {
            const response = await get<QueryTransformResponse>('/api/query/sorted', params)
            if (response?.query) {
                query.value = response.query
                return response.query
            }
        } catch (e) {
            console.error('Failed to add sortby:', e)
        }

        return query.value
    }

    /**
     * Remove a sortby from the query (client-side)
     */
    function removeSortBy(sortBy: string) {
        const segments = query.value.split('|')
        let newQuery = segments[0]

        for (let i = 1; i < segments.length; i++) {
            if (segments[i].trim().startsWith('sortby')) {
                segments[i] = segments[i].replace(' ' + sortBy, '')
                if (segments[i].trim() === 'sortby') {
                    segments[i] = ''
                }
            }
            if (segments[i].length > 0) {
                newQuery = newQuery.trim() + ' | ' + segments[i].trim()
            }
        }

        query.value = newQuery.trim()
    }

    // =========================================================================
    // Filter Toggle Functions
    // =========================================================================

    function setFilterToggles(toggles: FilterToggle[]) {
        filterToggles.value = toggles
    }

    function isFilterToggleEnabled(name: string): boolean {
        const toggle = filterToggles.value.find(t => t.name === name)
        return toggle?.enabled ?? false
    }

    function setFilterToggleEnabled(name: string, enabled: boolean) {
        const toggle = filterToggles.value.find(t => t.name === name)
        if (toggle) {
            toggle.enabled = enabled

            // Handle exclusive toggles
            if (enabled && toggle.exclusive) {
                filterToggles.value.forEach(t => {
                    if (t.name !== name && t.exclusive) {
                        t.enabled = false
                    }
                })
            }

            // Handle enables/disables other toggles
            if (toggle.enablesToggles) {
                toggle.enablesToggles.forEach(n => {
                    const target = filterToggles.value.find(t => t.name === n)
                    if (target) target.enabled = enabled
                })
            }
            if (toggle.disablesToggles) {
                toggle.disablesToggles.forEach(n => {
                    const target = filterToggles.value.find(t => t.name === n)
                    if (target) target.enabled = !enabled
                })
            }
        }
    }

    /**
     * Build effective query by combining base filter and active toggle filters
     */
    function buildEffectiveQuery(): string {
        let effectiveQuery = query.value || '*'

        // Apply base filter
        if (queryBaseFilter.value) {
            if (effectiveQuery === '*') {
                effectiveQuery = queryBaseFilter.value
            } else {
                effectiveQuery = `(${effectiveQuery}) AND (${queryBaseFilter.value})`
            }
        }

        // Apply active toggle filters
        filterToggles.value.forEach(toggle => {
            if (toggle.enabled && toggle.filter) {
                effectiveQuery = `(${effectiveQuery}) AND (${toggle.filter})`
            }
        })

        return effectiveQuery
    }

    // =========================================================================
    // MRU Queries
    // =========================================================================

    function addMruQuery(queryStr: string, limit: number = 10) {
        if (!queryStr || queryStr === '*') return

        // Remove if already exists
        const idx = mruQueries.value.indexOf(queryStr)
        if (idx >= 0) {
            mruQueries.value.splice(idx, 1)
        }

        // Add to front
        mruQueries.value.unshift(queryStr)

        // Trim to limit
        if (mruQueries.value.length > limit) {
            mruQueries.value = mruQueries.value.slice(0, limit)
        }
    }

    function clearMruQueries() {
        mruQueries.value = []
    }

    // =========================================================================
    // Preset Queries
    // =========================================================================

    function setQueryPresets(presets: QueryPreset[]) {
        queryPresets.value = presets
    }

    function getPresetByName(name: string): QueryPreset | undefined {
        return queryPresets.value.find(p => p.name === name)
    }

    function getPresetByQuery(queryStr: string): QueryPreset | undefined {
        return queryPresets.value.find(p => p.query === queryStr)
    }

    // =========================================================================
    // URL Parameter Handling
    // =========================================================================

    function parseFromUrlParams(params: URLSearchParams): boolean {
        const qParam = params.get('q')
        if (qParam) {
            query.value = qParam
            return true
        }
        return false
    }

    function serializeToUrlParams(): Record<string, string> {
        const params: Record<string, string> = {}
        if (query.value && query.value !== '*') {
            params.q = query.value
        }
        return params
    }

    // =========================================================================
    // Local Storage Persistence
    // =========================================================================

    function saveToLocalStorage(category: string) {
        const key = `hunt.${category}.query`
        const data = {
            mruQueries: mruQueries.value,
            filterToggles: filterToggles.value.map(t => ({ name: t.name, enabled: t.enabled }))
        }
        localStorage.setItem(key, JSON.stringify(data))
    }

    function loadFromLocalStorage(category: string) {
        const key = `hunt.${category}.query`
        const stored = localStorage.getItem(key)

        if (stored) {
            try {
                const data = JSON.parse(stored)
                if (data.mruQueries) {
                    mruQueries.value = data.mruQueries
                }
                if (data.filterToggles) {
                    data.filterToggles.forEach((saved: { name: string; enabled: boolean }) => {
                        const toggle = filterToggles.value.find(t => t.name === saved.name)
                        if (toggle) {
                            toggle.enabled = saved.enabled
                        }
                    })
                }
            } catch (e) {
                console.error('Failed to parse query settings:', e)
            }
        }
    }

    // =========================================================================
    // Reset
    // =========================================================================

    function reset() {
        query.value = ''
        queryBaseFilter.value = ''
        filterToggles.value.forEach(t => t.enabled = false)
    }

    return {
        // State
        query,
        queryBaseFilter,
        queryPresets,
        filterToggles,
        mruQueries,

        // Computed
        parsedQuery,
        queryFilters,
        queryGroupBys,
        querySortBys,
        querySearch,
        isComplexQuery,

        // Query manipulation
        setQuery,
        addFilter,
        removeFilter,
        addGroupBy,
        removeGroupBy,
        addSortBy,
        removeSortBy,

        // Filter toggles
        setFilterToggles,
        isFilterToggleEnabled,
        setFilterToggleEnabled,
        buildEffectiveQuery,

        // MRU
        addMruQuery,
        clearMruQueries,

        // Presets
        setQueryPresets,
        getPresetByName,
        getPresetByQuery,

        // URL params
        parseFromUrlParams,
        serializeToUrlParams,

        // Persistence
        saveToLocalStorage,
        loadFromLocalStorage,

        // Reset
        reset
    }
}
