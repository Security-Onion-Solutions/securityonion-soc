// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

import { ref, computed } from 'vue'
import { useApi } from './useApi'
import type { HuntCategory, HuntParams, EventHeader } from '../types/hunt'

// =============================================================================
// Types
// =============================================================================

interface InfoResponse {
    parameters: {
        hunt: HuntParams
        alerts: HuntParams
        cases: HuntParams
        detections: HuntParams
        [key: string]: any
    }
    [key: string]: any
}

// =============================================================================
// Module-level state (shared across all component instances)
// =============================================================================

const params = ref<Record<string, HuntParams>>({})
const eventFields = ref<Record<string, Record<string, string[]>>>({})
const loaded = ref(false)
const loading = ref(false)

// =============================================================================
// Composable
// =============================================================================

export function useHuntParams() {
    const { get } = useApi()

    // =========================================================================
    // Fetch Parameters
    // =========================================================================

    /**
     * Fetch hunt parameters from /api/info/
     * Caches the result for subsequent calls
     */
    async function fetchParams(): Promise<void> {
        if (loaded.value || loading.value) return

        loading.value = true

        try {
            const response = await get<InfoResponse>('/api/info/')

            if (response?.parameters) {
                // Store params for each category
                if (response.parameters.hunt) {
                    params.value.hunt = response.parameters.hunt
                    eventFields.value.hunt = response.parameters.hunt.eventFields || {}
                }
                if (response.parameters.alerts) {
                    params.value.alerts = response.parameters.alerts
                    eventFields.value.alerts = response.parameters.alerts.eventFields || {}
                }
                if (response.parameters.cases) {
                    params.value.cases = response.parameters.cases
                    eventFields.value.cases = response.parameters.cases.eventFields || {}
                }
                if (response.parameters.detections) {
                    params.value.detections = response.parameters.detections
                    eventFields.value.detections = response.parameters.detections.eventFields || {}
                }

                loaded.value = true
            }
        } catch (e) {
            console.error('Failed to fetch hunt parameters:', e)
        } finally {
            loading.value = false
        }
    }

    // =========================================================================
    // Field Resolution
    // =========================================================================

    /**
     * Filter visible fields based on event module and dataset
     * Implements the same priority-based resolution as classic UI:
     * 1. :module:dataset (most specific)
     * 2. ::dataset (dataset only)
     * 3. :module: (module only)
     * 4. default (fallback)
     */
    function filterVisibleFields(
        category: HuntCategory,
        eventModule: string | undefined,
        eventDataset: string | undefined,
        fallbackFields: string[]
    ): string[] {
        const fields = eventFields.value[category]
        if (!fields) return fallbackFields

        let filteredFields: string[] | undefined

        // Normalize dataset - strip module prefix if present (e.g., "suricata.alert" -> "alert")
        let dataset = eventDataset
        if (dataset && dataset.indexOf('.') !== -1) {
            dataset = dataset.substring(dataset.indexOf('.') + 1)
        }

        // Check for related fields prefix (so_XYZ.fields.)
        let relatedFieldsPrefix = ''
        for (const field of fallbackFields) {
            const match = field.match(/so_[^.]*\.fields\./)
            if (match) {
                relatedFieldsPrefix = match[0]
                break
            }
        }

        // Priority 1: :module:dataset (most specific)
        if (eventModule && dataset) {
            filteredFields = fields[`:${eventModule}:${dataset}`]
        }

        // Priority 2: ::dataset (dataset only)
        if (!filteredFields && dataset) {
            filteredFields = fields[`::${dataset}`]
        }

        // Priority 3: :module: (module only)
        if (!filteredFields && eventModule) {
            filteredFields = fields[`:${eventModule}:`]
        }

        // Priority 4: default (fallback)
        if (!filteredFields) {
            filteredFields = fields['default']
        }

        // If we found matching fields, apply related fields prefix if needed
        if (filteredFields && filteredFields.length > 0) {
            if (relatedFieldsPrefix) {
                return filteredFields.map(f => relatedFieldsPrefix + f)
            }
            return filteredFields
        }

        return fallbackFields
    }

    /**
     * Construct table headers from field list
     */
    function constructHeaders(fields: string[]): EventHeader[] {
        const headers: EventHeader[] = []

        // Custom sort functions for specific fields
        const customSortFields = new Set(['event.severity_label', 'soc_score'])

        for (const field of fields) {
            const header: EventHeader = {
                title: formatFieldTitle(field),
                value: field,
                sortable: true
            }

            headers.push(header)
        }

        return headers
    }

    /**
     * Format a field name into a human-readable title
     * e.g., "source.ip" -> "Source IP", "event.module" -> "Event Module"
     */
    function formatFieldTitle(field: string): string {
        // Remove any prefix like "so_hunt.fields."
        let title = field
        const prefixMatch = field.match(/so_[^.]*\.fields\.(.*)/)
        if (prefixMatch) {
            title = prefixMatch[1]
        }

        // Split by dots and format each part
        return title
            .split('.')
            .map(part => {
                // Handle common abbreviations
                if (part.toLowerCase() === 'ip') return 'IP'
                if (part.toLowerCase() === 'id') return 'ID'
                if (part.toLowerCase() === 'url') return 'URL'
                if (part.toLowerCase() === 'dns') return 'DNS'
                if (part.toLowerCase() === 'tcp') return 'TCP'
                if (part.toLowerCase() === 'udp') return 'UDP'
                if (part.toLowerCase() === 'http') return 'HTTP'

                // Capitalize first letter, handle underscores
                return part
                    .split('_')
                    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
                    .join(' ')
            })
            .join(' ')
    }

    /**
     * Extract module and dataset from events
     * Returns the module/dataset from the first event that has them
     */
    function extractModuleDataset(events: any[]): { module?: string; dataset?: string } {
        for (const event of events) {
            const module = event['event.module']
            const dataset = event['event.dataset']

            if (module) {
                return {
                    module: String(module).toLowerCase(),
                    dataset: dataset ? String(dataset).toLowerCase() : undefined
                }
            }
        }

        return {}
    }

    // =========================================================================
    // Getters
    // =========================================================================

    function getParams(category: HuntCategory): HuntParams | undefined {
        return params.value[category]
    }

    function getEventFields(category: HuntCategory): Record<string, string[]> {
        return eventFields.value[category] || {}
    }

    // =========================================================================
    // Return
    // =========================================================================

    return {
        // State
        params,
        eventFields,
        loaded,
        loading,

        // Methods
        fetchParams,
        filterVisibleFields,
        constructHeaders,
        formatFieldTitle,
        extractModuleDataset,
        getParams,
        getEventFields
    }
}
