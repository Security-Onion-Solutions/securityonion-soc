// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

import { ref } from 'vue'
import { useApi } from './useApi'
import {
    type EventRecord,
    type AckResponse,
    type ActionConfig
} from '../types/hunt'

// =============================================================================
// Composable
// =============================================================================

export function useHuntActions() {
    const { post, get, loading, error } = useApi()

    // MRU cases for escalation
    const mruCases = ref<{ id: string; title: string }[]>([])
    const maxMruCases = 5

    // =========================================================================
    // Acknowledge
    // =========================================================================

    /**
     * Acknowledge or unacknowledge an event
     */
    async function acknowledgeEvent(
        event: EventRecord,
        acknowledge: boolean,
        options: {
            dateRange?: string
            timezone?: string
        } = {}
    ): Promise<boolean> {
        try {
            const payload = {
                searchFilter: `soc_id:"${event.soc_id}"`,
                eventFilter: { 'soc_id': event.soc_id },
                dateRange: options.dateRange || '',
                timezone: options.timezone || 'Local',
                acknowledge,
                escalate: false
            }

            await post<AckResponse>('/api/events/ack', payload)
            return true
        } catch (e) {
            console.error('Failed to acknowledge event:', e)
            return false
        }
    }

    /**
     * Bulk acknowledge events
     */
    async function bulkAcknowledge(
        events: EventRecord[],
        acknowledge: boolean,
        options: {
            dateRange?: string
            timezone?: string
        } = {}
    ): Promise<boolean> {
        try {
            const ids = events.map(e => e.soc_id)
            const searchFilter = ids.map(id => `soc_id:"${id}"`).join(' OR ')

            const payload = {
                searchFilter: `(${searchFilter})`,
                eventFilter: {},
                dateRange: options.dateRange || '',
                timezone: options.timezone || 'Local',
                acknowledge,
                escalate: false
            }

            await post<AckResponse>('/api/events/ack', payload)
            return true
        } catch (e) {
            console.error('Failed to bulk acknowledge:', e)
            return false
        }
    }

    // =========================================================================
    // Escalate
    // =========================================================================

    /**
     * Escalate an event to a new case
     */
    async function escalateToNewCase(
        event: EventRecord,
        options: {
            title?: string
            description?: string
            severity?: string
            template?: string
            includeRelated?: boolean
        } = {}
    ): Promise<string | null> {
        try {
            // Build case from event
            const caseData = buildCaseFromEvent(event, options)

            // Create case
            const response = await post<{ id: string }>('/api/case/', caseData)

            if (response?.id) {
                // Acknowledge the event as escalated
                await post('/api/events/ack', {
                    searchFilter: `soc_id:"${event.soc_id}"`,
                    eventFilter: { 'soc_id': event.soc_id },
                    acknowledge: true,
                    escalate: true
                })

                // Add to MRU
                addMruCase(response.id, caseData.title)

                return response.id
            }

            return null
        } catch (e) {
            console.error('Failed to create case:', e)
            return null
        }
    }

    /**
     * Add event to existing case
     */
    async function addToCase(
        event: EventRecord,
        caseId: string,
        options: {
            includeRelated?: boolean
        } = {}
    ): Promise<boolean> {
        try {
            // Add event to case
            await post('/api/case/events', {
                caseId,
                eventIds: [event.soc_id]
            })

            // Acknowledge the event as escalated
            await post('/api/events/ack', {
                searchFilter: `soc_id:"${event.soc_id}"`,
                eventFilter: { 'soc_id': event.soc_id },
                acknowledge: true,
                escalate: true
            })

            return true
        } catch (e) {
            console.error('Failed to add to case:', e)
            return false
        }
    }

    /**
     * Build case data from event
     */
    function buildCaseFromEvent(
        event: EventRecord,
        options: {
            title?: string
            description?: string
            severity?: string
            template?: string
        } = {}
    ): Record<string, any> {
        // Extract relevant fields for case
        const ruleName = event['rule.name'] || event['event.module'] || 'Unknown Alert'
        const ruleDesc = event['rule.description'] || ''
        const sourceIp = event['source.ip'] || ''
        const destIp = event['destination.ip'] || ''
        const severity = options.severity || mapScoreToSeverity(event.soc_score)

        return {
            title: options.title || `Alert: ${ruleName}`,
            description: options.description || buildCaseDescription(event, ruleDesc),
            severity,
            template: options.template || '',
            status: 'open'
        }
    }

    function buildCaseDescription(event: EventRecord, ruleDesc: string): string {
        const lines: string[] = []

        if (ruleDesc) {
            lines.push(ruleDesc)
            lines.push('')
        }

        lines.push('**Alert Details:**')

        if (event['source.ip']) {
            lines.push(`- Source IP: ${event['source.ip']}`)
        }
        if (event['destination.ip']) {
            lines.push(`- Destination IP: ${event['destination.ip']}`)
        }
        if (event['rule.name']) {
            lines.push(`- Rule: ${event['rule.name']}`)
        }
        if (event.soc_timestamp) {
            lines.push(`- Time: ${event.soc_timestamp}`)
        }

        return lines.join('\n')
    }

    function mapScoreToSeverity(score?: number): string {
        if (score === undefined || score === null) return 'medium'
        if (score >= 75) return 'critical'
        if (score >= 50) return 'high'
        if (score >= 25) return 'medium'
        return 'low'
    }

    // =========================================================================
    // MRU Cases
    // =========================================================================

    function addMruCase(id: string, title: string) {
        // Remove if exists
        mruCases.value = mruCases.value.filter(c => c.id !== id)

        // Add to front
        mruCases.value.unshift({ id, title })

        // Trim to limit
        if (mruCases.value.length > maxMruCases) {
            mruCases.value = mruCases.value.slice(0, maxMruCases)
        }

        // Save to localStorage
        localStorage.setItem('hunt.mruCases', JSON.stringify(mruCases.value))
    }

    function loadMruCases() {
        try {
            const stored = localStorage.getItem('hunt.mruCases')
            if (stored) {
                mruCases.value = JSON.parse(stored)
            }
        } catch (e) {
            console.error('Failed to load MRU cases:', e)
        }
    }

    // =========================================================================
    // Custom Actions
    // =========================================================================

    /**
     * Execute a custom action
     */
    async function executeAction(
        action: ActionConfig,
        event: EventRecord,
        field?: string,
        value?: any
    ): Promise<boolean> {
        try {
            // Format the action link/body with event data
            let link = action.link || ''
            let body = action.body || ''

            // Replace placeholders
            link = formatActionContent(link, event, field, value)
            body = formatActionContent(body, event, field, value)

            if (action.method === 'POST' && body) {
                await post(link, JSON.parse(body))
            } else if (link) {
                // Open link
                if (action.target === '_blank') {
                    window.open(link, '_blank')
                } else {
                    window.location.href = link
                }
            }

            return true
        } catch (e) {
            console.error('Failed to execute action:', e)
            return false
        }
    }

    function formatActionContent(
        template: string,
        event: EventRecord,
        field?: string,
        value?: any
    ): string {
        let result = template

        // Replace {field} placeholder
        if (field) {
            result = result.replace(/\{field\}/g, field)
        }

        // Replace {value} placeholder
        if (value !== undefined) {
            result = result.replace(/\{value\}/g, String(value))
        }

        // Replace {soc_id} placeholder
        result = result.replace(/\{soc_id\}/g, event.soc_id)

        // Replace any event field placeholders like {source.ip}
        result = result.replace(/\{([^}]+)\}/g, (match, fieldName) => {
            const fieldValue = event[fieldName]
            return fieldValue !== undefined ? String(fieldValue) : match
        })

        return result
    }

    // =========================================================================
    // AI Investigation
    // =========================================================================

    /**
     * Start an AI investigation for an event
     */
    async function startInvestigation(
        event: EventRecord,
        navigateCallback: (sessionId: string) => void
    ): Promise<string | null> {
        try {
            // Generate investigation prompt
            const prompt = generateInvestigationPrompt(event)

            // Create new session with the prompt
            const response = await post<{ sessionId: string }>('/api/assistant/sessions', {
                initialMessage: prompt,
                context: {
                    eventId: event.soc_id,
                    eventType: 'investigation'
                }
            })

            if (response?.sessionId) {
                // Navigate to assistant with this session
                navigateCallback(response.sessionId)
                return response.sessionId
            }

            return null
        } catch (e) {
            console.error('Failed to start investigation:', e)
            return null
        }
    }

    function generateInvestigationPrompt(event: EventRecord): string {
        const alertId = event.soc_id || 'unknown'

        return `Investigate alert ${alertId}`
    }

    // Initialize
    loadMruCases()

    return {
        // State
        loading,
        error,
        mruCases,

        // Acknowledge
        acknowledgeEvent,
        bulkAcknowledge,

        // Escalate
        escalateToNewCase,
        addToCase,
        buildCaseFromEvent,

        // MRU
        addMruCase,
        loadMruCases,

        // Custom actions
        executeAction,
        formatActionContent,

        // AI Investigation
        startInvestigation,
        generateInvestigationPrompt
    }
}
