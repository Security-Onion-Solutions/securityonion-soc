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

    /**
     * Bulk acknowledge events by query filter
     */
    async function bulkAcknowledgeByQuery(
        searchFilter: string,
        acknowledge: boolean,
        options: {
            dateRange?: string
            timezone?: string
        } = {}
    ): Promise<boolean> {
        try {
            const payload = {
                searchFilter,
                eventFilter: {},
                dateRange: options.dateRange || '',
                timezone: options.timezone || 'Local',
                acknowledge,
                escalate: false
            }

            await post<AckResponse>('/api/events/ack', payload)
            return true
        } catch (e) {
            console.error('Failed to bulk acknowledge by query:', e)
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
            relatedEventIds?: string[]
        } = {}
    ): Promise<string | null> {
        try {
            // Build case from event
            const caseData = buildCaseFromEvent(event, options)

            // Create case
            const response = await post<{ id: string }>('/api/case/', caseData)

            if (response?.id) {
                const caseId = response.id

                // Attach the primary event to the case
                try {
                    await post('/api/case/events', {
                        caseId,
                        fields: { soc_id: event.soc_id },
                        dateRange: '',
                        dateRangeFormat: '2006/01/02 3:04:05 PM',
                        timezone: 'Local',
                        acknowledged: false,
                        escalated: false
                    })
                } catch (attachError) {
                    console.warn('Failed to attach event to case:', attachError)
                }

                // Attach related events from guided analysis (if any)
                if (options.relatedEventIds && options.relatedEventIds.length > 0) {
                    for (const relatedId of options.relatedEventIds) {
                        try {
                            await post('/api/case/events', {
                                caseId,
                                fields: { soc_id: relatedId },
                                dateRange: '',
                                dateRangeFormat: '2006/01/02 3:04:05 PM',
                                timezone: 'Local',
                                acknowledged: false,
                                escalated: false
                            })
                        } catch (attachError) {
                            // Don't fail the whole escalation if one related event fails
                            console.warn(`Failed to attach related event ${relatedId}:`, attachError)
                        }
                    }
                }

                // Acknowledge the event as escalated
                try {
                    await post('/api/events/ack', {
                        searchFilter: `_id:"${event.soc_id}"`,
                        eventFilter: { '_id': event.soc_id },
                        dateRange: '',
                        dateRangeFormat: '2006/01/02 3:04:05 PM',
                        timezone: 'Local',
                        acknowledge: true,
                        escalate: true
                    })
                } catch (ackError) {
                    // Event ack can fail but case was still created
                    console.warn('Failed to acknowledge escalated event:', ackError)
                }

                // Add to MRU
                addMruCase(caseId, caseData.title)

                return caseId
            }

            return null
        } catch (e) {
            console.error('Failed to create case:', e)
            throw e // Re-throw so the caller can handle the error
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
            // Attach the event to the case
            await post('/api/case/events', {
                caseId,
                fields: { soc_id: event.soc_id },
                dateRange: '',
                dateRangeFormat: '2006/01/02 3:04:05 PM',
                timezone: 'Local',
                acknowledged: false,
                escalated: false
            })

            // Acknowledge the event as escalated
            await post('/api/events/ack', {
                searchFilter: `_id:"${event.soc_id}"`,
                eventFilter: { '_id': event.soc_id },
                dateRange: '',
                dateRangeFormat: '2006/01/02 3:04:05 PM',
                timezone: 'Local',
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
     * Bulk escalate events by query to a new case
     */
    async function bulkEscalateByQuery(
        searchFilter: string,
        options: {
            title: string
            description?: string
            severity?: string
            template?: string
            dateRange?: string
            timezone?: string
        }
    ): Promise<string | null> {
        try {
            // Server has a 100 character limit on title
            const MAX_TITLE_LENGTH = 100
            let title = options.title
            if (title.length > MAX_TITLE_LENGTH) {
                title = title.substring(0, MAX_TITLE_LENGTH - 3) + '...'
            }

            // Create the case - matching classic UI format
            // Always include severity and template (even if empty) for server compatibility
            const caseData: Record<string, any> = {
                title,
                description: options.description || `Escalated alerts matching: ${searchFilter}`,
                severity: options.severity || '',
                template: options.template || ''
            }

            const response = await post<{ id: string }>('/api/case/', caseData)

            if (response?.id) {
                const caseId = response.id

                // Attach events by query to the case
                try {
                    await post('/api/case/events', {
                        caseId,
                        fields: {},
                        searchFilter,
                        dateRange: options.dateRange || '',
                        dateRangeFormat: '2006/01/02 3:04:05 PM',
                        timezone: options.timezone || 'Local',
                        acknowledged: false,
                        escalated: false
                    })
                } catch (attachError) {
                    console.warn('Failed to attach events to case:', attachError)
                }

                // Mark all matching events as escalated
                try {
                    await post('/api/events/ack', {
                        searchFilter,
                        eventFilter: {},
                        dateRange: options.dateRange || '',
                        timezone: options.timezone || 'Local',
                        acknowledge: true,
                        escalate: true
                    })
                } catch (ackError) {
                    console.warn('Failed to mark events as escalated:', ackError)
                }

                // Add to MRU
                addMruCase(caseId, caseData.title)

                return caseId
            }

            return null
        } catch (e) {
            console.error('Failed to bulk escalate:', e)
            throw e
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

        // Server has a 100 character limit on title
        const MAX_TITLE_LENGTH = 100
        let title = options.title || `Alert: ${ruleName}`
        if (title.length > MAX_TITLE_LENGTH) {
            title = title.substring(0, MAX_TITLE_LENGTH - 3) + '...'
        }

        // Build case data matching classic UI format
        // Always include severity and template (even if empty) for server compatibility
        const caseData: Record<string, any> = {
            title,
            description: options.description || buildCaseDescription(event, ruleDesc),
            severity: options.severity || '',
            template: options.template || ''
        }

        return caseData
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
    // PCAP Attachment
    // =========================================================================

    /**
     * Attach a PCAP file from a job to a case as an attachment
     */
    async function attachPcapToCase(
        pcapJobId: number,
        caseId: string,
        event?: EventRecord
    ): Promise<boolean> {
        console.log('[attachPcapToCase] Starting with jobId:', pcapJobId, 'caseId:', caseId)
        try {
            // Fetch the PCAP file as a blob
            const streamUrl = `/api/stream/${pcapJobId}?ext=pcap`
            console.log('[attachPcapToCase] Fetching PCAP from:', streamUrl)
            const response = await fetch(streamUrl)
            console.log('[attachPcapToCase] Fetch response status:', response.status)
            if (!response.ok) {
                throw new Error(`Failed to download PCAP file: ${response.status} ${response.statusText}`)
            }

            const blob = await response.blob()
            console.log('[attachPcapToCase] Got blob, size:', blob.size)

            // Generate filename from event info
            const timestamp = event?.soc_timestamp || new Date().toISOString()
            const dateStr = timestamp.replace(/[:/]/g, '-').replace(/\s/g, '_').slice(0, 19)
            const srcIp = event?.['source.ip'] || 'unknown'
            const dstIp = event?.['destination.ip'] || 'unknown'
            const filename = `pcap_${dateStr}_${srcIp}_to_${dstIp}.pcap`
            console.log('[attachPcapToCase] Generated filename:', filename)

            // Create a File object from the blob
            const file = new File([blob], filename, { type: 'application/vnd.tcpdump.pcap' })

            // Get CSRF token
            let srvToken: string | null = null
            try {
                const infoResponse = await fetch('/api/info')
                if (infoResponse.ok) {
                    const data = await infoResponse.json()
                    srvToken = data.srvToken || null
                }
            } catch (e) {
                console.debug('Could not fetch srvToken:', e)
            }
            console.log('[attachPcapToCase] Got srvToken:', !!srvToken)

            // Build multipart form data
            // NOTE: Do NOT include 'value' - the server sets it from the uploaded filename
            const artifactData = {
                caseId,
                groupType: 'attachments',
                artifactType: 'file',
                description: `Packet capture from alert investigation (Job #${pcapJobId})`,
                tlp: 'AMBER',
                tags: ['pcap', 'network'],
                protected: false
            }
            console.log('[attachPcapToCase] Artifact data:', artifactData)

            const formData = new FormData()
            formData.append('json', JSON.stringify(artifactData))
            formData.append('attachment', file)

            // Upload to case artifacts
            const headers: Record<string, string> = {}
            if (srvToken) {
                headers['X-Srv-Token'] = srvToken
            }

            console.log('[attachPcapToCase] Uploading to /api/case/artifacts...')
            const uploadResponse = await fetch('/api/case/artifacts', {
                method: 'POST',
                headers,
                body: formData
            })

            console.log('[attachPcapToCase] Upload response status:', uploadResponse.status)
            if (!uploadResponse.ok) {
                const errorText = await uploadResponse.text()
                console.error('[attachPcapToCase] Upload error:', errorText)
                throw new Error(errorText || 'Failed to upload PCAP attachment')
            }

            const result = await uploadResponse.json()
            console.log('[attachPcapToCase] Upload result:', result)

            return true
        } catch (e) {
            console.error('[attachPcapToCase] Failed:', e)
            return false
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
        bulkAcknowledgeByQuery,

        // Escalate
        escalateToNewCase,
        addToCase,
        bulkEscalateByQuery,
        buildCaseFromEvent,

        // MRU
        addMruCase,
        loadMruCases,

        // PCAP
        attachPcapToCase,

        // Custom actions
        executeAction,
        formatActionContent,

        // AI Investigation
        startInvestigation,
        generateInvestigationPrompt
    }
}
