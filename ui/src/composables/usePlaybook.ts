// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

import { ref } from 'vue'
import { useApi } from './useApi'
import { type EventRecord, type PlaybookQuestion } from '../types/hunt'

// =============================================================================
// Types
// =============================================================================

// Question type as returned by the API for detection playbooks
export interface PlaybookQuestionRaw {
    question: string
    context: string
    range?: string
    query: string  // Raw Sigma YAML query
    answer_sources?: string[]
    oqlQuery?: string  // Converted OQL query (populated after processing)
    filledQuery?: string
    fields?: string[]
    queryResults?: any[]
}

export interface Playbook {
    id?: string
    name: string
    description: string
    detection_id?: string
    detection_category?: string
    detection_type?: string
    contributors?: string[]
    questions: PlaybookQuestionRaw[]
    isCommunity?: boolean
    ruleset?: string
    createTime?: string
    updateTime?: string
}

export interface GroupedPlaybooks {
    detectionLevel: Playbook[]
    categoryLevel: Playbook[]
    engineLevel: Playbook[]
}

export interface PlaybookState {
    loading: boolean
    error: boolean
    playbooks: Playbook[] | null
    questions: PlaybookQuestion[]
    expandedQuestions: number[]
}

// =============================================================================
// Composable
// =============================================================================

export function usePlaybook() {
    const { get, post, put, del, loading, error } = useApi()

    // Cache playbook state per event
    const playbookCache = ref<Map<string, PlaybookState>>(new Map())

    // =========================================================================
    // Load Playbook
    // =========================================================================

    /**
     * Load playbook for an event
     */
    async function loadPlaybook(event: EventRecord): Promise<PlaybookState | null> {
        const socId = event.soc_id
        if (!socId) return null

        // Check cache
        const cached = playbookCache.value.get(socId)
        if (cached) return cached

        // Create initial state
        const state: PlaybookState = {
            loading: true,
            error: false,
            playbooks: null,
            questions: [],
            expandedQuestions: []
        }
        playbookCache.value.set(socId, state)

        try {
            const response = await get<Playbook[]>(`/api/playbook/event/${socId}`)

            if (response) {
                state.playbooks = response

                // Process questions - sort by those with results first
                const good: PlaybookQuestion[] = []
                const bad: PlaybookQuestion[] = []

                for (const pb of response) {
                    for (const q of pb.questions) {
                        // Check if question has results
                        if (q.queryResults && q.queryResults.length > 0) {
                            good.push(q)
                        } else {
                            bad.push(q)
                        }

                        // Determine if aggregate query
                        q.isAggregate = isQuestionAggregate(q)

                        // Add appropriate first field
                        if (q.isAggregate) {
                            q.fields = ['count', ...q.fields]
                        } else {
                            q.fields = ['@timestamp', ...q.fields]
                        }
                    }
                }

                // Questions with results first
                state.questions = [...good, ...bad]

                // Auto-expand questions with results
                state.expandedQuestions = good.map((_, i) => i)
            }

            state.loading = false
        } catch (e) {
            console.error('Failed to load playbook:', e)
            state.error = true
            state.loading = false
        }

        return state
    }

    /**
     * Check if a question is an aggregate query (has groupby)
     */
    function isQuestionAggregate(question: PlaybookQuestion): boolean {
        const query = question.oqlQuery || ''
        return query.includes('| groupby') || query.includes('|groupby')
    }

    // =========================================================================
    // Question Management
    // =========================================================================

    /**
     * Toggle question expansion
     */
    function toggleQuestion(socId: string, questionIndex: number) {
        const state = playbookCache.value.get(socId)
        if (!state) return

        const idx = state.expandedQuestions.indexOf(questionIndex)
        if (idx >= 0) {
            state.expandedQuestions.splice(idx, 1)
        } else {
            state.expandedQuestions.push(questionIndex)
        }
    }

    /**
     * Expand all questions
     */
    function expandAllQuestions(socId: string) {
        const state = playbookCache.value.get(socId)
        if (!state) return

        state.expandedQuestions = state.questions.map((_, i) => i)
    }

    /**
     * Collapse all questions
     */
    function collapseAllQuestions(socId: string) {
        const state = playbookCache.value.get(socId)
        if (!state) return

        state.expandedQuestions = []
    }

    /**
     * Check if question is expanded
     */
    function isQuestionExpanded(socId: string, questionIndex: number): boolean {
        const state = playbookCache.value.get(socId)
        if (!state) return false

        return state.expandedQuestions.includes(questionIndex)
    }

    // =========================================================================
    // Build Hunt Query from Question
    // =========================================================================

    /**
     * Build a hunt query from a playbook question
     */
    function buildHuntQuery(
        question: PlaybookQuestion,
        event: EventRecord
    ): { query: string; range: string } {
        let query = question.oqlQuery || '*'
        let range = ''

        // Parse the range from question
        if (question.range) {
            range = buildQuestionRange(event, question.range)
        }

        // Replace placeholders in query with event values
        query = replacePlaceholders(query, event)

        return { query, range }
    }

    /**
     * Build time range for question based on event timestamp
     */
    function buildQuestionRange(event: EventRecord, range: string): string {
        if (!range) return ''

        const timestamp = event.soc_timestamp || event['@timestamp']
        if (!timestamp) return ''

        const eventTime = new Date(timestamp)
        if (isNaN(eventTime.getTime())) return ''

        let plusMinus = false
        let lookingBack = false
        let rangeStr = range

        if (rangeStr.startsWith('+/-')) {
            plusMinus = true
            rangeStr = rangeStr.substring(3)
        } else if (rangeStr.startsWith('-')) {
            lookingBack = true
            rangeStr = rangeStr.substring(1)
        }

        const unit = rangeStr[rangeStr.length - 1].toLowerCase()
        const value = parseInt(rangeStr.substring(0, rangeStr.length - 1))

        if (isNaN(value)) return ''

        const unitMap: Record<string, number> = {
            'd': 24 * 60 * 60 * 1000,
            'h': 60 * 60 * 1000,
            'm': 60 * 1000,
            's': 1000
        }

        const ms = unitMap[unit]
        if (!ms) return ''

        const offset = value * ms
        let start: Date
        let end: Date

        if (plusMinus) {
            start = new Date(eventTime.getTime() - offset)
            end = new Date(eventTime.getTime() + offset)
        } else if (lookingBack) {
            start = new Date(eventTime.getTime() - offset)
            end = eventTime
        } else {
            start = eventTime
            end = new Date(eventTime.getTime() + offset)
        }

        return `${formatDateForRange(start)} - ${formatDateForRange(end)}`
    }

    function formatDateForRange(date: Date): string {
        const pad = (n: number) => n.toString().padStart(2, '0')
        const year = date.getFullYear()
        const month = pad(date.getMonth() + 1)
        const day = pad(date.getDate())
        let hours = date.getHours()
        const ampm = hours >= 12 ? 'PM' : 'AM'
        hours = hours % 12
        hours = hours ? hours : 12
        const minutes = pad(date.getMinutes())
        const seconds = pad(date.getSeconds())
        return `${year}/${month}/${day} ${hours}:${minutes}:${seconds} ${ampm}`
    }

    /**
     * Replace placeholders in query with event field values
     */
    function replacePlaceholders(query: string, event: EventRecord): string {
        return query.replace(/\{([^}]+)\}/g, (match, fieldName) => {
            const value = event[fieldName]
            if (value !== undefined && value !== null) {
                // Escape quotes in value
                const escaped = String(value).replace(/"/g, '\\"')
                return `"${escaped}"`
            }
            return match
        })
    }

    // =========================================================================
    // Get Playbook State
    // =========================================================================

    function getPlaybookState(socId: string): PlaybookState | null {
        return playbookCache.value.get(socId) || null
    }

    function hasPlaybook(socId: string): boolean {
        return playbookCache.value.has(socId)
    }

    function clearCache() {
        playbookCache.value.clear()
    }

    // =========================================================================
    // CRUD Operations for Detection Playbooks
    // =========================================================================

    /**
     * Get playbooks for a detection by public ID
     */
    async function getPlaybooksForDetection(publicId: string): Promise<Playbook[]> {
        try {
            const response = await get<Playbook[]>(`/api/playbook/detection/${publicId}`)
            return response || []
        } catch (e) {
            console.error('Failed to get playbooks for detection:', e)
            return []
        }
    }

    /**
     * Get playbooks for a detection grouped by match level (detection, category, engine)
     */
    async function getPlaybooksForDetectionGrouped(publicId: string): Promise<GroupedPlaybooks> {
        try {
            const response = await get<GroupedPlaybooks>(`/api/playbook/detection/${publicId}/grouped`)
            return response || { detectionLevel: [], categoryLevel: [], engineLevel: [] }
        } catch (e) {
            console.error('Failed to get grouped playbooks for detection:', e)
            return { detectionLevel: [], categoryLevel: [], engineLevel: [] }
        }
    }

    /**
     * Get all playbooks
     */
    async function getAllPlaybooks(): Promise<Playbook[]> {
        try {
            const response = await get<Playbook[]>('/api/playbook/')
            return response || []
        } catch (e) {
            console.error('Failed to get all playbooks:', e)
            return []
        }
    }

    /**
     * Create a new playbook
     */
    async function createPlaybook(playbook: Playbook): Promise<Playbook | null> {
        try {
            const response = await post<Playbook>('/api/playbook/', playbook)
            return response
        } catch (e) {
            console.error('Failed to create playbook:', e)
            throw e
        }
    }

    /**
     * Update an existing playbook
     */
    async function updatePlaybook(playbook: Playbook): Promise<Playbook | null> {
        try {
            const response = await put<Playbook>('/api/playbook/', playbook)
            return response
        } catch (e) {
            console.error('Failed to update playbook:', e)
            throw e
        }
    }

    /**
     * Delete a playbook
     */
    async function deletePlaybook(playbookId: string): Promise<boolean> {
        try {
            await del(`/api/playbook/${playbookId}`)
            return true
        } catch (e) {
            console.error('Failed to delete playbook:', e)
            throw e
        }
    }

    return {
        // State
        loading,
        error,
        playbookCache,

        // Load
        loadPlaybook,

        // Question management
        toggleQuestion,
        expandAllQuestions,
        collapseAllQuestions,
        isQuestionExpanded,

        // Query building
        buildHuntQuery,
        buildQuestionRange,
        replacePlaceholders,

        // State access
        getPlaybookState,
        hasPlaybook,
        clearCache,

        // CRUD operations
        getPlaybooksForDetection,
        getPlaybooksForDetectionGrouped,
        getAllPlaybooks,
        createPlaybook,
        updatePlaybook,
        deletePlaybook
    }
}
