// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

import { ref, computed, watch, isRef, unref, type Ref, type ComputedRef, type MaybeRef } from 'vue'

/**
 * Represents a marked/selected event from guided analysis
 */
export interface MarkedEvent {
    soc_id: string
    note: string
    sourceQuestion: string
    isHighlighted: boolean
}

const STORAGE_KEY_PREFIX = 'markedEvents:'

/**
 * Composable for managing marked/selected events during guided analysis
 * Allows analysts to select specific events, add notes, and track which
 * events should be highlighted when escalating to a case.
 *
 * @param alertIdRef - Optional alert ID (string or ref) for localStorage persistence.
 *                     If provided, marked events are saved to localStorage and restored on page refresh.
 */
export function useMarkedEvents(alertIdRef?: MaybeRef<string>) {
    // Map of soc_id -> MarkedEvent
    const markedEvents: Ref<Map<string, MarkedEvent>> = ref(new Map())

    // Track the current alert ID for storage
    const currentAlertId = ref<string>('')

    /**
     * Get storage key for current alert
     */
    function getStorageKey(): string | null {
        return currentAlertId.value ? `${STORAGE_KEY_PREFIX}${currentAlertId.value}` : null
    }

    /**
     * Load marked events from localStorage
     */
    function loadFromStorage(): void {
        const storageKey = getStorageKey()
        if (!storageKey) return

        try {
            const stored = localStorage.getItem(storageKey)
            if (stored) {
                const parsed = JSON.parse(stored) as MarkedEvent[]
                const map = new Map<string, MarkedEvent>()
                for (const event of parsed) {
                    map.set(event.soc_id, event)
                }
                markedEvents.value = map
                console.log('[useMarkedEvents] Loaded from storage:', parsed.length, 'events for alert:', currentAlertId.value)
            } else {
                // Clear any existing marks when switching to a new alert with no saved data
                markedEvents.value = new Map()
            }
        } catch (e) {
            console.error('[useMarkedEvents] Failed to load from storage:', e)
        }
    }

    /**
     * Save marked events to localStorage
     */
    function saveToStorage(): void {
        const storageKey = getStorageKey()
        if (!storageKey) return

        try {
            const events = Array.from(markedEvents.value.values())
            if (events.length > 0) {
                localStorage.setItem(storageKey, JSON.stringify(events))
                console.log('[useMarkedEvents] Saved to storage:', events.length, 'events')
            } else {
                // Remove storage if no events
                localStorage.removeItem(storageKey)
            }
        } catch (e) {
            console.error('[useMarkedEvents] Failed to save to storage:', e)
        }
    }

    /**
     * Toggle the marked state of an event
     */
    function toggleMarked(socId: string, question: string = ''): void {
        if (markedEvents.value.has(socId)) {
            markedEvents.value.delete(socId)
        } else {
            markedEvents.value.set(socId, {
                soc_id: socId,
                note: '',
                sourceQuestion: question,
                isHighlighted: true
            })
        }
        // Trigger reactivity
        markedEvents.value = new Map(markedEvents.value)
        saveToStorage()
    }

    /**
     * Mark an event (add to selection)
     */
    function markEvent(socId: string, question: string = ''): void {
        if (!markedEvents.value.has(socId)) {
            markedEvents.value.set(socId, {
                soc_id: socId,
                note: '',
                sourceQuestion: question,
                isHighlighted: true
            })
            // Trigger reactivity
            markedEvents.value = new Map(markedEvents.value)
            saveToStorage()
        }
    }

    /**
     * Unmark an event (remove from selection)
     */
    function unmarkEvent(socId: string): void {
        if (markedEvents.value.has(socId)) {
            markedEvents.value.delete(socId)
            // Trigger reactivity
            markedEvents.value = new Map(markedEvents.value)
            saveToStorage()
        }
    }

    /**
     * Check if an event is marked
     */
    function isMarked(socId: string): boolean {
        return markedEvents.value.has(socId)
    }

    /**
     * Update the note for a marked event
     */
    function updateNote(socId: string, note: string): void {
        console.log('[useMarkedEvents] updateNote called:', { socId, note: note.substring(0, 50) + (note.length > 50 ? '...' : '') })
        const event = markedEvents.value.get(socId)
        if (event) {
            event.note = note
            // Trigger reactivity
            markedEvents.value = new Map(markedEvents.value)
            saveToStorage()
            console.log('[useMarkedEvents] Note updated and saved for event:', socId)
        } else {
            console.warn('[useMarkedEvents] Could not find marked event to update note:', socId)
        }
    }

    /**
     * Get the note for an event
     */
    function getNote(socId: string): string {
        return markedEvents.value.get(socId)?.note || ''
    }

    /**
     * Get all marked events as an array
     */
    function getMarkedEvents(): MarkedEvent[] {
        const events = Array.from(markedEvents.value.values())
        console.log('[useMarkedEvents] getMarkedEvents called, returning:', events.map(e => ({
            soc_id: e.soc_id,
            note: e.note ? e.note.substring(0, 30) + '...' : '(empty)',
            isHighlighted: e.isHighlighted
        })))
        return events
    }

    /**
     * Get all marked event IDs
     */
    function getMarkedEventIds(): string[] {
        return Array.from(markedEvents.value.keys())
    }

    /**
     * Mark multiple events at once
     */
    function markAll(events: Array<{ soc_id: string; question?: string }>): void {
        for (const event of events) {
            if (!markedEvents.value.has(event.soc_id)) {
                markedEvents.value.set(event.soc_id, {
                    soc_id: event.soc_id,
                    note: '',
                    sourceQuestion: event.question || '',
                    isHighlighted: true
                })
            }
        }
        // Trigger reactivity
        markedEvents.value = new Map(markedEvents.value)
        saveToStorage()
    }

    /**
     * Unmark all events
     */
    function clearMarks(): void {
        markedEvents.value.clear()
        // Trigger reactivity
        markedEvents.value = new Map(markedEvents.value)
        saveToStorage()
    }

    /**
     * Clear storage for this alert (called after successful escalation)
     */
    function clearStorage(): void {
        const storageKey = getStorageKey()
        if (storageKey) {
            localStorage.removeItem(storageKey)
            console.log('[useMarkedEvents] Cleared storage for alert')
        }
        // Also clear in-memory marks
        markedEvents.value = new Map()
    }

    /**
     * Number of marked events
     */
    const markedCount: ComputedRef<number> = computed(() => markedEvents.value.size)

    /**
     * Check if any events are marked
     */
    const hasMarkedEvents: ComputedRef<boolean> = computed(() => markedEvents.value.size > 0)

    // Watch for alertId changes and load from storage
    if (alertIdRef !== undefined) {
        // If it's a ref, watch it
        if (isRef(alertIdRef)) {
            watch(alertIdRef, (newId) => {
                if (newId && newId !== currentAlertId.value) {
                    currentAlertId.value = newId
                    loadFromStorage()
                }
            }, { immediate: true })
        } else {
            // It's a plain string
            currentAlertId.value = alertIdRef
            loadFromStorage()
        }
    }

    return {
        markedEvents,
        markedCount,
        hasMarkedEvents,
        toggleMarked,
        markEvent,
        unmarkEvent,
        isMarked,
        updateNote,
        getNote,
        getMarkedEvents,
        getMarkedEventIds,
        markAll,
        clearMarks,
        clearStorage
    }
}
