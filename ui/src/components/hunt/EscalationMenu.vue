<script setup lang="ts">
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

import { ref, computed, onMounted, onUnmounted } from 'vue'
import {
    Plus,
    Briefcase,
    X,
    Loader2,
    AlertTriangle
} from 'lucide-vue-next'
import { cn } from '../../lib/utils'
import { useApi } from '../../composables/useApi'
import { type EventRecord } from '../../types/hunt'

// =============================================================================
// Props & Emits
// =============================================================================

const props = defineProps<{
    visible: boolean
    x: number
    y: number
    event: EventRecord | null
    escalateRelatedEvents?: boolean
}>()

const emit = defineEmits<{
    'close': []
    'create-new': [event: EventRecord, includeRelated: boolean]
    'add-to-case': [event: EventRecord, caseId: string, includeRelated: boolean]
}>()

// =============================================================================
// State
// =============================================================================

const { get, loading } = useApi()
const menuRef = ref<HTMLElement | null>(null)
const mruCases = ref<{ id: string; title: string }[]>([])
const includeRelated = ref(true)
const loadingCases = ref(false)

// =============================================================================
// Computed
// =============================================================================

const menuStyle = computed(() => {
    let left = props.x
    let top = props.y

    if (typeof window !== 'undefined') {
        if (left + 320 > window.innerWidth) {
            left = window.innerWidth - 330
        }
        if (top + 300 > window.innerHeight) {
            top = window.innerHeight - 310
        }
    }

    return {
        left: `${left}px`,
        top: `${top}px`
    }
})

// =============================================================================
// Methods
// =============================================================================

async function loadMruCases() {
    loadingCases.value = true
    try {
        // Load recently used cases
        const stored = localStorage.getItem('hunt.mruCases')
        if (stored) {
            mruCases.value = JSON.parse(stored)
        }
    } catch (e) {
        console.error('Failed to load MRU cases:', e)
    } finally {
        loadingCases.value = false
    }
}

function handleCreateNew() {
    if (!props.event) return
    emit('create-new', props.event, includeRelated.value)
    emit('close')
}

function handleAddToCase(caseId: string) {
    if (!props.event) return
    emit('add-to-case', props.event, caseId, includeRelated.value)
    emit('close')
}

function handleClickOutside(event: MouseEvent) {
    if (menuRef.value && !menuRef.value.contains(event.target as Node)) {
        emit('close')
    }
}

function handleEscape(event: KeyboardEvent) {
    if (event.key === 'Escape') {
        emit('close')
    }
}

// =============================================================================
// Lifecycle
// =============================================================================

onMounted(() => {
    document.addEventListener('click', handleClickOutside)
    document.addEventListener('keydown', handleEscape)
    loadMruCases()
})

onUnmounted(() => {
    document.removeEventListener('click', handleClickOutside)
    document.removeEventListener('keydown', handleEscape)
})
</script>

<template>
    <Teleport to="body">
        <div
            v-if="visible && event"
            ref="menuRef"
            :style="menuStyle"
            class="fixed z-50 w-80 bg-card border border-border rounded-lg shadow-xl overflow-hidden"
            @click.stop
        >
            <!-- Header -->
            <div class="px-3 py-2 bg-muted/50 border-b border-border">
                <div class="flex items-center justify-between">
                    <div class="flex items-center gap-2">
                        <Briefcase class="h-4 w-4 text-primary" />
                        <span class="font-medium text-sm">Escalate to Case</span>
                    </div>
                    <button @click="emit('close')" class="p-0.5 hover:bg-muted rounded">
                        <X class="h-3 w-3 text-muted-foreground" />
                    </button>
                </div>
            </div>

            <!-- Related Events Option -->
            <div v-if="escalateRelatedEvents" class="px-3 py-2 border-b border-border">
                <label class="flex items-center gap-2 cursor-pointer">
                    <input
                        type="checkbox"
                        v-model="includeRelated"
                        class="rounded border-border"
                    />
                    <span class="text-sm">Include related events</span>
                </label>
            </div>

            <!-- Create New Case -->
            <div class="p-1">
                <button
                    @click="handleCreateNew"
                    class="w-full flex items-center gap-2 px-3 py-2 text-sm rounded hover:bg-muted transition-colors"
                >
                    <Plus class="h-4 w-4 text-green-500" />
                    <span>Create New Case</span>
                </button>
            </div>

            <!-- Recent Cases -->
            <div v-if="mruCases.length > 0" class="border-t border-border">
                <div class="px-3 py-1.5 text-xs text-muted-foreground font-medium">
                    Recent Cases
                </div>
                <div class="p-1 max-h-40 overflow-auto">
                    <button
                        v-for="c in mruCases"
                        :key="c.id"
                        @click="handleAddToCase(c.id)"
                        class="w-full flex items-center gap-2 px-3 py-2 text-sm rounded hover:bg-muted transition-colors"
                    >
                        <Briefcase class="h-4 w-4 text-muted-foreground" />
                        <span class="truncate">{{ c.title }}</span>
                    </button>
                </div>
            </div>

            <!-- Loading State -->
            <div v-if="loadingCases" class="p-4 flex items-center justify-center">
                <Loader2 class="h-5 w-5 animate-spin text-muted-foreground" />
            </div>

            <!-- Empty State -->
            <div v-else-if="mruCases.length === 0" class="p-4 text-center text-sm text-muted-foreground">
                No recent cases. Create a new case to get started.
            </div>
        </div>
    </Teleport>
</template>
