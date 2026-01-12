<script setup lang="ts">
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

import { ref, computed, onMounted, onUnmounted } from 'vue'
import {
    Filter,
    Plus,
    Minus,
    Target,
    ArrowDown,
    BarChart3,
    Copy,
    ExternalLink,
    ChevronRight,
    X,
    Bot
} from 'lucide-vue-next'
import { cn } from '../../lib/utils'
import {
    FILTER_INCLUDE,
    FILTER_EXCLUDE,
    FILTER_EXACT,
    FILTER_DRILLDOWN,
    type FilterMode,
    type ActionConfig
} from '../../types/hunt'

// =============================================================================
// Props & Emits
// =============================================================================

const props = defineProps<{
    visible: boolean
    x: number
    y: number
    field: string
    value: any
    isNumeric: boolean
    actions?: ActionConfig[]
}>()

const emit = defineEmits<{
    'close': []
    'filter': [field: string, value: any, mode: FilterMode]
    'filter-less-than': [field: string, value: any]
    'filter-greater-than': [field: string, value: any]
    'filter-between': [field: string, start: any, end: any]
    'group-by': [field: string]
    'group-by-new': [field: string]
    'copy': [value: string]
    'action': [action: ActionConfig]
    'ask-ai': [field: string, value: any]
}>()

// =============================================================================
// State
// =============================================================================

const menuRef = ref<HTMLElement | null>(null)
const showBetweenDialog = ref(false)
const betweenStart = ref('')
const betweenEnd = ref('')

// =============================================================================
// Computed
// =============================================================================

const displayValue = computed(() => {
    const val = props.value
    if (val === null || val === undefined) return 'null'
    if (typeof val === 'object') return JSON.stringify(val)
    const str = String(val)
    return str.length > 50 ? str.substring(0, 50) + '...' : str
})

const menuStyle = computed(() => {
    // Position menu near click, but keep on screen
    let left = props.x
    let top = props.y

    // Adjust if too close to right edge
    if (typeof window !== 'undefined') {
        if (left + 280 > window.innerWidth) {
            left = window.innerWidth - 290
        }
        if (top + 400 > window.innerHeight) {
            top = window.innerHeight - 410
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

function handleFilter(mode: FilterMode) {
    emit('filter', props.field, props.value, mode)
    emit('close')
}

function handleLessThan() {
    emit('filter-less-than', props.field, props.value)
    emit('close')
}

function handleGreaterThan() {
    emit('filter-greater-than', props.field, props.value)
    emit('close')
}

function handleBetween() {
    if (betweenStart.value && betweenEnd.value) {
        emit('filter-between', props.field, betweenStart.value, betweenEnd.value)
        showBetweenDialog.value = false
        emit('close')
    }
}

function handleGroupBy() {
    emit('group-by', props.field)
    emit('close')
}

function handleGroupByNew() {
    emit('group-by-new', props.field)
    emit('close')
}

function handleCopy() {
    const val = props.value === null || props.value === undefined ? '' : String(props.value)
    navigator.clipboard.writeText(val)
    emit('close')
}

function handleAction(action: ActionConfig) {
    emit('action', action)
    emit('close')
}

function handleAskAi() {
    emit('ask-ai', props.field, props.value)
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
})

onUnmounted(() => {
    document.removeEventListener('click', handleClickOutside)
    document.removeEventListener('keydown', handleEscape)
})
</script>

<template>
    <Teleport to="body">
        <div
            v-if="visible"
            ref="menuRef"
            :style="menuStyle"
            class="fixed z-50 w-72 bg-card border border-border rounded-lg shadow-xl overflow-hidden"
            @click.stop
        >
            <!-- Header -->
            <div class="px-3 py-2 bg-muted/50 border-b border-border">
                <div class="flex items-center justify-between">
                    <div class="text-xs text-muted-foreground truncate flex-1">
                        {{ field }}
                    </div>
                    <button @click="emit('close')" class="p-0.5 hover:bg-muted rounded">
                        <X class="h-3 w-3 text-muted-foreground" />
                    </button>
                </div>
                <div class="text-sm font-medium truncate" :title="String(value)">
                    {{ displayValue }}
                </div>
            </div>

            <!-- Filter Actions -->
            <div class="p-1">
                <div class="px-2 py-1 text-xs text-muted-foreground font-medium">Filter</div>

                <button
                    @click="handleFilter(FILTER_INCLUDE)"
                    class="w-full flex items-center gap-2 px-2 py-1.5 text-sm rounded hover:bg-muted transition-colors"
                >
                    <Plus class="h-4 w-4 text-green-500" />
                    Include
                </button>

                <button
                    @click="handleFilter(FILTER_EXCLUDE)"
                    class="w-full flex items-center gap-2 px-2 py-1.5 text-sm rounded hover:bg-muted transition-colors"
                >
                    <Minus class="h-4 w-4 text-red-500" />
                    Exclude
                </button>

                <button
                    @click="handleFilter(FILTER_EXACT)"
                    class="w-full flex items-center gap-2 px-2 py-1.5 text-sm rounded hover:bg-muted transition-colors"
                >
                    <Target class="h-4 w-4 text-blue-500" />
                    Exact Match
                </button>

                <button
                    @click="handleFilter(FILTER_DRILLDOWN)"
                    class="w-full flex items-center gap-2 px-2 py-1.5 text-sm rounded hover:bg-muted transition-colors"
                >
                    <ArrowDown class="h-4 w-4 text-purple-500" />
                    Drilldown
                </button>
            </div>

            <!-- Numeric Filters (if numeric) -->
            <div v-if="isNumeric" class="p-1 border-t border-border">
                <div class="px-2 py-1 text-xs text-muted-foreground font-medium">Numeric</div>

                <button
                    @click="handleLessThan"
                    class="w-full flex items-center gap-2 px-2 py-1.5 text-sm rounded hover:bg-muted transition-colors"
                >
                    <span class="w-4 text-center text-muted-foreground">&lt;</span>
                    Less than {{ displayValue }}
                </button>

                <button
                    @click="handleGreaterThan"
                    class="w-full flex items-center gap-2 px-2 py-1.5 text-sm rounded hover:bg-muted transition-colors"
                >
                    <span class="w-4 text-center text-muted-foreground">&gt;</span>
                    Greater than {{ displayValue }}
                </button>

                <button
                    @click="showBetweenDialog = true"
                    class="w-full flex items-center gap-2 px-2 py-1.5 text-sm rounded hover:bg-muted transition-colors"
                >
                    <span class="w-4 text-center text-muted-foreground">↔</span>
                    Between range...
                </button>

                <!-- Between Dialog -->
                <div v-if="showBetweenDialog" class="p-2 bg-muted/50 rounded mt-1">
                    <div class="flex gap-2 items-center">
                        <input
                            v-model="betweenStart"
                            type="text"
                            placeholder="Start"
                            class="flex-1 px-2 py-1 text-sm rounded border border-border bg-background"
                        />
                        <span class="text-muted-foreground">to</span>
                        <input
                            v-model="betweenEnd"
                            type="text"
                            placeholder="End"
                            class="flex-1 px-2 py-1 text-sm rounded border border-border bg-background"
                        />
                    </div>
                    <div class="flex gap-2 mt-2">
                        <button
                            @click="showBetweenDialog = false"
                            class="flex-1 px-2 py-1 text-xs rounded bg-muted hover:bg-muted/80"
                        >
                            Cancel
                        </button>
                        <button
                            @click="handleBetween"
                            class="flex-1 px-2 py-1 text-xs rounded bg-primary text-primary-foreground hover:bg-primary/90"
                        >
                            Apply
                        </button>
                    </div>
                </div>
            </div>

            <!-- Group By -->
            <div class="p-1 border-t border-border">
                <div class="px-2 py-1 text-xs text-muted-foreground font-medium">Aggregate</div>

                <button
                    @click="handleGroupBy"
                    class="w-full flex items-center gap-2 px-2 py-1.5 text-sm rounded hover:bg-muted transition-colors"
                >
                    <BarChart3 class="h-4 w-4 text-purple-500" />
                    Add to Group By
                </button>

                <button
                    @click="handleGroupByNew"
                    class="w-full flex items-center gap-2 px-2 py-1.5 text-sm rounded hover:bg-muted transition-colors"
                >
                    <Plus class="h-4 w-4 text-purple-500" />
                    New Group By
                </button>
            </div>

            <!-- Utilities -->
            <div class="p-1 border-t border-border">
                <button
                    @click="handleCopy"
                    class="w-full flex items-center gap-2 px-2 py-1.5 text-sm rounded hover:bg-muted transition-colors"
                >
                    <Copy class="h-4 w-4 text-muted-foreground" />
                    Copy Value
                </button>

                <button
                    @click="handleAskAi"
                    class="w-full flex items-center gap-2 px-2 py-1.5 text-sm rounded hover:bg-muted transition-colors"
                >
                    <Bot class="h-4 w-4 text-purple-500" />
                    Ask AI
                </button>
            </div>

            <!-- Custom Actions -->
            <div v-if="actions && actions.length > 0" class="p-1 border-t border-border">
                <div class="px-2 py-1 text-xs text-muted-foreground font-medium">Actions</div>

                <button
                    v-for="action in actions"
                    :key="action.name"
                    @click="handleAction(action)"
                    class="w-full flex items-center gap-2 px-2 py-1.5 text-sm rounded hover:bg-muted transition-colors"
                >
                    <ExternalLink class="h-4 w-4 text-muted-foreground" />
                    {{ action.name }}
                </button>
            </div>
        </div>
    </Teleport>
</template>
