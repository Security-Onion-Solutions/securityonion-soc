<script setup lang="ts">
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

import { ref, computed } from 'vue'
import {
    CheckSquare,
    Square,
    Minus,
    Power,
    PowerOff,
    Trash2,
    X,
    AlertTriangle,
    Loader2
} from 'lucide-vue-next'
import { cn } from '../../lib/utils'
import { type EventRecord } from '../../types/hunt'

// =============================================================================
// Props & Emits
// =============================================================================

const props = defineProps<{
    selectedCount: number
    totalCount: number
    selectAllState: boolean
    selectAllIndeterminate: boolean
    loading?: boolean
}>()

const emit = defineEmits<{
    'toggle-select-all': []
    'clear-selection': []
    'bulk-enable': []
    'bulk-disable': []
    'bulk-delete': []
}>()

// =============================================================================
// State
// =============================================================================

const showDeleteConfirm = ref(false)

// =============================================================================
// Computed
// =============================================================================

const hasSelection = computed(() => props.selectedCount > 0)

const selectionText = computed(() => {
    if (props.selectedCount === 0) return 'None selected'
    if (props.selectedCount === 1) return '1 item selected'
    return `${props.selectedCount} items selected`
})

// =============================================================================
// Methods
// =============================================================================

function handleToggleSelectAll() {
    emit('toggle-select-all')
}

function handleClearSelection() {
    emit('clear-selection')
}

function handleEnable() {
    emit('bulk-enable')
}

function handleDisable() {
    emit('bulk-disable')
}

function handleDelete() {
    showDeleteConfirm.value = true
}

function confirmDelete() {
    emit('bulk-delete')
    showDeleteConfirm.value = false
}

function cancelDelete() {
    showDeleteConfirm.value = false
}
</script>

<template>
    <div class="flex items-center gap-4 px-4 py-2 bg-muted/50 border-b border-border rounded-t-lg">
        <!-- Select All Checkbox -->
        <button
            @click="handleToggleSelectAll"
            :disabled="loading"
            class="flex items-center gap-2 text-sm hover:text-primary transition-colors disabled:opacity-50"
        >
            <component
                :is="selectAllState ? CheckSquare : (selectAllIndeterminate ? Minus : Square)"
                :class="cn(
                    'h-4 w-4',
                    selectAllState || selectAllIndeterminate ? 'text-primary' : 'text-muted-foreground'
                )"
            />
            <span class="hidden sm:inline">Select All</span>
        </button>

        <!-- Selection Count -->
        <div class="text-sm text-muted-foreground">
            {{ selectionText }}
        </div>

        <!-- Spacer -->
        <div class="flex-1" />

        <!-- Bulk Actions (visible when items selected) -->
        <div v-if="hasSelection" class="flex items-center gap-2">
            <!-- Enable Button -->
            <button
                @click="handleEnable"
                :disabled="loading"
                :class="cn(
                    'flex items-center gap-1 px-3 py-1.5 text-sm rounded-md transition-colors',
                    'bg-green-500/10 text-green-500 hover:bg-green-500/20',
                    'disabled:opacity-50 disabled:cursor-not-allowed'
                )"
            >
                <Loader2 v-if="loading" class="h-4 w-4 animate-spin" />
                <Power v-else class="h-4 w-4" />
                <span class="hidden sm:inline">Enable</span>
            </button>

            <!-- Disable Button -->
            <button
                @click="handleDisable"
                :disabled="loading"
                :class="cn(
                    'flex items-center gap-1 px-3 py-1.5 text-sm rounded-md transition-colors',
                    'bg-amber-500/10 text-amber-500 hover:bg-amber-500/20',
                    'disabled:opacity-50 disabled:cursor-not-allowed'
                )"
            >
                <Loader2 v-if="loading" class="h-4 w-4 animate-spin" />
                <PowerOff v-else class="h-4 w-4" />
                <span class="hidden sm:inline">Disable</span>
            </button>

            <!-- Delete Button -->
            <button
                @click="handleDelete"
                :disabled="loading"
                :class="cn(
                    'flex items-center gap-1 px-3 py-1.5 text-sm rounded-md transition-colors',
                    'bg-destructive/10 text-destructive hover:bg-destructive/20',
                    'disabled:opacity-50 disabled:cursor-not-allowed'
                )"
            >
                <Loader2 v-if="loading" class="h-4 w-4 animate-spin" />
                <Trash2 v-else class="h-4 w-4" />
                <span class="hidden sm:inline">Delete</span>
            </button>

            <!-- Clear Selection -->
            <button
                @click="handleClearSelection"
                :disabled="loading"
                class="p-1.5 text-muted-foreground hover:text-foreground hover:bg-muted rounded-md transition-colors disabled:opacity-50"
                title="Clear selection"
            >
                <X class="h-4 w-4" />
            </button>
        </div>

        <!-- Delete Confirmation Dialog -->
        <Teleport to="body">
            <div
                v-if="showDeleteConfirm"
                class="fixed inset-0 z-50 flex items-center justify-center bg-black/50"
                @click.self="cancelDelete"
            >
                <div class="bg-card border border-border rounded-lg shadow-xl p-6 max-w-md mx-4">
                    <div class="flex items-center gap-3 mb-4">
                        <div class="p-2 rounded-full bg-destructive/10">
                            <AlertTriangle class="h-6 w-6 text-destructive" />
                        </div>
                        <h3 class="text-lg font-semibold">Confirm Delete</h3>
                    </div>

                    <p class="text-muted-foreground mb-6">
                        Are you sure you want to delete {{ selectedCount }}
                        {{ selectedCount === 1 ? 'detection' : 'detections' }}?
                        This action cannot be undone.
                    </p>

                    <div class="flex justify-end gap-3">
                        <button
                            @click="cancelDelete"
                            class="px-4 py-2 text-sm rounded-md bg-muted hover:bg-muted/80 transition-colors"
                        >
                            Cancel
                        </button>
                        <button
                            @click="confirmDelete"
                            class="px-4 py-2 text-sm rounded-md bg-destructive text-destructive-foreground hover:bg-destructive/90 transition-colors"
                        >
                            Delete
                        </button>
                    </div>
                </div>
            </div>
        </Teleport>
    </div>
</template>
