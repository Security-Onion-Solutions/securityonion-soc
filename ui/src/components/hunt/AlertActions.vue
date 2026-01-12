<script setup lang="ts">
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

import { ref, computed } from 'vue'
import {
    Check,
    Undo2,
    ArrowUpRight,
    Bot,
    Info,
    MoreVertical,
    Loader2
} from 'lucide-vue-next'
import { cn } from '../../lib/utils'
import { type EventRecord } from '../../types/hunt'

// =============================================================================
// Props & Emits
// =============================================================================

const props = defineProps<{
    event: EventRecord
    ackEnabled: boolean
    escalateEnabled: boolean
    investigateEnabled: boolean
    isAcknowledged?: boolean
    isEscalated?: boolean
    hasInvestigation?: boolean
    loading?: boolean
}>()

const emit = defineEmits<{
    'acknowledge': [event: EventRecord, acknowledge: boolean]
    'escalate': [event: EventRecord, mouseEvent: MouseEvent]
    'investigate': [event: EventRecord]
    'view-info': [event: EventRecord]
}>()

// =============================================================================
// State
// =============================================================================

const isProcessing = ref(false)

// =============================================================================
// Computed
// =============================================================================

const acknowledged = computed(() => {
    return props.isAcknowledged ||
        props.event['event.acknowledged'] === true ||
        props.event['so_status'] === 'acknowledged'
})

const escalated = computed(() => {
    return props.isEscalated ||
        props.event['event.escalated'] === true ||
        props.event['so_case.id'] !== undefined
})

const hasAiInvestigation = computed(() => {
    return props.hasInvestigation || props.event._aiInvestigated
})

// =============================================================================
// Methods
// =============================================================================

async function handleAcknowledge() {
    if (isProcessing.value) return
    isProcessing.value = true
    try {
        emit('acknowledge', props.event, !acknowledged.value)
    } finally {
        isProcessing.value = false
    }
}

function handleEscalate(e: MouseEvent) {
    emit('escalate', props.event, e)
}

function handleInvestigate() {
    emit('investigate', props.event)
}

function handleViewInfo() {
    emit('view-info', props.event)
}
</script>

<template>
    <div class="flex items-center gap-1">
        <!-- Acknowledge Button -->
        <button
            v-if="ackEnabled"
            @click.stop="handleAcknowledge"
            :disabled="isProcessing || loading"
            :title="acknowledged ? 'Unacknowledge' : 'Acknowledge'"
            :class="cn(
                'p-1.5 rounded-md transition-colors',
                acknowledged
                    ? 'bg-green-500/10 text-green-500 hover:bg-green-500/20'
                    : 'text-muted-foreground hover:bg-muted hover:text-foreground',
                (isProcessing || loading) && 'opacity-50 cursor-not-allowed'
            )"
        >
            <Loader2 v-if="isProcessing" class="h-4 w-4 animate-spin" />
            <Undo2 v-else-if="acknowledged" class="h-4 w-4" />
            <Check v-else class="h-4 w-4" />
        </button>

        <!-- Escalate Button -->
        <button
            v-if="escalateEnabled"
            @click.stop="handleEscalate"
            :disabled="loading"
            :title="escalated ? 'Already escalated' : 'Escalate to case'"
            :class="cn(
                'p-1.5 rounded-md transition-colors',
                escalated
                    ? 'bg-blue-500/10 text-blue-500'
                    : 'text-muted-foreground hover:bg-muted hover:text-foreground',
                loading && 'opacity-50 cursor-not-allowed'
            )"
        >
            <ArrowUpRight class="h-4 w-4" />
        </button>

        <!-- AI Investigation Button -->
        <button
            v-if="investigateEnabled"
            @click.stop="handleInvestigate"
            :disabled="loading"
            :title="hasAiInvestigation ? 'Continue investigation' : 'Start AI investigation'"
            :class="cn(
                'p-1.5 rounded-md transition-colors',
                hasAiInvestigation
                    ? 'bg-purple-500/10 text-purple-500 hover:bg-purple-500/20'
                    : 'text-muted-foreground hover:bg-muted hover:text-foreground',
                loading && 'opacity-50 cursor-not-allowed'
            )"
        >
            <Bot class="h-4 w-4" />
        </button>

        <!-- View Info Button -->
        <button
            @click.stop="handleViewInfo"
            :disabled="loading"
            title="View details"
            :class="cn(
                'p-1.5 rounded-md transition-colors',
                'text-muted-foreground hover:bg-muted hover:text-foreground',
                loading && 'opacity-50 cursor-not-allowed'
            )"
        >
            <Info class="h-4 w-4" />
        </button>
    </div>
</template>
