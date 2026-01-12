<script setup lang="ts">
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

import { ref, computed, onMounted, watch } from 'vue'
import {
    HelpCircle,
    ChevronDown,
    ChevronRight,
    ExternalLink,
    CheckCircle2,
    XCircle,
    Loader2,
    ChevronsUpDown,
    AlertTriangle
} from 'lucide-vue-next'
import { cn } from '../../lib/utils'
import { usePlaybook, type PlaybookState } from '../../composables/usePlaybook'
import { type EventRecord, type PlaybookQuestion } from '../../types/hunt'

// =============================================================================
// Props & Emits
// =============================================================================

const props = defineProps<{
    event: EventRecord
    visible: boolean
}>()

const emit = defineEmits<{
    'hunt-query': [query: string, range: string]
}>()

// =============================================================================
// Composables
// =============================================================================

const {
    loadPlaybook,
    toggleQuestion,
    expandAllQuestions,
    collapseAllQuestions,
    isQuestionExpanded,
    getPlaybookState,
    buildHuntQuery
} = usePlaybook()

// =============================================================================
// State
// =============================================================================

const playbookState = ref<PlaybookState | null>(null)

// =============================================================================
// Computed
// =============================================================================

const questions = computed(() => playbookState.value?.questions || [])

const hasQuestions = computed(() => questions.value.length > 0)

const questionsWithResults = computed(() => {
    return questions.value.filter(q => q.queryResults && q.queryResults.length > 0).length
})

const allExpanded = computed(() => {
    if (!playbookState.value) return false
    return playbookState.value.expandedQuestions.length === questions.value.length
})

// =============================================================================
// Methods
// =============================================================================

async function load() {
    if (!props.event || !props.visible) return
    playbookState.value = await loadPlaybook(props.event)
}

function handleToggleQuestion(index: number) {
    if (!props.event) return
    toggleQuestion(props.event.soc_id, index)
    // Force reactivity update
    playbookState.value = getPlaybookState(props.event.soc_id)
}

function handleToggleAll() {
    if (!props.event) return
    if (allExpanded.value) {
        collapseAllQuestions(props.event.soc_id)
    } else {
        expandAllQuestions(props.event.soc_id)
    }
    playbookState.value = getPlaybookState(props.event.soc_id)
}

function handleHuntQuery(question: PlaybookQuestion) {
    const { query, range } = buildHuntQuery(question, props.event)
    emit('hunt-query', query, range)
}

function getQuestionIcon(question: PlaybookQuestion) {
    if (question.queryResults && question.queryResults.length > 0) {
        return CheckCircle2
    }
    return XCircle
}

function getQuestionIconClass(question: PlaybookQuestion) {
    if (question.queryResults && question.queryResults.length > 0) {
        return 'text-green-500'
    }
    return 'text-muted-foreground'
}

function formatFieldValue(value: any): string {
    if (value === null || value === undefined) return '-'
    if (typeof value === 'object') return JSON.stringify(value)
    return String(value)
}

// =============================================================================
// Lifecycle
// =============================================================================

onMounted(() => {
    if (props.visible) {
        load()
    }
})

watch(() => props.visible, (visible) => {
    if (visible && !playbookState.value) {
        load()
    }
})

watch(() => props.event?.soc_id, () => {
    playbookState.value = null
    if (props.visible) {
        load()
    }
})
</script>

<template>
    <div class="space-y-4">
        <!-- Header -->
        <div class="flex items-center justify-between">
            <div class="flex items-center gap-2">
                <HelpCircle class="h-5 w-5 text-primary" />
                <h3 class="font-semibold">Guided Analysis</h3>
                <span v-if="hasQuestions" class="text-sm text-muted-foreground">
                    ({{ questionsWithResults }}/{{ questions.length }} with results)
                </span>
            </div>
            <button
                v-if="hasQuestions"
                @click="handleToggleAll"
                class="flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
            >
                <ChevronsUpDown class="h-4 w-4" />
                {{ allExpanded ? 'Collapse All' : 'Expand All' }}
            </button>
        </div>

        <!-- Loading State -->
        <div v-if="playbookState?.loading" class="flex items-center justify-center py-8">
            <Loader2 class="h-6 w-6 animate-spin text-primary" />
            <span class="ml-2 text-muted-foreground">Loading playbook...</span>
        </div>

        <!-- Error State -->
        <div v-else-if="playbookState?.error" class="p-4 rounded-lg bg-destructive/10 border border-destructive/20">
            <div class="flex items-center gap-2 text-destructive">
                <AlertTriangle class="h-5 w-5" />
                <span>Failed to load playbook</span>
            </div>
        </div>

        <!-- No Questions -->
        <div v-else-if="!hasQuestions && playbookState" class="p-4 text-center text-muted-foreground">
            <HelpCircle class="h-8 w-8 mx-auto mb-2 opacity-20" />
            <p>No playbook questions available for this alert.</p>
        </div>

        <!-- Questions List -->
        <div v-else-if="hasQuestions" class="space-y-2">
            <div
                v-for="(question, index) in questions"
                :key="index"
                class="rounded-lg border border-border overflow-hidden"
            >
                <!-- Question Header -->
                <button
                    @click="handleToggleQuestion(index)"
                    class="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-muted/50 transition-colors"
                >
                    <component
                        :is="isQuestionExpanded(event.soc_id, index) ? ChevronDown : ChevronRight"
                        class="h-4 w-4 text-muted-foreground flex-shrink-0"
                    />
                    <component
                        :is="getQuestionIcon(question)"
                        :class="cn('h-4 w-4 flex-shrink-0', getQuestionIconClass(question))"
                    />
                    <span class="flex-1 text-sm">{{ question.question }}</span>
                    <span
                        v-if="question.queryResults"
                        :class="cn(
                            'text-xs px-2 py-0.5 rounded-full',
                            question.queryResults.length > 0
                                ? 'bg-green-500/10 text-green-500'
                                : 'bg-muted text-muted-foreground'
                        )"
                    >
                        {{ question.queryResults.length }} result{{ question.queryResults.length !== 1 ? 's' : '' }}
                    </span>
                </button>

                <!-- Question Content (Expanded) -->
                <div
                    v-if="isQuestionExpanded(event.soc_id, index)"
                    class="border-t border-border bg-muted/30"
                >
                    <!-- Context -->
                    <div v-if="question.context" class="px-4 py-2 text-sm text-muted-foreground border-b border-border">
                        {{ question.context }}
                    </div>

                    <!-- Results Table -->
                    <div v-if="question.queryResults && question.queryResults.length > 0" class="overflow-x-auto">
                        <table class="w-full text-sm">
                            <thead class="bg-muted/50">
                                <tr>
                                    <th
                                        v-for="field in question.fields"
                                        :key="field"
                                        class="px-3 py-2 text-left text-xs font-medium text-muted-foreground"
                                    >
                                        {{ field }}
                                    </th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr
                                    v-for="(result, rIdx) in question.queryResults.slice(0, 10)"
                                    :key="rIdx"
                                    class="border-t border-border"
                                >
                                    <td
                                        v-for="field in question.fields"
                                        :key="field"
                                        class="px-3 py-2 text-xs"
                                    >
                                        {{ formatFieldValue(result.payload?.[field] ?? result[field]) }}
                                    </td>
                                </tr>
                            </tbody>
                        </table>

                        <!-- More results indicator -->
                        <div
                            v-if="question.queryResults.length > 10"
                            class="px-4 py-2 text-xs text-muted-foreground border-t border-border"
                        >
                            Showing 10 of {{ question.queryResults.length }} results
                        </div>
                    </div>

                    <!-- No Results -->
                    <div v-else class="px-4 py-4 text-sm text-muted-foreground text-center">
                        No results found for this query.
                    </div>

                    <!-- Hunt Link -->
                    <div class="px-4 py-2 border-t border-border">
                        <button
                            @click="handleHuntQuery(question)"
                            class="flex items-center gap-1 text-xs text-primary hover:underline"
                        >
                            <ExternalLink class="h-3 w-3" />
                            Open in Hunt
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>
</template>
