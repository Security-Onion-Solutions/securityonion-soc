<script setup lang="ts">
import { ref, computed } from 'vue'
import {
    Wrench,
    Check,
    X,
    Loader2,
    AlertCircle,
    Clock,
    ChevronDown,
    ChevronUp,
    SkipForward,
    CircleHelp
} from 'lucide-vue-next'
import type { ToolUse, ToolStatus } from '@/composables/useAssistant'

const props = defineProps<{
    toolUse: ToolUse
}>()

const emit = defineEmits<{
    approve: []
    reject: []
}>()

const isExpanded = ref(false)
const showResult = ref(false)

const isPending = computed(() => props.toolUse.status === 'pending_approval')
const isExecuting = computed(() => props.toolUse.status === 'executing' || props.toolUse.status === 'preparing' || props.toolUse.status === 'queued')
const isCompleted = computed(() => props.toolUse.status === 'completed')
const isError = computed(() => props.toolUse.status === 'error')
const isRejected = computed(() => props.toolUse.status === 'rejected')
const isSkipped = computed(() => props.toolUse.status === 'skipped')

const statusConfig = computed(() => {
    const configs: Record<ToolStatus, { icon: any; label: string; classes: string }> = {
        preparing: { icon: Loader2, label: 'Preparing', classes: 'text-blue-500 bg-blue-500/10 border-blue-500/20' },
        queued: { icon: Clock, label: 'Queued', classes: 'text-blue-500 bg-blue-500/10 border-blue-500/20' },
        pending_approval: { icon: CircleHelp, label: 'Pending Approval', classes: 'text-amber-500 bg-amber-500/10 border-amber-500/20' },
        executing: { icon: Loader2, label: 'Executing', classes: 'text-blue-500 bg-blue-500/10 border-blue-500/20' },
        completed: { icon: Check, label: 'Completed', classes: 'text-green-500 bg-green-500/10 border-green-500/20' },
        error: { icon: AlertCircle, label: 'Error', classes: 'text-red-500 bg-red-500/10 border-red-500/20' },
        rejected: { icon: X, label: 'Rejected', classes: 'text-red-500 bg-red-500/10 border-red-500/20' },
        skipped: { icon: SkipForward, label: 'Skipped', classes: 'text-muted-foreground bg-muted border-border' },
    }
    return configs[props.toolUse.status] || configs.pending_approval
})

const formattedInput = computed(() => {
    try {
        return JSON.stringify(props.toolUse.input, null, 2)
    } catch {
        return String(props.toolUse.input)
    }
})

const formattedResult = computed(() => {
    if (!props.toolUse.rawResult) return null
    try {
        return JSON.stringify(props.toolUse.rawResult, null, 2)
    } catch {
        return String(props.toolUse.rawResult)
    }
})

const toolDisplayName = computed(() => {
    const nameMap: Record<string, string> = {
        query_events: 'Query Events',
        get_playbooks: 'Get Playbooks',
        query_cases: 'Query Cases',
        query_detections: 'Query Detections',
        ack_alerts: 'Acknowledge Alerts',
        escalate_alerts: 'Escalate Alerts',
        create_detection: 'Create Detection',
        update_detection_content: 'Update Detection',
        toggle_detections: 'Toggle Detections',
        add_overrides: 'Add Overrides',
        update_overrides: 'Update Overrides',
    }
    return nameMap[props.toolUse.name] || props.toolUse.name
})
</script>

<template>
    <div class="rounded-lg border bg-card overflow-hidden" :class="statusConfig.classes.split(' ').filter(c => c.startsWith('border-')).join(' ')">
        <!-- Header -->
        <div
            class="flex items-center justify-between px-3 py-2 cursor-pointer hover:bg-muted/50 transition-colors"
            @click="isExpanded = !isExpanded"
        >
            <div class="flex items-center gap-2">
                <Wrench class="h-4 w-4 text-muted-foreground" />
                <span class="text-sm font-medium">{{ toolDisplayName }}</span>
                <span
                    class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium border"
                    :class="statusConfig.classes"
                >
                    <component
                        :is="statusConfig.icon"
                        class="h-3 w-3"
                        :class="{ 'animate-spin': isExecuting }"
                    />
                    {{ statusConfig.label }}
                </span>
            </div>
            <div class="flex items-center gap-2">
                <!-- Approval buttons -->
                <template v-if="isPending">
                    <button
                        class="flex items-center gap-1 px-2 py-1 text-xs font-medium rounded bg-green-500/10 text-green-500 hover:bg-green-500/20 transition-colors"
                        @click.stop="emit('approve')"
                    >
                        <Check class="h-3 w-3" />
                        Approve
                    </button>
                    <button
                        class="flex items-center gap-1 px-2 py-1 text-xs font-medium rounded bg-red-500/10 text-red-500 hover:bg-red-500/20 transition-colors"
                        @click.stop="emit('reject')"
                    >
                        <X class="h-3 w-3" />
                        Reject
                    </button>
                </template>
                <ChevronUp v-if="isExpanded" class="h-4 w-4 text-muted-foreground" />
                <ChevronDown v-else class="h-4 w-4 text-muted-foreground" />
            </div>
        </div>

        <!-- Expanded Content -->
        <div v-if="isExpanded" class="border-t border-border">
            <!-- Input Parameters -->
            <div class="px-3 py-2">
                <div class="text-xs font-medium text-muted-foreground mb-1">Input Parameters</div>
                <pre class="text-xs bg-muted/50 rounded p-2 overflow-x-auto max-h-40"><code>{{ formattedInput }}</code></pre>
            </div>

            <!-- Error Message -->
            <div v-if="isError && toolUse.error" class="px-3 py-2 border-t border-border">
                <div class="text-xs font-medium text-red-500 mb-1">Error</div>
                <div class="text-xs text-red-500/80 bg-red-500/5 rounded p-2">
                    {{ toolUse.error }}
                </div>
            </div>

            <!-- Result (if completed) -->
            <div v-if="isCompleted && formattedResult" class="px-3 py-2 border-t border-border">
                <button
                    class="flex items-center gap-1 text-xs font-medium text-muted-foreground hover:text-foreground transition-colors"
                    @click="showResult = !showResult"
                >
                    <ChevronDown v-if="!showResult" class="h-3 w-3" />
                    <ChevronUp v-else class="h-3 w-3" />
                    {{ showResult ? 'Hide' : 'Show' }} Result
                </button>
                <pre v-if="showResult" class="text-xs bg-muted/50 rounded p-2 overflow-x-auto max-h-60 mt-2"><code>{{ formattedResult }}</code></pre>
            </div>
        </div>
    </div>
</template>
