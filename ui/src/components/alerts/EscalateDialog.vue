<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import {
    X,
    Briefcase,
    AlertTriangle,
    Loader2,
    BookOpen,
    HardDrive,
    Star,
    CheckSquare
} from 'lucide-vue-next'
import { cn } from '../../lib/utils'
import type { EventRecord } from '../../types/hunt'

// Guided analysis event - minimal info needed for attaching
interface GuidedAnalysisEvent {
    soc_id: string
    question?: string
}

// Marked event from guided analysis - includes notes and highlighting info
interface MarkedEvent {
    soc_id: string
    note: string
    sourceQuestion: string
    isHighlighted: boolean
}

// PCAP Job info - minimal info needed for attachment option
interface PcapJobInfo {
    id: number
    status: number // 0=Pending, 1=Completed, 2=Incomplete, 3=Deleted
    size?: number
}

// Escalation modes for guided analysis events
type EscalationMode = 'none' | 'all' | 'marked' | 'all-highlight-marked'

const props = defineProps<{
    open: boolean
    event: EventRecord | null
    guidedAnalysisEvents?: GuidedAnalysisEvent[]
    markedEvents?: MarkedEvent[]
    pcapJob?: PcapJobInfo | null
}>()

const emit = defineEmits<{
    (e: 'close'): void
    (e: 'confirm', data: {
        title: string
        description: string
        severity: string
        escalationMode: EscalationMode
        includePcap: boolean
    }): void
}>()

const loading = ref(false)

// Form state
const title = ref('')
const description = ref('')
const severity = ref('medium')
const escalationMode = ref<EscalationMode>('all')
const includePcap = ref(true)

// Computed: count of guided analysis events
const guidedAnalysisCount = computed(() => props.guidedAnalysisEvents?.length || 0)

// Computed: count of marked events
const markedCount = computed(() => props.markedEvents?.length || 0)

// Computed: check if any events have notes
const hasNotedEvents = computed(() => props.markedEvents?.some(e => e.note.trim()) || false)

// Computed: check if PCAP is available (completed job)
const JOB_STATUS_COMPLETED = 1
const pcapAvailable = computed(() => props.pcapJob?.status === JOB_STATUS_COMPLETED)

// Format bytes helper
function formatBytes(bytes: number | undefined): string {
    if (!bytes) return ''
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i]
}

const severityOptions = [
    { value: 'critical', label: 'Critical', color: 'bg-red-500' },
    { value: 'high', label: 'High', color: 'bg-orange-500' },
    { value: 'medium', label: 'Medium', color: 'bg-yellow-500' },
    { value: 'low', label: 'Low', color: 'bg-blue-500' }
]

// Initialize form when dialog opens
watch(() => props.open, (isOpen) => {
    if (isOpen && props.event) {
        // Generate default title from event
        const ruleName = props.event['rule.name'] || props.event['event.module'] || 'Unknown Alert'
        title.value = `Alert: ${ruleName}`

        // Generate default description
        const lines: string[] = []
        const ruleDesc = props.event['rule.description']
        if (ruleDesc) {
            lines.push(ruleDesc)
            lines.push('')
        }

        lines.push('**Alert Details:**')
        if (props.event['source.ip']) {
            lines.push(`- Source IP: ${props.event['source.ip']}`)
        }
        if (props.event['destination.ip']) {
            lines.push(`- Destination IP: ${props.event['destination.ip']}`)
        }
        if (props.event['rule.name']) {
            lines.push(`- Rule: ${props.event['rule.name']}`)
        }
        if (props.event.soc_timestamp) {
            lines.push(`- Time: ${props.event.soc_timestamp}`)
        }

        description.value = lines.join('\n')

        // Set severity from event if available
        const eventSeverity = props.event['event.severity_label']?.toLowerCase()
        if (eventSeverity && ['critical', 'high', 'medium', 'low'].includes(eventSeverity)) {
            severity.value = eventSeverity
        } else {
            severity.value = 'medium'
        }

        // Set default escalation mode based on marked events
        if (markedCount.value > 0) {
            // If there are marked events, default to including all and highlighting marked
            escalationMode.value = 'all-highlight-marked'
        } else if (guidedAnalysisCount.value > 0) {
            // If there are guided analysis events but none marked, include all
            escalationMode.value = 'all'
        } else {
            // No guided analysis events
            escalationMode.value = 'none'
        }

        // Default to include PCAP if available
        includePcap.value = pcapAvailable.value
    }
})

function handleClose() {
    if (!loading.value) {
        emit('close')
    }
}

async function handleConfirm() {
    loading.value = true
    const confirmData = {
        title: title.value,
        description: description.value,
        severity: severity.value,
        escalationMode: escalationMode.value,
        includePcap: includePcap.value && pcapAvailable.value
    }
    console.log('[EscalateDialog] Emitting confirm with data:', confirmData)
    console.log('[EscalateDialog] markedEvents:', props.markedEvents)
    emit('confirm', confirmData)
}

// Allow parent to reset loading state
defineExpose({
    setLoading: (val: boolean) => { loading.value = val }
})
</script>

<template>
    <Teleport to="body">
        <!-- Backdrop -->
        <Transition
            enter-active-class="transition-opacity duration-200"
            enter-from-class="opacity-0"
            enter-to-class="opacity-100"
            leave-active-class="transition-opacity duration-200"
            leave-from-class="opacity-100"
            leave-to-class="opacity-0"
        >
            <div
                v-if="open"
                class="fixed inset-0 bg-black/50 z-50"
                @click="handleClose"
            ></div>
        </Transition>

        <!-- Dialog -->
        <Transition
            enter-active-class="transition-all duration-200"
            enter-from-class="opacity-0 scale-95"
            enter-to-class="opacity-100 scale-100"
            leave-active-class="transition-all duration-200"
            leave-from-class="opacity-100 scale-100"
            leave-to-class="opacity-0 scale-95"
        >
            <div
                v-if="open"
                class="fixed inset-0 z-50 flex items-center justify-center p-4"
                @click.self="handleClose"
            >
                <div class="bg-card border border-border rounded-xl shadow-2xl w-full max-w-lg max-h-[90vh] overflow-hidden flex flex-col">
                    <!-- Header -->
                    <div class="flex items-center justify-between p-4 border-b border-border">
                        <div class="flex items-center gap-2">
                            <Briefcase class="h-5 w-5 text-primary" />
                            <h2 class="text-lg font-semibold">Escalate to Case</h2>
                        </div>
                        <button
                            @click="handleClose"
                            :disabled="loading"
                            class="p-1 hover:bg-muted rounded-md transition-colors text-muted-foreground hover:text-foreground disabled:opacity-50"
                        >
                            <X class="h-5 w-5" />
                        </button>
                    </div>

                    <!-- Content -->
                    <div class="p-4 space-y-4 overflow-y-auto flex-1">
                        <!-- Title -->
                        <div>
                            <label class="block text-sm font-medium mb-1.5">Case Title</label>
                            <input
                                v-model="title"
                                type="text"
                                :disabled="loading"
                                class="w-full px-3 py-2 bg-background border border-border rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-primary/50 disabled:opacity-50"
                                placeholder="Enter case title..."
                            />
                        </div>

                        <!-- Severity -->
                        <div>
                            <label class="block text-sm font-medium mb-1.5">Severity</label>
                            <div class="flex gap-2">
                                <button
                                    v-for="option in severityOptions"
                                    :key="option.value"
                                    @click="severity = option.value"
                                    :disabled="loading"
                                    :class="cn(
                                        'flex-1 px-3 py-2 rounded-md text-sm font-medium transition-all border-2',
                                        severity === option.value
                                            ? 'border-primary bg-primary/10 text-foreground'
                                            : 'border-transparent bg-muted text-muted-foreground hover:bg-muted/80',
                                        'disabled:opacity-50'
                                    )"
                                >
                                    <div class="flex items-center justify-center gap-2">
                                        <span :class="cn('w-2 h-2 rounded-full', option.color)"></span>
                                        {{ option.label }}
                                    </div>
                                </button>
                            </div>
                        </div>

                        <!-- Description -->
                        <div>
                            <label class="block text-sm font-medium mb-1.5">Description</label>
                            <textarea
                                v-model="description"
                                :disabled="loading"
                                rows="6"
                                class="w-full px-3 py-2 bg-background border border-border rounded-md text-sm font-mono focus:outline-none focus:ring-2 focus:ring-primary/50 resize-none disabled:opacity-50"
                                placeholder="Enter case description..."
                            ></textarea>
                            <p class="text-xs text-muted-foreground mt-1">Supports Markdown formatting</p>
                        </div>

                        <!-- Guided Analysis Events Escalation Mode -->
                        <div v-if="guidedAnalysisCount > 0" class="space-y-2">
                            <label class="block text-sm font-medium">
                                <div class="flex items-center gap-2">
                                    <BookOpen class="h-4 w-4 text-primary" />
                                    Guided Analysis Events
                                </div>
                            </label>
                            <p class="text-xs text-muted-foreground mb-2">
                                {{ guidedAnalysisCount }} {{ guidedAnalysisCount === 1 ? 'event' : 'events' }} found
                                <template v-if="markedCount > 0">
                                    <span class="text-amber-500 font-medium">
                                        ({{ markedCount }} marked<template v-if="hasNotedEvents">, with notes</template>)
                                    </span>
                                </template>
                            </p>

                            <div class="space-y-2 bg-muted/30 rounded-lg p-3 border border-border">
                                <!-- Option: Include All -->
                                <label class="flex items-start gap-3 cursor-pointer p-2 rounded-md hover:bg-muted/50 transition-colors">
                                    <input
                                        type="radio"
                                        v-model="escalationMode"
                                        value="all"
                                        :disabled="loading"
                                        class="mt-0.5 h-4 w-4 text-primary focus:ring-primary/50"
                                    />
                                    <div class="flex-1">
                                        <div class="text-sm font-medium">Include All Events</div>
                                        <p class="text-xs text-muted-foreground">
                                            Attach all {{ guidedAnalysisCount }} events from guided analysis
                                        </p>
                                    </div>
                                </label>

                                <!-- Option: Include Only Marked -->
                                <label
                                    :class="cn(
                                        'flex items-start gap-3 cursor-pointer p-2 rounded-md transition-colors',
                                        markedCount === 0 ? 'opacity-50 cursor-not-allowed' : 'hover:bg-muted/50'
                                    )"
                                >
                                    <input
                                        type="radio"
                                        v-model="escalationMode"
                                        value="marked"
                                        :disabled="loading || markedCount === 0"
                                        class="mt-0.5 h-4 w-4 text-primary focus:ring-primary/50"
                                    />
                                    <div class="flex-1">
                                        <div class="text-sm font-medium flex items-center gap-2">
                                            <CheckSquare class="h-3.5 w-3.5 text-amber-500" />
                                            Include Only Marked Events
                                        </div>
                                        <p class="text-xs text-muted-foreground">
                                            <template v-if="markedCount > 0">
                                                Attach {{ markedCount }} marked {{ markedCount === 1 ? 'event' : 'events' }} (highlighted in case)
                                            </template>
                                            <template v-else>
                                                No events marked - use checkboxes in guided analysis results
                                            </template>
                                        </p>
                                    </div>
                                </label>

                                <!-- Option: Include All, Highlight Marked -->
                                <label
                                    :class="cn(
                                        'flex items-start gap-3 cursor-pointer p-2 rounded-md transition-colors',
                                        markedCount === 0 ? 'opacity-50 cursor-not-allowed' : 'hover:bg-muted/50'
                                    )"
                                >
                                    <input
                                        type="radio"
                                        v-model="escalationMode"
                                        value="all-highlight-marked"
                                        :disabled="loading || markedCount === 0"
                                        class="mt-0.5 h-4 w-4 text-primary focus:ring-primary/50"
                                    />
                                    <div class="flex-1">
                                        <div class="text-sm font-medium flex items-center gap-2">
                                            <Star class="h-3.5 w-3.5 text-amber-500" />
                                            Include All, Highlight Marked
                                        </div>
                                        <p class="text-xs text-muted-foreground">
                                            <template v-if="markedCount > 0">
                                                Attach all events, highlight {{ markedCount }} marked with notes visible in case
                                            </template>
                                            <template v-else>
                                                No events marked - use checkboxes in guided analysis results
                                            </template>
                                        </p>
                                    </div>
                                </label>

                                <!-- Option: Don't Include Events -->
                                <label class="flex items-start gap-3 cursor-pointer p-2 rounded-md hover:bg-muted/50 transition-colors">
                                    <input
                                        type="radio"
                                        v-model="escalationMode"
                                        value="none"
                                        :disabled="loading"
                                        class="mt-0.5 h-4 w-4 text-primary focus:ring-primary/50"
                                    />
                                    <div class="flex-1">
                                        <div class="text-sm font-medium">Don't Include Events</div>
                                        <p class="text-xs text-muted-foreground">
                                            Only attach the primary alert to the case
                                        </p>
                                    </div>
                                </label>
                            </div>
                        </div>

                        <!-- Include PCAP -->
                        <div v-if="pcapAvailable" class="flex items-start gap-3 p-3 bg-muted/50 rounded-lg border border-border">
                            <input
                                type="checkbox"
                                id="includePcap"
                                v-model="includePcap"
                                :disabled="loading"
                                class="mt-0.5 h-4 w-4 rounded border-border text-primary focus:ring-primary/50 disabled:opacity-50"
                            />
                            <label for="includePcap" class="flex-1 cursor-pointer">
                                <div class="flex items-center gap-2 text-sm font-medium">
                                    <HardDrive class="h-4 w-4 text-primary" />
                                    Include PCAP
                                </div>
                                <p class="text-xs text-muted-foreground mt-0.5">
                                    Attach the packet capture{{ pcapJob?.size ? ` (${formatBytes(pcapJob.size)})` : '' }} as a case attachment
                                </p>
                            </label>
                        </div>
                    </div>

                    <!-- Footer -->
                    <div class="flex items-center justify-end gap-2 p-4 border-t border-border bg-muted/30">
                        <button
                            @click="handleClose"
                            :disabled="loading"
                            class="px-4 py-2 text-sm font-medium rounded-md hover:bg-muted transition-colors disabled:opacity-50"
                        >
                            Cancel
                        </button>
                        <button
                            @click="handleConfirm"
                            :disabled="loading || !title.trim()"
                            class="px-4 py-2 text-sm font-medium bg-primary text-primary-foreground rounded-md hover:bg-primary/90 transition-colors disabled:opacity-50 flex items-center gap-2"
                        >
                            <Loader2 v-if="loading" class="h-4 w-4 animate-spin" />
                            <Briefcase v-else class="h-4 w-4" />
                            Create Case
                        </button>
                    </div>
                </div>
            </div>
        </Transition>
    </Teleport>
</template>
