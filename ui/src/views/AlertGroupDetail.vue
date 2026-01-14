<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import {
    ArrowLeft,
    RefreshCw,
    Eye,
    Check,
    X,
    AlertTriangle,
    Network,
    Clock,
    Loader2,
    ChevronRight,
    Sparkles,
    ExternalLink,
    Briefcase,
    CheckCircle,
    XCircle
} from 'lucide-vue-next'
import { cn } from '../lib/utils'
import { useAlerts } from '../composables/useAlerts'
import { useTimeRange } from '../composables/useTimeRange'
import { useFormatters } from '../composables/useFormatters'
import { useStatusStyles } from '../composables/useStatusStyles'
import { useHuntActions } from '../composables/useHuntActions'
import { useChatWidget } from '../composables/useChatWidget'
import type { EventRecord } from '../types/hunt'
import type { SourceDestPair } from '../types/alerts'

const route = useRoute()
const router = useRouter()

const props = defineProps<{ ruleId?: string }>()
const ruleId = computed(() => (route.params.ruleId as string) || props.ruleId || '')
const ruleName = computed(() => decodeURIComponent(ruleId.value))

const { formatDate, formatRelativeTime } = useFormatters()
const { getSeverityStyles } = useStatusStyles()
const { rangeDescription } = useTimeRange()

const {
    pairs,
    alerts,
    selectedPair,
    pairsLoading,
    pairsLoadingMore,
    pairsError,
    hasMorePairs,
    alertsLoading,
    alertsLoadingMore,
    alertsError,
    hasMoreAlerts,
    fetchPairs,
    fetchAlerts,
    selectPair
} = useAlerts()

const {
    acknowledgeEvent,
    escalateToNewCase,
    generateInvestigationPrompt,
    loading: actionLoading
} = useHuntActions()

const { openNewChatWithPrompt } = useChatWidget()

// Local state
const refreshing = ref(false)
const showDetailPanel = ref(false)
const selectedAlert = ref<EventRecord | null>(null)
const alertsLoadTrigger = ref<HTMLElement | null>(null)

// Infinite scroll for alerts
let alertsObserver: IntersectionObserver | null = null

onMounted(async () => {
    if (ruleName.value) {
        await fetchPairs(ruleName.value)
        await fetchAlerts(ruleName.value)
    }

    // Setup infinite scroll for alerts
    alertsObserver = new IntersectionObserver(
        (entries) => {
            if (entries[0].isIntersecting && hasMoreAlerts.value && !alertsLoading.value && !alertsLoadingMore.value) {
                fetchAlerts(ruleName.value, selectedPair.value, true)
            }
        },
        { threshold: 0.1 }
    )

    if (alertsLoadTrigger.value) {
        alertsObserver.observe(alertsLoadTrigger.value)
    }
})

onUnmounted(() => {
    if (alertsObserver) {
        alertsObserver.disconnect()
    }
})

// Watch for pair selection changes
watch(selectedPair, (newPair) => {
    if (ruleName.value) {
        fetchAlerts(ruleName.value, newPair)
    }
})

function goBack() {
    router.push({ name: 'alerts' })
}

async function handleRefresh() {
    refreshing.value = true
    await fetchPairs(ruleName.value)
    await fetchAlerts(ruleName.value, selectedPair.value)
    refreshing.value = false
}

function handlePairClick(pair: SourceDestPair) {
    if (selectedPair.value?.sourceIp === pair.sourceIp && selectedPair.value?.destinationIp === pair.destinationIp) {
        selectPair(null) // Deselect
    } else {
        selectPair(pair)
    }
}

function handleAlertClick(alert: EventRecord) {
    selectedAlert.value = alert
    showDetailPanel.value = true
}

function closeDetailPanel() {
    showDetailPanel.value = false
    selectedAlert.value = null
}

async function handleAcknowledge(alert: EventRecord, acknowledge: boolean) {
    const success = await acknowledgeEvent(alert, acknowledge, {
        timezone: 'Local'
    })
    if (success) {
        // Update local state
        alert['event.acknowledged'] = acknowledge
    }
}

async function handleEscalate(alert: EventRecord) {
    const caseId = await escalateToNewCase(alert)
    if (caseId) {
        // Optionally navigate to the case
        router.push({ name: 'case-detail', params: { id: caseId } })
    }
}

function handleInvestigate(alert: EventRecord) {
    const prompt = generateInvestigationPrompt(alert)
    openNewChatWithPrompt(prompt)
}

function drillIntoHunt(alert: EventRecord) {
    const query = `soc_id:"${alert.soc_id}"`
    router.push({ name: 'hunt', query: { q: query } })
}

// Helper to get field value from alert
function getField(alert: EventRecord, field: string): string {
    return alert[field] || '-'
}
</script>

<template>
    <div class="space-y-6 animate-in fade-in duration-500">
        <!-- Header -->
        <div class="flex items-start justify-between gap-4">
            <div class="flex items-start gap-4">
                <button
                    @click="goBack"
                    class="p-2 hover:bg-muted rounded-md transition-colors mt-1"
                >
                    <ArrowLeft class="h-5 w-5" />
                </button>
                <div>
                    <h2 class="text-2xl font-bold tracking-tight line-clamp-2">{{ ruleName }}</h2>
                    <p class="text-muted-foreground mt-1">
                        {{ rangeDescription }} &middot; {{ alerts.length }} alerts
                        <span v-if="selectedPair"> &middot; Filtered by {{ selectedPair.sourceIp }} → {{ selectedPair.destinationIp }}</span>
                    </p>
                </div>
            </div>
            <button
                @click="handleRefresh"
                :disabled="refreshing || pairsLoading || alertsLoading"
                class="inline-flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 transition-colors font-medium disabled:opacity-50"
            >
                <RefreshCw :class="cn('h-4 w-4', refreshing && 'animate-spin')" />
                Refresh
            </button>
        </div>

        <!-- Source/Destination Pairs Section -->
        <div class="rounded-xl border border-border bg-card shadow-sm">
            <div class="px-4 py-3 border-b border-border bg-muted/30">
                <div class="flex items-center gap-2">
                    <Network class="h-4 w-4 text-muted-foreground" />
                    <h3 class="font-semibold">Source / Destination Pairs</h3>
                    <span class="text-xs text-muted-foreground">({{ pairs.length }} pairs)</span>
                    <button
                        v-if="selectedPair"
                        @click="selectPair(null)"
                        class="ml-auto text-xs text-primary hover:underline"
                    >
                        Clear filter
                    </button>
                </div>
            </div>

            <div v-if="pairsLoading && pairs.length === 0" class="p-8 text-center">
                <Loader2 class="h-6 w-6 animate-spin mx-auto text-muted-foreground" />
                <p class="mt-2 text-sm text-muted-foreground">Loading pairs...</p>
            </div>

            <div v-else-if="pairsError" class="p-6 text-center text-destructive">
                <AlertTriangle class="h-6 w-6 mx-auto mb-2" />
                <p>{{ pairsError }}</p>
            </div>

            <div v-else-if="pairs.length === 0" class="p-8 text-center text-muted-foreground">
                <Network class="h-8 w-8 mx-auto mb-2 opacity-30" />
                <p>No source/destination pairs found</p>
            </div>

            <div v-else class="divide-y divide-border max-h-64 overflow-y-auto">
                <div
                    v-for="pair in pairs"
                    :key="`${pair.sourceIp}-${pair.destinationIp}`"
                    @click="handlePairClick(pair)"
                    :class="cn(
                        'px-4 py-3 flex items-center justify-between cursor-pointer transition-colors',
                        selectedPair?.sourceIp === pair.sourceIp && selectedPair?.destinationIp === pair.destinationIp
                            ? 'bg-primary/10 border-l-2 border-l-primary'
                            : 'hover:bg-muted/50'
                    )"
                >
                    <div class="flex items-center gap-4">
                        <div class="font-mono text-sm">
                            <span class="text-foreground">{{ pair.sourceIp }}</span>
                            <ChevronRight class="inline h-4 w-4 text-muted-foreground mx-1" />
                            <span class="text-foreground">{{ pair.destinationIp }}</span>
                        </div>
                    </div>
                    <div class="flex items-center gap-4">
                        <span class="font-mono font-semibold text-sm">{{ pair.count.toLocaleString() }}</span>
                        <ChevronRight class="h-4 w-4 text-muted-foreground" />
                    </div>
                </div>
            </div>

            <div v-if="pairsLoadingMore" class="p-3 text-center border-t border-border">
                <Loader2 class="h-4 w-4 animate-spin inline mr-2" />
                <span class="text-sm text-muted-foreground">Loading more...</span>
            </div>
        </div>

        <!-- Individual Alerts Section -->
        <div class="rounded-xl border border-border bg-card shadow-sm overflow-hidden">
            <div class="px-4 py-3 border-b border-border bg-muted/30">
                <div class="flex items-center gap-2">
                    <AlertTriangle class="h-4 w-4 text-muted-foreground" />
                    <h3 class="font-semibold">Individual Alerts</h3>
                    <span class="text-xs text-muted-foreground">({{ alerts.length }} shown)</span>
                </div>
            </div>

            <div class="overflow-x-auto">
                <table class="w-full text-sm">
                    <thead>
                        <tr class="bg-muted/50 border-b border-border">
                            <th class="px-4 py-3 text-left font-medium text-muted-foreground">Timestamp</th>
                            <th class="px-4 py-3 text-left font-medium text-muted-foreground">Source</th>
                            <th class="px-4 py-3 text-left font-medium text-muted-foreground">Destination</th>
                            <th class="px-4 py-3 text-left font-medium text-muted-foreground">Severity</th>
                            <th class="px-4 py-3 text-left font-medium text-muted-foreground">Status</th>
                            <th class="px-4 py-3 text-right font-medium text-muted-foreground">Actions</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-border">
                        <!-- Loading State -->
                        <tr v-if="alertsLoading && alerts.length === 0" v-for="i in 5" :key="i" class="animate-pulse">
                            <td class="px-4 py-4"><div class="h-4 w-32 bg-muted rounded"></div></td>
                            <td class="px-4 py-4"><div class="h-4 w-24 bg-muted rounded"></div></td>
                            <td class="px-4 py-4"><div class="h-4 w-24 bg-muted rounded"></div></td>
                            <td class="px-4 py-4"><div class="h-6 w-16 bg-muted rounded-full"></div></td>
                            <td class="px-4 py-4"><div class="h-6 w-16 bg-muted rounded-full"></div></td>
                            <td class="px-4 py-4"><div class="h-8 w-24 bg-muted rounded ml-auto"></div></td>
                        </tr>

                        <!-- Empty State -->
                        <tr v-else-if="alerts.length === 0 && !alertsLoading">
                            <td colspan="6" class="px-4 py-12 text-center text-muted-foreground">
                                <AlertTriangle class="h-8 w-8 mx-auto mb-2 opacity-30" />
                                <p>No alerts found</p>
                            </td>
                        </tr>

                        <!-- Data Rows -->
                        <tr
                            v-else
                            v-for="alert in alerts"
                            :key="alert.soc_id"
                            class="hover:bg-muted/30 transition-colors cursor-pointer group"
                            @click="handleAlertClick(alert)"
                        >
                            <td class="px-4 py-3">
                                <div class="flex items-center gap-2">
                                    <Clock class="h-4 w-4 text-muted-foreground" />
                                    <span class="text-sm">{{ formatDate(alert.soc_timestamp || alert['@timestamp']) }}</span>
                                </div>
                            </td>
                            <td class="px-4 py-3 font-mono text-sm">
                                {{ getField(alert, 'source.ip') }}
                                <span v-if="alert['source.port']" class="text-muted-foreground">:{{ alert['source.port'] }}</span>
                            </td>
                            <td class="px-4 py-3 font-mono text-sm">
                                {{ getField(alert, 'destination.ip') }}
                                <span v-if="alert['destination.port']" class="text-muted-foreground">:{{ alert['destination.port'] }}</span>
                            </td>
                            <td class="px-4 py-3">
                                <span :class="cn('px-2 py-0.5 rounded-full border text-xs font-semibold', getSeverityStyles(alert['event.severity_label'] || 'unknown'))">
                                    {{ alert['event.severity_label'] || 'unknown' }}
                                </span>
                            </td>
                            <td class="px-4 py-3">
                                <span v-if="alert['event.acknowledged']" class="inline-flex items-center gap-1 text-xs text-green-600">
                                    <CheckCircle class="h-3 w-3" />
                                    Ack
                                </span>
                                <span v-else class="inline-flex items-center gap-1 text-xs text-muted-foreground">
                                    <XCircle class="h-3 w-3" />
                                    Unack
                                </span>
                            </td>
                            <td class="px-4 py-3 text-right">
                                <div class="flex items-center justify-end gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                                    <button
                                        @click.stop="handleAlertClick(alert)"
                                        class="p-1.5 hover:bg-muted rounded transition-colors"
                                        title="View details"
                                    >
                                        <Eye class="h-4 w-4" />
                                    </button>
                                    <button
                                        v-if="!alert['event.acknowledged']"
                                        @click.stop="handleAcknowledge(alert, true)"
                                        class="p-1.5 hover:bg-green-500/20 text-green-600 rounded transition-colors"
                                        title="Acknowledge"
                                    >
                                        <Check class="h-4 w-4" />
                                    </button>
                                    <button
                                        v-else
                                        @click.stop="handleAcknowledge(alert, false)"
                                        class="p-1.5 hover:bg-red-500/20 text-red-600 rounded transition-colors"
                                        title="Unacknowledge"
                                    >
                                        <X class="h-4 w-4" />
                                    </button>
                                </div>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <!-- Load More Trigger -->
            <div ref="alertsLoadTrigger" class="h-4"></div>

            <!-- Loading More Indicator -->
            <div v-if="alertsLoadingMore" class="flex items-center justify-center py-4 border-t border-border">
                <Loader2 class="h-5 w-5 animate-spin text-muted-foreground" />
                <span class="ml-2 text-sm text-muted-foreground">Loading more...</span>
            </div>
        </div>

        <!-- Alert Detail Slide-out Panel -->
        <Teleport to="body">
            <Transition
                enter-active-class="transition-opacity duration-200"
                enter-from-class="opacity-0"
                enter-to-class="opacity-100"
                leave-active-class="transition-opacity duration-200"
                leave-from-class="opacity-100"
                leave-to-class="opacity-0"
            >
                <div
                    v-if="showDetailPanel"
                    class="fixed inset-0 bg-black/50 z-40"
                    @click="closeDetailPanel"
                />
            </Transition>

            <Transition
                enter-active-class="transition-transform duration-300 ease-out"
                enter-from-class="translate-x-full"
                enter-to-class="translate-x-0"
                leave-active-class="transition-transform duration-300 ease-in"
                leave-from-class="translate-x-0"
                leave-to-class="translate-x-full"
            >
                <div
                    v-if="showDetailPanel && selectedAlert"
                    class="fixed right-0 top-0 bottom-0 w-full max-w-2xl bg-background border-l border-border shadow-xl z-50 overflow-y-auto"
                >
                    <!-- Panel Header -->
                    <div class="sticky top-0 bg-background border-b border-border px-6 py-4 flex items-center justify-between">
                        <div>
                            <h3 class="font-semibold text-lg">Alert Details</h3>
                            <p class="text-sm text-muted-foreground font-mono">{{ selectedAlert.soc_id }}</p>
                        </div>
                        <button
                            @click="closeDetailPanel"
                            class="p-2 hover:bg-muted rounded-md transition-colors"
                        >
                            <X class="h-5 w-5" />
                        </button>
                    </div>

                    <!-- Panel Content -->
                    <div class="p-6 space-y-6">
                        <!-- Actions Bar -->
                        <div class="flex flex-wrap gap-2">
                            <button
                                v-if="!selectedAlert['event.acknowledged']"
                                @click="handleAcknowledge(selectedAlert, true)"
                                :disabled="actionLoading"
                                class="inline-flex items-center gap-2 px-3 py-2 bg-green-500/10 text-green-600 border border-green-500/30 rounded-md hover:bg-green-500/20 transition-colors text-sm font-medium"
                            >
                                <Check class="h-4 w-4" />
                                Acknowledge
                            </button>
                            <button
                                v-else
                                @click="handleAcknowledge(selectedAlert, false)"
                                :disabled="actionLoading"
                                class="inline-flex items-center gap-2 px-3 py-2 bg-red-500/10 text-red-600 border border-red-500/30 rounded-md hover:bg-red-500/20 transition-colors text-sm font-medium"
                            >
                                <X class="h-4 w-4" />
                                Unacknowledge
                            </button>
                            <button
                                @click="handleEscalate(selectedAlert)"
                                :disabled="actionLoading"
                                class="inline-flex items-center gap-2 px-3 py-2 bg-primary/10 text-primary border border-primary/30 rounded-md hover:bg-primary/20 transition-colors text-sm font-medium"
                            >
                                <Briefcase class="h-4 w-4" />
                                Escalate to Case
                            </button>
                            <button
                                @click="handleInvestigate(selectedAlert)"
                                :disabled="actionLoading"
                                class="inline-flex items-center gap-2 px-3 py-2 bg-purple-500/10 text-purple-600 border border-purple-500/30 rounded-md hover:bg-purple-500/20 transition-colors text-sm font-medium"
                            >
                                <Sparkles class="h-4 w-4" />
                                AI Investigate
                            </button>
                            <button
                                @click="drillIntoHunt(selectedAlert)"
                                class="inline-flex items-center gap-2 px-3 py-2 bg-muted text-foreground border border-border rounded-md hover:bg-muted/80 transition-colors text-sm font-medium"
                            >
                                <ExternalLink class="h-4 w-4" />
                                Open in Hunt
                            </button>
                        </div>

                        <!-- Key Details -->
                        <div class="rounded-lg border border-border bg-card">
                            <div class="px-4 py-3 border-b border-border bg-muted/30">
                                <h4 class="font-semibold">Key Details</h4>
                            </div>
                            <div class="p-4 grid grid-cols-2 gap-4">
                                <div>
                                    <label class="text-xs text-muted-foreground uppercase tracking-wider">Timestamp</label>
                                    <p class="font-medium">{{ formatDate(selectedAlert.soc_timestamp || selectedAlert['@timestamp']) }}</p>
                                </div>
                                <div>
                                    <label class="text-xs text-muted-foreground uppercase tracking-wider">Severity</label>
                                    <p>
                                        <span :class="cn('px-2 py-0.5 rounded-full border text-xs font-semibold', getSeverityStyles(selectedAlert['event.severity_label'] || 'unknown'))">
                                            {{ selectedAlert['event.severity_label'] || 'unknown' }}
                                        </span>
                                    </p>
                                </div>
                                <div>
                                    <label class="text-xs text-muted-foreground uppercase tracking-wider">Source</label>
                                    <p class="font-mono">
                                        {{ getField(selectedAlert, 'source.ip') }}
                                        <span v-if="selectedAlert['source.port']" class="text-muted-foreground">:{{ selectedAlert['source.port'] }}</span>
                                    </p>
                                </div>
                                <div>
                                    <label class="text-xs text-muted-foreground uppercase tracking-wider">Destination</label>
                                    <p class="font-mono">
                                        {{ getField(selectedAlert, 'destination.ip') }}
                                        <span v-if="selectedAlert['destination.port']" class="text-muted-foreground">:{{ selectedAlert['destination.port'] }}</span>
                                    </p>
                                </div>
                                <div>
                                    <label class="text-xs text-muted-foreground uppercase tracking-wider">Module</label>
                                    <p>{{ getField(selectedAlert, 'event.module') }}</p>
                                </div>
                                <div>
                                    <label class="text-xs text-muted-foreground uppercase tracking-wider">Observer</label>
                                    <p>{{ getField(selectedAlert, 'observer.name') }}</p>
                                </div>
                                <div class="col-span-2">
                                    <label class="text-xs text-muted-foreground uppercase tracking-wider">Rule</label>
                                    <p class="font-medium">{{ getField(selectedAlert, 'rule.name') }}</p>
                                </div>
                                <div class="col-span-2" v-if="selectedAlert['rule.description']">
                                    <label class="text-xs text-muted-foreground uppercase tracking-wider">Description</label>
                                    <p class="text-sm text-muted-foreground">{{ selectedAlert['rule.description'] }}</p>
                                </div>
                            </div>
                        </div>

                        <!-- Raw Event Data -->
                        <div class="rounded-lg border border-border bg-card">
                            <details class="group">
                                <summary class="px-4 py-3 cursor-pointer hover:bg-muted/30 transition-colors flex items-center justify-between">
                                    <h4 class="font-semibold">Raw Event Data</h4>
                                    <ChevronRight class="h-4 w-4 transition-transform group-open:rotate-90" />
                                </summary>
                                <div class="p-4 border-t border-border">
                                    <pre class="text-xs font-mono bg-muted/50 p-4 rounded-md overflow-x-auto max-h-96">{{ JSON.stringify(selectedAlert, null, 2) }}</pre>
                                </div>
                            </details>
                        </div>
                    </div>
                </div>
            </Transition>
        </Teleport>
    </div>
</template>
