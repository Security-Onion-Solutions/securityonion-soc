<script setup lang="ts">
import { ref, reactive, onMounted, onUnmounted, watch } from 'vue'
import { useRouter } from 'vue-router'
import {
    Bell,
    Search,
    RefreshCw,
    AlertTriangle,
    ShieldAlert,
    CheckCircle,
    Loader2,
    ChevronRight,
    ChevronDown,
    Network,
    Clock,
    Check,
    X,
    Sparkles,
    Briefcase,
    ExternalLink,
    Eye
} from 'lucide-vue-next'
import { cn } from '../lib/utils'
import { useAlerts } from '../composables/useAlerts'
import { useTimeRange } from '../composables/useTimeRange'
import { useStatusStyles } from '../composables/useStatusStyles'
import { useFormatters } from '../composables/useFormatters'
import { useHuntActions } from '../composables/useHuntActions'
import { useChatWidget } from '../composables/useChatWidget'
import type { AlertGroup, SourceDestPair } from '../types/alerts'
import type { EventRecord } from '../types/hunt'
import DateTimePicker from '../components/common/DateTimePicker.vue'

const router = useRouter()
const { getSeverityStyles } = useStatusStyles()
const { formatDate } = useFormatters()
const { rangeDescription } = useTimeRange()

const {
    alertGroups,
    filteredGroups,
    totalAlerts,
    groupsLoading,
    groupsLoadingMore,
    groupsError,
    hasMoreGroups,
    searchQuery,
    acknowledgedFilter,
    fetchAlertGroups,
    fetchPairs,
    fetchAlerts,
    pairs,
    alerts,
    pairsLoading,
    alertsLoading,
    selectedPair,
    selectPair
} = useAlerts()

const {
    acknowledgeEvent,
    escalateToNewCase,
    generateInvestigationPrompt
} = useHuntActions()

const { openNewChatWithPrompt } = useChatWidget()

// Local state for accordion
const expandedGroup = ref<string | null>(null)
const expandedPair = ref<string | null>(null)
const refreshing = ref(false)
const loadTrigger = ref<HTMLElement | null>(null)

// Track loading state per group
const groupLoadingState = reactive<Record<string, boolean>>({})

// Debounced search
let debounceTimer: ReturnType<typeof setTimeout> | null = null

watch(searchQuery, () => {
    if (debounceTimer) clearTimeout(debounceTimer)
    debounceTimer = setTimeout(() => {
        // Local filtering happens via computed, no need to refetch
    }, 300)
})

watch(acknowledgedFilter, () => {
    expandedGroup.value = null
    expandedPair.value = null
    fetchAlertGroups()
})

// Infinite scroll observer
let observer: IntersectionObserver | null = null

onMounted(() => {
    fetchAlertGroups()

    observer = new IntersectionObserver(
        (entries) => {
            if (entries[0].isIntersecting && hasMoreGroups.value && !groupsLoading.value && !groupsLoadingMore.value) {
                fetchAlertGroups(true)
            }
        },
        { threshold: 0.1 }
    )

    if (loadTrigger.value) {
        observer.observe(loadTrigger.value)
    }
})

onUnmounted(() => {
    if (observer) observer.disconnect()
    if (debounceTimer) clearTimeout(debounceTimer)
})

async function handleRefresh() {
    refreshing.value = true
    expandedGroup.value = null
    expandedPair.value = null
    await fetchAlertGroups()
    refreshing.value = false
}

async function toggleGroup(group: AlertGroup) {
    if (expandedGroup.value === group.ruleId) {
        // Collapse
        expandedGroup.value = null
        expandedPair.value = null
    } else {
        // Expand and fetch pairs
        expandedGroup.value = group.ruleId
        expandedPair.value = null
        groupLoadingState[group.ruleId] = true
        await fetchPairs(group.ruleName)
        groupLoadingState[group.ruleId] = false
    }
}

async function togglePair(group: AlertGroup, pair: SourceDestPair) {
    const pairKey = `${pair.sourceIp}-${pair.destinationIp}`
    if (expandedPair.value === pairKey) {
        // Collapse
        expandedPair.value = null
        selectPair(null)
    } else {
        // Expand and fetch alerts for this pair
        expandedPair.value = pairKey
        selectPair(pair)
        await fetchAlerts(group.ruleName, pair)
    }
}

function getPairKey(pair: SourceDestPair): string {
    return `${pair.sourceIp}-${pair.destinationIp}`
}

async function handleAcknowledge(alert: EventRecord, acknowledge: boolean) {
    const success = await acknowledgeEvent(alert, acknowledge, { timezone: 'Local' })
    if (success) {
        alert['event.acknowledged'] = acknowledge
    }
}

async function handleEscalate(alert: EventRecord) {
    const caseId = await escalateToNewCase(alert)
    if (caseId) {
        router.push({ name: 'case-detail', params: { id: caseId } })
    }
}

function handleInvestigate(alert: EventRecord) {
    const prompt = generateInvestigationPrompt(alert)
    openNewChatWithPrompt(prompt)
}

function drillIntoHunt(alert: EventRecord) {
    router.push({ name: 'hunt', query: { q: `soc_id:"${alert.soc_id}"` } })
}

function viewAlertDetail(alert: EventRecord) {
    router.push({ name: 'alert-detail', params: { id: alert.soc_id } })
}

function getField(alert: EventRecord, field: string): string {
    return alert[field] || '-'
}

// Stats
function getCriticalCount() {
    return alertGroups.value
        .filter(g => g.severity.toLowerCase() === 'critical' || g.severity.toLowerCase() === 'high')
        .reduce((sum, g) => sum + g.count, 0)
}
</script>

<template>
    <div class="space-y-6 animate-in fade-in duration-500">
        <!-- Header -->
        <div class="flex items-center justify-between">
            <div>
                <h2 class="text-3xl font-bold tracking-tight">Alert Triage</h2>
                <p class="text-muted-foreground">Review and triage security alerts grouped by detection rule.</p>
            </div>
            <div class="flex items-center gap-4">
                <!-- Acknowledged Filter -->
                <div class="flex items-center bg-muted rounded-lg p-1">
                    <button
                        v-for="filter in [
                            { value: 'unacknowledged', label: 'Unack' },
                            { value: 'acknowledged', label: 'Ack' },
                            { value: 'all', label: 'All' }
                        ]"
                        :key="filter.value"
                        @click="acknowledgedFilter = filter.value as any"
                        :class="cn(
                            'px-3 py-1.5 rounded-md text-xs font-medium transition-all',
                            acknowledgedFilter === filter.value
                                ? 'bg-background text-foreground shadow-sm'
                                : 'text-muted-foreground hover:text-foreground'
                        )"
                    >
                        {{ filter.label }}
                    </button>
                </div>

                <!-- Time Range -->
                <DateTimePicker @change="handleRefresh" />

                <!-- Search -->
                <div class="relative w-64">
                    <Search class="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                    <input
                        v-model="searchQuery"
                        type="search"
                        placeholder="Filter rules..."
                        class="w-full bg-background border border-border rounded-md pl-9 pr-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary/50"
                    />
                </div>

                <!-- Refresh -->
                <button
                    @click="handleRefresh"
                    :disabled="refreshing || groupsLoading"
                    class="inline-flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 transition-colors font-medium disabled:opacity-50"
                >
                    <RefreshCw :class="cn('h-4 w-4', (refreshing || groupsLoading) && 'animate-spin')" />
                    Refresh
                </button>
            </div>
        </div>

        <!-- Stats Cards -->
        <div class="grid gap-4 md:grid-cols-4">
            <div class="p-6 rounded-xl border border-border bg-card shadow-sm">
                <div class="flex items-center gap-2 text-sm font-medium text-muted-foreground mb-2">
                    <Bell class="h-4 w-4" />
                    Total Alerts
                </div>
                <div class="text-2xl font-bold">{{ totalAlerts.toLocaleString() }}</div>
            </div>
            <div class="p-6 rounded-xl border border-border bg-card shadow-sm">
                <div class="flex items-center gap-2 text-sm font-medium text-muted-foreground mb-2">
                    <ShieldAlert class="h-4 w-4 text-orange-500" />
                    Alert Groups
                </div>
                <div class="text-2xl font-bold">{{ alertGroups.length }}</div>
            </div>
            <div class="p-6 rounded-xl border border-border bg-card shadow-sm">
                <div class="flex items-center gap-2 text-sm font-medium text-muted-foreground mb-2">
                    <AlertTriangle class="h-4 w-4 text-red-500" />
                    Critical/High
                </div>
                <div class="text-2xl font-bold">{{ getCriticalCount().toLocaleString() }}</div>
            </div>
            <div class="p-6 rounded-xl border border-border bg-card shadow-sm">
                <div class="flex items-center gap-2 text-sm font-medium text-muted-foreground mb-2">
                    <CheckCircle class="h-4 w-4 text-green-500" />
                    Status
                </div>
                <div class="text-2xl font-bold capitalize">{{ acknowledgedFilter }}</div>
            </div>
        </div>

        <!-- Error State -->
        <div v-if="groupsError" class="rounded-xl border border-destructive/50 bg-destructive/10 p-6 text-center">
            <AlertTriangle class="h-8 w-8 text-destructive mx-auto mb-2" />
            <p class="text-destructive font-medium">{{ groupsError }}</p>
            <button @click="handleRefresh" class="mt-4 px-4 py-2 bg-destructive text-destructive-foreground rounded-md hover:bg-destructive/90">
                Retry
            </button>
        </div>

        <!-- Alert Groups Accordion -->
        <div v-else class="space-y-2">
            <!-- Loading State -->
            <div v-if="groupsLoading && !groupsLoadingMore" class="space-y-2">
                <div v-for="i in 5" :key="i" class="rounded-xl border border-border bg-card p-4 animate-pulse">
                    <div class="flex items-center justify-between">
                        <div class="h-5 w-96 bg-muted rounded"></div>
                        <div class="h-5 w-16 bg-muted rounded"></div>
                    </div>
                </div>
            </div>

            <!-- Empty State -->
            <div v-else-if="filteredGroups.length === 0" class="rounded-xl border border-border bg-card p-12 text-center">
                <Bell class="h-12 w-12 mx-auto mb-4 opacity-20" />
                <p class="text-lg font-medium">No alerts found</p>
                <p class="text-sm text-muted-foreground mt-1">
                    {{ searchQuery ? 'Try adjusting your search filter.' : 'No alerts match the current filters.' }}
                </p>
            </div>

            <!-- Alert Group Items -->
            <template v-else>
                <div
                    v-for="group in filteredGroups"
                    :key="group.ruleId"
                    class="rounded-xl border border-border bg-card overflow-hidden shadow-sm"
                >
                    <!-- Group Header (clickable) -->
                    <div
                        @click="toggleGroup(group)"
                        :class="cn(
                            'px-4 py-3 flex items-center justify-between cursor-pointer transition-colors',
                            expandedGroup === group.ruleId ? 'bg-muted/50' : 'hover:bg-muted/30'
                        )"
                    >
                        <div class="flex items-center gap-3 min-w-0 flex-1">
                            <component
                                :is="expandedGroup === group.ruleId ? ChevronDown : ChevronRight"
                                class="h-5 w-5 text-muted-foreground flex-shrink-0 transition-transform"
                            />
                            <div class="min-w-0 flex-1">
                                <div class="font-medium text-foreground line-clamp-1">
                                    {{ group.ruleName }}
                                </div>
                                <div class="flex items-center gap-3 mt-1">
                                    <span class="text-xs text-muted-foreground font-mono">{{ group.module }}</span>
                                    <span :class="cn('px-2 py-0.5 rounded-full border text-xs font-semibold', getSeverityStyles(group.severity))">
                                        {{ group.severity }}
                                    </span>
                                </div>
                            </div>
                        </div>
                        <div class="flex items-center gap-4 flex-shrink-0">
                            <span class="font-mono font-semibold text-lg">{{ group.count.toLocaleString() }}</span>
                            <Loader2 v-if="groupLoadingState[group.ruleId]" class="h-4 w-4 animate-spin text-muted-foreground" />
                        </div>
                    </div>

                    <!-- Expanded Content: Source/Dest Pairs -->
                    <div v-if="expandedGroup === group.ruleId" class="border-t border-border">
                        <!-- Loading pairs -->
                        <div v-if="pairsLoading && pairs.length === 0" class="p-4 text-center">
                            <Loader2 class="h-5 w-5 animate-spin mx-auto text-muted-foreground" />
                            <p class="text-sm text-muted-foreground mt-2">Loading source/destination pairs...</p>
                        </div>

                        <!-- No pairs -->
                        <div v-else-if="pairs.length === 0" class="p-6 text-center text-muted-foreground">
                            <Network class="h-8 w-8 mx-auto mb-2 opacity-30" />
                            <p>No source/destination pairs found</p>
                        </div>

                        <!-- Pairs list -->
                        <div v-else class="divide-y divide-border">
                            <div v-for="pair in pairs" :key="getPairKey(pair)">
                                <!-- Pair Row -->
                                <div
                                    @click="togglePair(group, pair)"
                                    :class="cn(
                                        'px-4 py-3 pl-12 flex items-center justify-between cursor-pointer transition-colors',
                                        expandedPair === getPairKey(pair) ? 'bg-primary/5' : 'hover:bg-muted/30'
                                    )"
                                >
                                    <div class="flex items-center gap-3">
                                        <component
                                            :is="expandedPair === getPairKey(pair) ? ChevronDown : ChevronRight"
                                            class="h-4 w-4 text-muted-foreground"
                                        />
                                        <Network class="h-4 w-4 text-muted-foreground" />
                                        <span class="font-mono text-sm">
                                            {{ pair.sourceIp }}
                                            <span class="text-muted-foreground mx-2">→</span>
                                            {{ pair.destinationIp }}
                                        </span>
                                    </div>
                                    <span class="font-mono font-medium">{{ pair.count.toLocaleString() }}</span>
                                </div>

                                <!-- Expanded Alerts for this pair -->
                                <div v-if="expandedPair === getPairKey(pair)" class="bg-muted/20 border-t border-border">
                                    <!-- Loading alerts -->
                                    <div v-if="alertsLoading && alerts.length === 0" class="p-4 text-center">
                                        <Loader2 class="h-4 w-4 animate-spin mx-auto text-muted-foreground" />
                                    </div>

                                    <!-- Alerts table -->
                                    <div v-else-if="alerts.length > 0" class="overflow-x-auto">
                                        <table class="w-full text-sm">
                                            <thead>
                                                <tr class="bg-muted/50 border-b border-border">
                                                    <th class="px-4 py-2 text-left font-medium text-muted-foreground text-xs">Timestamp</th>
                                                    <th class="px-4 py-2 text-left font-medium text-muted-foreground text-xs">Source</th>
                                                    <th class="px-4 py-2 text-left font-medium text-muted-foreground text-xs">Destination</th>
                                                    <th class="px-4 py-2 text-left font-medium text-muted-foreground text-xs">Status</th>
                                                    <th class="px-4 py-2 text-right font-medium text-muted-foreground text-xs">Actions</th>
                                                </tr>
                                            </thead>
                                            <tbody class="divide-y divide-border">
                                                <tr
                                                    v-for="alert in alerts"
                                                    :key="alert.soc_id"
                                                    class="hover:bg-muted/30 transition-colors group cursor-pointer"
                                                    @click="viewAlertDetail(alert)"
                                                >
                                                    <td class="px-4 py-2">
                                                        <div class="flex items-center gap-2 text-xs">
                                                            <Clock class="h-3 w-3 text-muted-foreground" />
                                                            {{ formatDate(alert.soc_timestamp || alert['@timestamp']) }}
                                                        </div>
                                                    </td>
                                                    <td class="px-4 py-2 font-mono text-xs">
                                                        {{ getField(alert, 'source.ip') }}
                                                        <span v-if="alert['source.port']" class="text-muted-foreground">:{{ alert['source.port'] }}</span>
                                                    </td>
                                                    <td class="px-4 py-2 font-mono text-xs">
                                                        {{ getField(alert, 'destination.ip') }}
                                                        <span v-if="alert['destination.port']" class="text-muted-foreground">:{{ alert['destination.port'] }}</span>
                                                    </td>
                                                    <td class="px-4 py-2">
                                                        <span v-if="alert['event.acknowledged']" class="inline-flex items-center gap-1 text-xs text-green-600">
                                                            <CheckCircle class="h-3 w-3" />
                                                            Ack
                                                        </span>
                                                        <span v-else class="inline-flex items-center gap-1 text-xs text-muted-foreground">
                                                            <X class="h-3 w-3" />
                                                            Unack
                                                        </span>
                                                    </td>
                                                    <td class="px-4 py-2">
                                                        <div class="flex items-center justify-end gap-1">
                                                            <button
                                                                v-if="!alert['event.acknowledged']"
                                                                @click.stop="handleAcknowledge(alert, true)"
                                                                class="p-1 hover:bg-green-500/20 text-green-600 rounded transition-colors"
                                                                title="Acknowledge"
                                                            >
                                                                <Check class="h-3.5 w-3.5" />
                                                            </button>
                                                            <button
                                                                v-else
                                                                @click.stop="handleAcknowledge(alert, false)"
                                                                class="p-1 hover:bg-red-500/20 text-red-600 rounded transition-colors"
                                                                title="Unacknowledge"
                                                            >
                                                                <X class="h-3.5 w-3.5" />
                                                            </button>
                                                            <button
                                                                @click.stop="handleEscalate(alert)"
                                                                class="p-1 hover:bg-primary/20 text-primary rounded transition-colors"
                                                                title="Escalate to Case"
                                                            >
                                                                <Briefcase class="h-3.5 w-3.5" />
                                                            </button>
                                                            <button
                                                                @click.stop="handleInvestigate(alert)"
                                                                class="p-1 hover:bg-purple-500/20 text-purple-600 rounded transition-colors"
                                                                title="AI Investigate"
                                                            >
                                                                <Sparkles class="h-3.5 w-3.5" />
                                                            </button>
                                                            <button
                                                                @click.stop="drillIntoHunt(alert)"
                                                                class="p-1 hover:bg-muted text-muted-foreground rounded transition-colors"
                                                                title="Open in Hunt"
                                                            >
                                                                <ExternalLink class="h-3.5 w-3.5" />
                                                            </button>
                                                        </div>
                                                    </td>
                                                </tr>
                                            </tbody>
                                        </table>
                                    </div>

                                    <!-- No alerts -->
                                    <div v-else class="p-4 text-center text-sm text-muted-foreground">
                                        No alerts found for this pair
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </template>

            <!-- Load More Trigger -->
            <div ref="loadTrigger" class="h-4"></div>

            <!-- Loading More -->
            <div v-if="groupsLoadingMore" class="flex items-center justify-center py-4">
                <Loader2 class="h-5 w-5 animate-spin text-muted-foreground" />
                <span class="ml-2 text-sm text-muted-foreground">Loading more...</span>
            </div>

            <!-- End of List -->
            <div v-else-if="!hasMoreGroups && filteredGroups.length > 0" class="py-4 text-center text-sm text-muted-foreground">
                End of results
            </div>
        </div>
    </div>
</template>
