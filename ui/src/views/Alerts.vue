<script setup lang="ts">
defineOptions({ name: 'Alerts' })

import { ref, reactive, computed, onMounted, onUnmounted, watch } from 'vue'
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
    CheckCheck,
    X,
    Sparkles,
    Briefcase,
    ExternalLink,
    Eye,
    ArrowUpDown,
    ArrowUp,
    ArrowDown,
    Settings,
    Layers,
    Table,
    Group,
    Shield,
    Bot,
    Power
} from 'lucide-vue-next'
import { cn } from '../lib/utils'
import { useAlerts } from '../composables/useAlerts'
import { useApi } from '../composables/useApi'
import { useTimeRange } from '../composables/useTimeRange'
import { useStatusStyles } from '../composables/useStatusStyles'
import { useFormatters } from '../composables/useFormatters'
import { useHuntActions } from '../composables/useHuntActions'
import { useChatWidget } from '../composables/useChatWidget'
import type { AlertGroup, SourceDestPair } from '../types/alerts'
import type { EventRecord } from '../types/hunt'
import DateTimePicker from '../components/common/DateTimePicker.vue'
import EscalateDialog from '../components/alerts/EscalateDialog.vue'

const router = useRouter()
const { put } = useApi()
const { getSeverityStyles } = useStatusStyles()
const { formatDate } = useFormatters()
const { rangeDescription, zone } = useTimeRange()

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
    sortField,
    sortDirection,
    triageGroupBy,
    setTriageGroupBy,
    fetchAlertGroups,
    fetchPairs,
    fetchSubgroups,
    fetchAlerts,
    fetchAlertsForSubgroup,
    fetchAllAlerts,
    pairs,
    subgroups,
    subgroupsLoading,
    alerts,
    pairsLoading,
    alertsLoading,
    selectedPair,
    selectPair,
    setSort,
    allAlerts,
    sortedAllAlerts,
    allAlertsLoading,
    allAlertsLoadingMore,
    hasMoreAllAlerts,
    tableSortField,
    tableSortDirection,
    tableGroupBy,
    tableGroups,
    setTableSort,
    setTableGroupBy,
    toggleTableGroup,
    computeTableGroups,
    buildGroupQuery,
    buildSubgroupQuery,
    getGroupLabel,
    getSubgroupLabel,
    fetchDetectionForRule,
    getDetectionInfo,
    isDetectionInfoLoading
} = useAlerts()

const {
    acknowledgeEvent,
    escalateToNewCase,
    bulkAcknowledgeByQuery,
    bulkEscalateByQuery,
    generateInvestigationPrompt
} = useHuntActions()

const { openNewChatWithPrompt } = useChatWidget()

// Local state for accordion
const expandedGroup = ref<string | null>(null)
const expandedPair = ref<string | null>(null)
const refreshing = ref(false)
const loadTrigger = ref<HTMLElement | null>(null)

// Detection toggle state
interface Detection {
    id: string
    publicId: string
    title: string
    isEnabled: boolean
    [key: string]: any
}
const detectionToggleLoading = ref<string | null>(null) // Rule name being toggled
const showDisableDetectionConfirm = ref(false)
const disableDetectionAckAll = ref(true)
const pendingDisableRuleName = ref<string | null>(null)
const detectionCache = ref<Map<string, Detection>>(new Map())

// Fetch full detection data for toggle
async function fetchFullDetection(ruleName: string): Promise<Detection | null> {
    // Check cache first
    if (detectionCache.value.has(ruleName)) {
        return detectionCache.value.get(ruleName) || null
    }

    const detectionInfo = getDetectionInfo(ruleName)
    if (!detectionInfo?.publicId) {
        return null
    }

    try {
        const response = await fetch(`/api/detection/public/${encodeURIComponent(detectionInfo.publicId)}`)
        if (response.ok) {
            const detection = await response.json()
            detectionCache.value.set(ruleName, detection)
            return detection
        }
    } catch (e) {
        console.error('Failed to fetch detection:', e)
    }
    return null
}

// Toggle detection enabled/disabled
function toggleDetectionEnabled(ruleName: string) {
    if (detectionToggleLoading.value) return

    const detection = detectionCache.value.get(ruleName)
    if (!detection) return

    // If enabling, do it directly
    if (!detection.isEnabled) {
        performToggleDetection(ruleName)
        return
    }

    // If disabling, show confirmation dialog
    pendingDisableRuleName.value = ruleName
    disableDetectionAckAll.value = true
    showDisableDetectionConfirm.value = true
}

// Actually perform the detection toggle
async function performToggleDetection(ruleName: string) {
    const detection = detectionCache.value.get(ruleName)
    if (!detection || detectionToggleLoading.value) return

    detectionToggleLoading.value = ruleName
    try {
        const updatedDetection = await put<Detection>(`/api/detection/`, {
            ...detection,
            isEnabled: !detection.isEnabled
        })

        if (updatedDetection) {
            detectionCache.value.set(ruleName, updatedDetection)
        }
    } catch (e: any) {
        console.error('Failed to update detection:', e)
    } finally {
        detectionToggleLoading.value = null
    }
}

// Confirm disable detection and optionally acknowledge all alerts
async function confirmDisableDetection() {
    const ruleName = pendingDisableRuleName.value
    if (!ruleName) return

    showDisableDetectionConfirm.value = false

    const detection = detectionCache.value.get(ruleName)
    if (!detection) return

    // Disable the detection
    await performToggleDetection(ruleName)

    // If user chose to acknowledge all alerts
    if (disableDetectionAckAll.value) {
        try {
            const ruleTitle = detection.title || detection.publicId
            const searchFilter = `tags:alert AND rule.name:"${ruleTitle.replace(/"/g, '\\"')}" AND NOT event.acknowledged:true`
            await bulkAcknowledgeByQuery(searchFilter, true, { timezone: zone.value })
            // Refresh the groups after acknowledging
            await fetchAlertGroups()
        } catch (e: any) {
            console.error('Failed to acknowledge alerts:', e)
        }
    }

    pendingDisableRuleName.value = null
}

// Cancel disable detection
function cancelDisableDetection() {
    showDisableDetectionConfirm.value = false
    disableDetectionAckAll.value = true
    pendingDisableRuleName.value = null
}

// View mode state
type ViewMode = 'triage' | 'table'
const PREFERENCES_KEY = 'alertsViewPreferences'
const viewMode = ref<ViewMode>('triage')
const showSettingsPanel = ref(false)

function loadViewPreferences() {
    try {
        const stored = localStorage.getItem(PREFERENCES_KEY)
        if (stored) {
            const parsed = JSON.parse(stored)
            if (parsed.viewMode) viewMode.value = parsed.viewMode
        }
    } catch (e) {
        console.debug('Could not load alerts view preferences:', e)
    }
}

function saveViewPreferences() {
    try {
        localStorage.setItem(PREFERENCES_KEY, JSON.stringify({ viewMode: viewMode.value }))
    } catch (e) {
        console.debug('Could not save alerts view preferences:', e)
    }
}

function setViewMode(mode: ViewMode) {
    viewMode.value = mode
    saveViewPreferences()
    // Always ensure we have the right data for the selected view
    if (mode === 'table') {
        if (allAlerts.value.length === 0) {
            fetchAllAlerts()
        }
    } else {
        if (alertGroups.value.length === 0) {
            fetchAlertGroups()
        }
    }
}

// Escalate dialog state
const showEscalateDialog = ref(false)
const escalateDialogRef = ref<InstanceType<typeof EscalateDialog> | null>(null)
const escalateTarget = ref<EventRecord | null>(null)

// Track last clicked alert for highlighting when returning from detail view
const lastClickedAlertId = ref<string | null>(null)

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
    if (viewMode.value === 'table') {
        fetchAllAlerts()
    } else {
        fetchAlertGroups()
    }
})

// Infinite scroll observer
let observer: IntersectionObserver | null = null

onMounted(() => {
    loadViewPreferences()
    if (viewMode.value === 'table') {
        fetchAllAlerts()
    } else {
        fetchAlertGroups()
    }

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
    if (viewMode.value === 'table') {
        await fetchAllAlerts()
    } else {
        await fetchAlertGroups()
    }
    refreshing.value = false
}

async function toggleGroup(group: AlertGroup) {
    if (expandedGroup.value === group.ruleId) {
        // Collapse
        expandedGroup.value = null
        expandedPair.value = null
    } else {
        // Expand and fetch subgroups (pairs or rules depending on triageGroupBy)
        expandedGroup.value = group.ruleId
        expandedPair.value = null
        groupLoadingState[group.ruleId] = true
        // Use the decoded ruleId as the group key (it contains the actual value like IP or rule name)
        const groupKey = decodeURIComponent(group.ruleId)

        // Fetch detection info (AI summary) and full detection data in parallel when grouped by rule
        if (triageGroupBy.value === 'rule') {
            fetchDetectionForRule(groupKey).then(() => {
                // After detection info is fetched, fetch full detection for toggle
                fetchFullDetection(groupKey)
            })
        }

        await fetchSubgroups(groupKey)
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

// Toggle subgroup expansion (works for both pair and rule subgroups)
async function toggleSubgroup(group: AlertGroup, subgroup: { key: string; label: string; secondaryLabel?: string; count: number; type: 'pair' | 'rule' }) {
    if (expandedPair.value === subgroup.key) {
        // Collapse
        expandedPair.value = null
    } else {
        // Expand and fetch alerts for this subgroup
        expandedPair.value = subgroup.key
        const parentGroupKey = decodeURIComponent(group.ruleId)
        await fetchAlertsForSubgroup(parentGroupKey, subgroup)
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

function handleEscalate(alert: EventRecord) {
    escalateTarget.value = alert
    showEscalateDialog.value = true
}

async function handleEscalateConfirm(data: { title: string; description: string; severity: string }) {
    if (!escalateTarget.value) return

    try {
        const caseId = await escalateToNewCase(escalateTarget.value, {
            title: data.title,
            description: data.description,
            severity: data.severity
        })

        if (caseId) {
            escalateTarget.value['event.escalated'] = true
            showEscalateDialog.value = false
            router.push({ name: 'case-detail', params: { id: caseId } })
        }
    } catch (e: any) {
        console.error('Escalation failed:', e)
    } finally {
        escalateDialogRef.value?.setLoading(false)
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
    lastClickedAlertId.value = alert.soc_id
    router.push({ name: 'alert-detail', params: { id: alert.soc_id } })
}

function getField(alert: EventRecord, field: string): string {
    return alert[field] || '-'
}

// Bulk action state
const bulkActionLoading = reactive<Record<string, boolean>>({})

// Bulk acknowledge all alerts in a group
async function handleBulkAcknowledgeGroup(group: AlertGroup) {
    const groupKey = decodeURIComponent(group.ruleId)
    const loadingKey = `ack-group-${group.ruleId}`
    bulkActionLoading[loadingKey] = true

    try {
        const query = buildGroupQuery(groupKey)
        const success = await bulkAcknowledgeByQuery(query, true, { timezone: 'Local' })
        if (success) {
            // Refresh the groups to update counts
            await fetchAlertGroups()
        }
    } catch (e) {
        console.error('Bulk acknowledge failed:', e)
    } finally {
        bulkActionLoading[loadingKey] = false
    }
}

// Bulk escalate all alerts in a group to a new case
async function handleBulkEscalateGroup(group: AlertGroup) {
    const groupKey = decodeURIComponent(group.ruleId)
    const loadingKey = `esc-group-${group.ruleId}`
    bulkActionLoading[loadingKey] = true

    try {
        const query = buildGroupQuery(groupKey)
        const label = getGroupLabel(groupKey)
        const caseId = await bulkEscalateByQuery(query, {
            title: `Escalated: ${label}`,
            description: `Bulk escalation of ${group.count} alerts for ${label}`,
            severity: group.severity,
            timezone: 'Local'
        })

        if (caseId) {
            // Refresh and navigate to case
            await fetchAlertGroups()
            router.push({ name: 'case-detail', params: { id: caseId } })
        }
    } catch (e) {
        console.error('Bulk escalate failed:', e)
    } finally {
        bulkActionLoading[loadingKey] = false
    }
}

// Bulk acknowledge all alerts in a subgroup
async function handleBulkAcknowledgeSubgroup(group: AlertGroup, subgroup: { key: string; label: string; secondaryLabel?: string; count: number; type: 'pair' | 'rule' }) {
    const parentGroupKey = decodeURIComponent(group.ruleId)
    const loadingKey = `ack-subgroup-${subgroup.key}`
    bulkActionLoading[loadingKey] = true

    try {
        const query = buildSubgroupQuery(parentGroupKey, subgroup as any)
        const success = await bulkAcknowledgeByQuery(query, true, { timezone: 'Local' })
        if (success) {
            // Refresh subgroups to update counts
            await fetchSubgroups(parentGroupKey)
        }
    } catch (e) {
        console.error('Bulk acknowledge subgroup failed:', e)
    } finally {
        bulkActionLoading[loadingKey] = false
    }
}

// Bulk escalate all alerts in a subgroup to a new case
async function handleBulkEscalateSubgroup(group: AlertGroup, subgroup: { key: string; label: string; secondaryLabel?: string; count: number; type: 'pair' | 'rule' }) {
    const parentGroupKey = decodeURIComponent(group.ruleId)
    const loadingKey = `esc-subgroup-${subgroup.key}`
    bulkActionLoading[loadingKey] = true

    try {
        const query = buildSubgroupQuery(parentGroupKey, subgroup as any)
        const label = getSubgroupLabel(parentGroupKey, subgroup as any)
        const caseId = await bulkEscalateByQuery(query, {
            title: `Escalated: ${label}`,
            description: `Bulk escalation of ${subgroup.count} alerts for ${label}`,
            severity: group.severity,
            timezone: 'Local'
        })

        if (caseId) {
            // Refresh and navigate to case
            await fetchSubgroups(parentGroupKey)
            router.push({ name: 'case-detail', params: { id: caseId } })
        }
    } catch (e) {
        console.error('Bulk escalate subgroup failed:', e)
    } finally {
        bulkActionLoading[loadingKey] = false
    }
}

// Stats
function getCriticalCount() {
    return alertGroups.value
        .filter(g => g.severity.toLowerCase() === 'critical' || g.severity.toLowerCase() === 'high')
        .reduce((sum, g) => sum + g.count, 0)
}

// Computed: Aggregate unique source IPs from current subgroups (pairs)
const aggregatedSourceIps = computed(() => {
    if (triageGroupBy.value !== 'rule') return []
    const ipMap = new Map<string, number>()
    for (const subgroup of subgroups.value) {
        if (subgroup.type === 'pair' && subgroup.label && subgroup.label !== '-') {
            ipMap.set(subgroup.label, (ipMap.get(subgroup.label) || 0) + subgroup.count)
        }
    }
    return Array.from(ipMap.entries())
        .map(([ip, count]) => ({ ip, count }))
        .sort((a, b) => b.count - a.count)
})

// Computed: Aggregate unique destination IPs from current subgroups (pairs)
const aggregatedDestIps = computed(() => {
    if (triageGroupBy.value !== 'rule') return []
    const ipMap = new Map<string, number>()
    for (const subgroup of subgroups.value) {
        if (subgroup.type === 'pair' && subgroup.secondaryLabel && subgroup.secondaryLabel !== '-') {
            ipMap.set(subgroup.secondaryLabel, (ipMap.get(subgroup.secondaryLabel) || 0) + subgroup.count)
        }
    }
    return Array.from(ipMap.entries())
        .map(([ip, count]) => ({ ip, count }))
        .sort((a, b) => b.count - a.count)
})

// Computed: Total alert count from subgroups
const aggregatedTotalCount = computed(() => {
    return subgroups.value.reduce((sum, s) => sum + s.count, 0)
})
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

                <!-- Settings -->
                <div class="relative">
                    <button
                        @click="showSettingsPanel = !showSettingsPanel"
                        :class="cn(
                            'p-2 rounded-md transition-colors',
                            showSettingsPanel ? 'bg-muted text-foreground' : 'text-muted-foreground hover:text-foreground hover:bg-muted'
                        )"
                    >
                        <Settings class="h-5 w-5" />
                    </button>
                    <div
                        v-if="showSettingsPanel"
                        class="absolute right-0 top-full mt-2 w-56 bg-popover border border-border rounded-lg shadow-lg z-50"
                    >
                        <div class="p-3 border-b border-border">
                            <h3 class="font-semibold text-sm">Display Settings</h3>
                            <p class="text-xs text-muted-foreground mt-0.5">Choose how alerts are displayed</p>
                        </div>
                        <div class="p-2">
                            <button
                                @click="setViewMode('triage')"
                                :class="cn(
                                    'w-full flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors',
                                    viewMode === 'triage' ? 'bg-primary/10 text-primary' : 'hover:bg-muted'
                                )"
                            >
                                <Layers class="h-4 w-4" />
                                <div class="text-left">
                                    <div class="font-medium">Triage View</div>
                                    <div class="text-xs text-muted-foreground">Grouped by rule with expandable pairs</div>
                                </div>
                            </button>
                            <button
                                @click="setViewMode('table')"
                                :class="cn(
                                    'w-full flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors mt-1',
                                    viewMode === 'table' ? 'bg-primary/10 text-primary' : 'hover:bg-muted'
                                )"
                            >
                                <Table class="h-4 w-4" />
                                <div class="text-left">
                                    <div class="font-medium">Table View</div>
                                    <div class="text-xs text-muted-foreground">Flat list like Hunt</div>
                                </div>
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <!-- Settings Panel Backdrop -->
        <div v-if="showSettingsPanel" class="fixed inset-0 z-40" @click="showSettingsPanel = false"></div>

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

        <!-- ==================== TRIAGE VIEW ==================== -->
        <template v-if="viewMode === 'triage'">
            <!-- Triage Toolbar -->
            <div class="flex items-center justify-between mb-4">
                <div class="flex items-center gap-4">
                    <!-- Group By Dropdown -->
                    <div class="flex items-center gap-2">
                        <Group class="h-4 w-4 text-muted-foreground" />
                        <span class="text-sm text-muted-foreground">Group by:</span>
                        <select
                            :value="triageGroupBy"
                            @change="setTriageGroupBy(($event.target as HTMLSelectElement).value as any)"
                            class="bg-background border border-border rounded-md px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-primary/50"
                        >
                            <option value="rule">Rule</option>
                            <option value="severity">Severity</option>
                            <option value="source">Source IP</option>
                            <option value="destination">Destination IP</option>
                        </select>
                    </div>

                    <!-- Sort Controls -->
                    <div class="flex items-center gap-1">
                        <span class="text-sm text-muted-foreground mr-1">Sort:</span>
                        <div class="flex items-center bg-muted rounded-lg p-1">
                            <button
                                v-for="sort in [
                                    { value: 'count', label: 'Count' },
                                    { value: 'name', label: 'Name' },
                                    { value: 'severity', label: 'Severity' }
                                ]"
                                :key="sort.value"
                                @click="setSort(sort.value as any)"
                                :class="cn(
                                    'px-3 py-1 rounded-md text-xs font-medium transition-all flex items-center gap-1',
                                    sortField === sort.value
                                        ? 'bg-background text-foreground shadow-sm'
                                        : 'text-muted-foreground hover:text-foreground'
                                )"
                            >
                                {{ sort.label }}
                                <component
                                    v-if="sortField === sort.value"
                                    :is="sortDirection === 'asc' ? ArrowUp : ArrowDown"
                                    class="h-3 w-3"
                                />
                            </button>
                        </div>
                    </div>
                </div>
                <div class="text-sm text-muted-foreground">
                    {{ filteredGroups.length }} groups &middot; {{ totalAlerts.toLocaleString() }} alerts
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
                                <!-- Primary group display based on triageGroupBy -->
                                <div v-if="triageGroupBy === 'severity'" class="flex items-center gap-2">
                                    <span :class="cn('px-2 py-0.5 rounded-full border text-xs font-semibold', getSeverityStyles(group.severity))">
                                        {{ group.severity }}
                                    </span>
                                </div>
                                <div v-else-if="triageGroupBy === 'source' || triageGroupBy === 'destination'" class="flex items-center gap-2">
                                    <Network class="h-4 w-4 text-muted-foreground" />
                                    <span class="font-mono font-medium">{{ decodeURIComponent(group.ruleId) }}</span>
                                </div>
                                <div v-else class="font-medium text-foreground line-clamp-1">
                                    {{ group.ruleName }}
                                </div>
                                <!-- Secondary info row -->
                                <div class="flex items-center gap-3 mt-1">
                                    <span v-if="triageGroupBy !== 'rule' && group.ruleName !== 'Unknown'" class="text-xs text-muted-foreground truncate max-w-xs" :title="group.ruleName">
                                        {{ group.ruleName }}
                                    </span>
                                    <span v-if="triageGroupBy === 'rule'" class="text-xs text-muted-foreground font-mono">{{ group.module }}</span>
                                    <span v-if="triageGroupBy !== 'severity'" :class="cn('px-2 py-0.5 rounded-full border text-xs font-semibold', getSeverityStyles(group.severity))">
                                        {{ group.severity }}
                                    </span>
                                </div>
                            </div>
                        </div>
                        <div class="flex items-center gap-4 flex-shrink-0">
                            <!-- Bulk Actions -->
                            <div class="flex items-center gap-1">
                                <button
                                    @click.stop="handleBulkAcknowledgeGroup(group)"
                                    :disabled="bulkActionLoading[`ack-group-${group.ruleId}`]"
                                    class="p-1.5 hover:bg-green-500/20 text-green-600 rounded transition-colors disabled:opacity-50"
                                    title="Acknowledge All"
                                >
                                    <Loader2 v-if="bulkActionLoading[`ack-group-${group.ruleId}`]" class="h-4 w-4 animate-spin" />
                                    <CheckCheck v-else class="h-4 w-4" />
                                </button>
                                <button
                                    @click.stop="handleBulkEscalateGroup(group)"
                                    :disabled="bulkActionLoading[`esc-group-${group.ruleId}`]"
                                    class="p-1.5 hover:bg-primary/20 text-primary rounded transition-colors disabled:opacity-50"
                                    title="Escalate All to Case"
                                >
                                    <Loader2 v-if="bulkActionLoading[`esc-group-${group.ruleId}`]" class="h-4 w-4 animate-spin" />
                                    <Briefcase v-else class="h-4 w-4" />
                                </button>
                            </div>
                            <span class="font-mono font-semibold text-lg">{{ group.count.toLocaleString() }}</span>
                            <Loader2 v-if="groupLoadingState[group.ruleId]" class="h-4 w-4 animate-spin text-muted-foreground" />
                        </div>
                    </div>

                    <!-- Expanded Content: Subgroups (Pairs when grouped by rule, Rules when grouped by source/dest) -->
                    <div v-if="expandedGroup === group.ruleId" class="border-t border-border">
                        <!-- AI Summary (shown when grouped by rule) -->
                        <div
                            v-if="triageGroupBy === 'rule' && (getDetectionInfo(decodeURIComponent(group.ruleId)) !== undefined || isDetectionInfoLoading(decodeURIComponent(group.ruleId)))"
                            class="px-4 py-3 bg-muted/30 border-b border-border"
                        >
                            <div v-if="isDetectionInfoLoading(decodeURIComponent(group.ruleId))" class="flex items-center gap-2 text-sm text-muted-foreground">
                                <Loader2 class="h-4 w-4 animate-spin" />
                                <span>Loading AI summary...</span>
                            </div>
                            <div v-else class="space-y-1">
                                <div class="flex items-center gap-2">
                                    <Bot class="h-4 w-4 text-primary" />
                                    <span class="text-xs font-semibold text-primary uppercase tracking-wider">AI Summary</span>
                                    <span
                                        v-if="getDetectionInfo(decodeURIComponent(group.ruleId))?.isAiSummaryStale"
                                        class="text-xs bg-amber-500/10 text-amber-500 px-1.5 py-0.5 rounded"
                                    >
                                        Stale
                                    </span>
                                </div>
                                <p v-if="getDetectionInfo(decodeURIComponent(group.ruleId))?.aiSummary" class="text-sm text-muted-foreground leading-relaxed pl-6">
                                    {{ getDetectionInfo(decodeURIComponent(group.ruleId))?.aiSummary }}
                                </p>
                                <p v-else class="text-sm text-muted-foreground/60 italic pl-6">This rule doesn't have an AI Summary</p>
                            </div>
                        </div>

                        <!-- IP Aggregation Summary (shown when grouped by rule and subgroups are loaded) -->
                        <div
                            v-if="triageGroupBy === 'rule' && subgroups.length > 0 && (aggregatedSourceIps.length > 0 || aggregatedDestIps.length > 0)"
                            class="px-4 py-3 bg-muted/20 border-b border-border"
                        >
                            <div class="flex items-center justify-between mb-3">
                                <div class="flex items-center gap-2">
                                    <Network class="h-4 w-4 text-muted-foreground" />
                                    <span class="text-xs font-semibold text-muted-foreground uppercase tracking-wider">IP Overview</span>
                                    <span class="text-xs text-muted-foreground">
                                        ({{ aggregatedTotalCount.toLocaleString() }} alerts across {{ subgroups.length }} pairs)
                                    </span>
                                </div>
                                <!-- Detection Toggle -->
                                <div v-if="detectionCache.get(decodeURIComponent(group.ruleId))" class="flex items-center gap-2">
                                    <span class="text-xs text-muted-foreground">Detection</span>
                                    <span
                                        :class="detectionCache.get(decodeURIComponent(group.ruleId))?.isEnabled ? 'text-green-500' : 'text-amber-500'"
                                        class="text-xs font-medium flex items-center gap-1"
                                    >
                                        <CheckCircle v-if="detectionCache.get(decodeURIComponent(group.ruleId))?.isEnabled" class="h-3 w-3" />
                                        <X v-else class="h-3 w-3" />
                                        {{ detectionCache.get(decodeURIComponent(group.ruleId))?.isEnabled ? 'Active' : 'Disabled' }}
                                    </span>
                                    <button
                                        @click.stop="toggleDetectionEnabled(decodeURIComponent(group.ruleId))"
                                        :disabled="detectionToggleLoading === decodeURIComponent(group.ruleId)"
                                        :class="cn(
                                            'relative inline-flex h-5 w-9 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-primary focus:ring-offset-2 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed',
                                            detectionCache.get(decodeURIComponent(group.ruleId))?.isEnabled ? 'bg-green-500' : 'bg-muted'
                                        )"
                                        :title="detectionCache.get(decodeURIComponent(group.ruleId))?.isEnabled ? 'Disable detection' : 'Enable detection'"
                                    >
                                        <span
                                            :class="cn(
                                                'inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow-sm transition-transform',
                                                detectionCache.get(decodeURIComponent(group.ruleId))?.isEnabled ? 'translate-x-5' : 'translate-x-0.5'
                                            )"
                                        />
                                        <Loader2
                                            v-if="detectionToggleLoading === decodeURIComponent(group.ruleId)"
                                            class="absolute inset-0 m-auto h-2.5 w-2.5 animate-spin text-white"
                                        />
                                    </button>
                                </div>
                            </div>
                            <div class="grid grid-cols-2 gap-4">
                                <!-- Source IPs -->
                                <div class="space-y-1.5">
                                    <div class="text-xs font-medium text-muted-foreground flex items-center gap-1.5">
                                        <span class="w-2 h-2 rounded-full bg-blue-500"></span>
                                        Sources ({{ aggregatedSourceIps.length }})
                                    </div>
                                    <div class="flex flex-wrap gap-1.5 max-h-24 overflow-y-auto">
                                        <span
                                            v-for="item in aggregatedSourceIps.slice(0, 10)"
                                            :key="item.ip"
                                            class="inline-flex items-center gap-1 px-2 py-0.5 bg-blue-500/10 text-blue-600 dark:text-blue-400 rounded text-xs font-mono"
                                            :title="`${item.ip}: ${item.count} alerts`"
                                        >
                                            {{ item.ip }}
                                            <span class="text-blue-400 dark:text-blue-500">{{ item.count }}</span>
                                        </span>
                                        <span
                                            v-if="aggregatedSourceIps.length > 10"
                                            class="inline-flex items-center px-2 py-0.5 bg-muted text-muted-foreground rounded text-xs"
                                        >
                                            +{{ aggregatedSourceIps.length - 10 }} more
                                        </span>
                                    </div>
                                </div>
                                <!-- Destination IPs -->
                                <div class="space-y-1.5">
                                    <div class="text-xs font-medium text-muted-foreground flex items-center gap-1.5">
                                        <span class="w-2 h-2 rounded-full bg-orange-500"></span>
                                        Destinations ({{ aggregatedDestIps.length }})
                                    </div>
                                    <div class="flex flex-wrap gap-1.5 max-h-24 overflow-y-auto">
                                        <span
                                            v-for="item in aggregatedDestIps.slice(0, 10)"
                                            :key="item.ip"
                                            class="inline-flex items-center gap-1 px-2 py-0.5 bg-orange-500/10 text-orange-600 dark:text-orange-400 rounded text-xs font-mono"
                                            :title="`${item.ip}: ${item.count} alerts`"
                                        >
                                            {{ item.ip }}
                                            <span class="text-orange-400 dark:text-orange-500">{{ item.count }}</span>
                                        </span>
                                        <span
                                            v-if="aggregatedDestIps.length > 10"
                                            class="inline-flex items-center px-2 py-0.5 bg-muted text-muted-foreground rounded text-xs"
                                        >
                                            +{{ aggregatedDestIps.length - 10 }} more
                                        </span>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <!-- Loading subgroups -->
                        <div v-if="subgroupsLoading && subgroups.length === 0" class="p-4 text-center">
                            <Loader2 class="h-5 w-5 animate-spin mx-auto text-muted-foreground" />
                            <p class="text-sm text-muted-foreground mt-2">
                                {{ triageGroupBy === 'rule' ? 'Loading source/destination pairs...' : 'Loading rules...' }}
                            </p>
                        </div>

                        <!-- No subgroups -->
                        <div v-else-if="subgroups.length === 0" class="p-6 text-center text-muted-foreground">
                            <component :is="triageGroupBy === 'rule' ? Network : Shield" class="h-8 w-8 mx-auto mb-2 opacity-30" />
                            <p>{{ triageGroupBy === 'rule' ? 'No source/destination pairs found' : 'No rules found' }}</p>
                        </div>

                        <!-- Subgroups list -->
                        <div v-else class="divide-y divide-border">
                            <div v-for="subgroup in subgroups" :key="subgroup.key">
                                <!-- Subgroup Row -->
                                <div
                                    @click="toggleSubgroup(group, subgroup)"
                                    :class="cn(
                                        'px-4 py-3 pl-12 flex items-center justify-between cursor-pointer transition-colors',
                                        expandedPair === subgroup.key ? 'bg-primary/5' : 'hover:bg-muted/30'
                                    )"
                                >
                                    <div class="flex items-center gap-3">
                                        <component
                                            :is="expandedPair === subgroup.key ? ChevronDown : ChevronRight"
                                            class="h-4 w-4 text-muted-foreground"
                                        />
                                        <!-- Pair display (source → dest) -->
                                        <template v-if="subgroup.type === 'pair'">
                                            <Network class="h-4 w-4 text-muted-foreground" />
                                            <span class="font-mono text-sm">
                                                {{ subgroup.label }}
                                                <span class="text-muted-foreground mx-2">→</span>
                                                {{ subgroup.secondaryLabel }}
                                            </span>
                                        </template>
                                        <!-- Rule display (rule name with severity badge) -->
                                        <template v-else>
                                            <Shield class="h-4 w-4 text-muted-foreground" />
                                            <span class="text-sm truncate max-w-md" :title="subgroup.label">{{ subgroup.label }}</span>
                                            <span v-if="subgroup.secondaryLabel" :class="cn('px-2 py-0.5 rounded-full border text-xs font-semibold', getSeverityStyles(subgroup.secondaryLabel))">
                                                {{ subgroup.secondaryLabel }}
                                            </span>
                                        </template>
                                    </div>
                                    <div class="flex items-center gap-3">
                                        <!-- Subgroup Bulk Actions -->
                                        <div class="flex items-center gap-1">
                                            <button
                                                @click.stop="handleBulkAcknowledgeSubgroup(group, subgroup)"
                                                :disabled="bulkActionLoading[`ack-subgroup-${subgroup.key}`]"
                                                class="p-1 hover:bg-green-500/20 text-green-600 rounded transition-colors disabled:opacity-50"
                                                title="Acknowledge All"
                                            >
                                                <Loader2 v-if="bulkActionLoading[`ack-subgroup-${subgroup.key}`]" class="h-3.5 w-3.5 animate-spin" />
                                                <CheckCheck v-else class="h-3.5 w-3.5" />
                                            </button>
                                            <button
                                                @click.stop="handleBulkEscalateSubgroup(group, subgroup)"
                                                :disabled="bulkActionLoading[`esc-subgroup-${subgroup.key}`]"
                                                class="p-1 hover:bg-primary/20 text-primary rounded transition-colors disabled:opacity-50"
                                                title="Escalate All to Case"
                                            >
                                                <Loader2 v-if="bulkActionLoading[`esc-subgroup-${subgroup.key}`]" class="h-3.5 w-3.5 animate-spin" />
                                                <Briefcase v-else class="h-3.5 w-3.5" />
                                            </button>
                                        </div>
                                        <span class="font-mono font-medium">{{ subgroup.count.toLocaleString() }}</span>
                                    </div>
                                </div>

                                <!-- Expanded Alerts for this subgroup -->
                                <div v-if="expandedPair === subgroup.key" class="bg-muted/20 border-t border-border">
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
                                                    <th v-if="subgroup.type === 'rule'" class="px-4 py-2 text-left font-medium text-muted-foreground text-xs">Rule</th>
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
                                                    :class="cn(
                                                        'hover:bg-muted/30 transition-colors group cursor-pointer',
                                                        lastClickedAlertId === alert.soc_id && 'bg-primary/10 ring-1 ring-primary/30'
                                                    )"
                                                    @click="viewAlertDetail(alert)"
                                                >
                                                    <td class="px-4 py-2">
                                                        <div class="flex items-center gap-2 text-xs">
                                                            <Clock class="h-3 w-3 text-muted-foreground" />
                                                            {{ formatDate(alert.soc_timestamp || alert['@timestamp']) }}
                                                        </div>
                                                    </td>
                                                    <td v-if="subgroup.type === 'rule'" class="px-4 py-2 text-xs truncate max-w-xs" :title="getField(alert, 'rule.name')">
                                                        {{ getField(alert, 'rule.name') }}
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
                                        No alerts found
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
        </template>

        <!-- ==================== TABLE VIEW (Hunt-like) ==================== -->
        <template v-else-if="viewMode === 'table'">
            <!-- Table Toolbar -->
            <div class="flex items-center justify-between mb-4">
                <div class="flex items-center gap-4">
                    <!-- Group By Dropdown -->
                    <div class="flex items-center gap-2">
                        <Group class="h-4 w-4 text-muted-foreground" />
                        <span class="text-sm text-muted-foreground">Group by:</span>
                        <select
                            :value="tableGroupBy"
                            @change="setTableGroupBy(($event.target as HTMLSelectElement).value as any)"
                            class="bg-background border border-border rounded-md px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-primary/50"
                        >
                            <option value="none">None</option>
                            <option value="rule">Rule</option>
                            <option value="severity">Severity</option>
                            <option value="source">Source IP</option>
                            <option value="destination">Destination IP</option>
                        </select>
                    </div>
                </div>
                <div class="text-sm text-muted-foreground">
                    {{ totalAlerts.toLocaleString() }} alerts
                </div>
            </div>

            <!-- Loading State -->
            <div v-if="allAlertsLoading && !allAlertsLoadingMore" class="rounded-xl border border-border bg-card overflow-hidden">
                <div class="p-8 text-center">
                    <Loader2 class="h-8 w-8 animate-spin mx-auto text-muted-foreground" />
                    <p class="text-sm text-muted-foreground mt-2">Loading alerts...</p>
                </div>
            </div>

            <!-- Empty State -->
            <div v-else-if="allAlerts.length === 0" class="rounded-xl border border-border bg-card p-12 text-center">
                <Bell class="h-12 w-12 mx-auto mb-4 opacity-20" />
                <p class="text-lg font-medium">No alerts found</p>
                <p class="text-sm text-muted-foreground mt-1">No alerts match the current filters.</p>
            </div>

            <!-- Grouped View -->
            <div v-else-if="tableGroupBy !== 'none'" class="space-y-2">
                <div
                    v-for="group in tableGroups"
                    :key="group.key"
                    class="rounded-xl border border-border bg-card overflow-hidden"
                >
                    <!-- Group Header -->
                    <div
                        @click="toggleTableGroup(group.key)"
                        class="px-4 py-3 flex items-center justify-between cursor-pointer hover:bg-muted/30 transition-colors"
                    >
                        <div class="flex items-center gap-3">
                            <component
                                :is="group.expanded ? ChevronDown : ChevronRight"
                                class="h-5 w-5 text-muted-foreground"
                            />
                            <span v-if="tableGroupBy === 'severity'" :class="cn('px-2 py-0.5 rounded-full border text-xs font-semibold', getSeverityStyles(group.label))">
                                {{ group.label }}
                            </span>
                            <span v-else class="font-medium">{{ group.label }}</span>
                        </div>
                        <span class="font-mono font-semibold">{{ group.count.toLocaleString() }}</span>
                    </div>

                    <!-- Expanded Group Table -->
                    <div v-if="group.expanded" class="border-t border-border">
                        <div class="overflow-x-auto">
                            <table class="w-full text-sm">
                                <thead>
                                    <tr class="bg-muted/30 border-b border-border">
                                        <th class="px-4 py-2 text-left font-medium text-muted-foreground text-xs">Timestamp</th>
                                        <th v-if="tableGroupBy !== 'rule'" class="px-4 py-2 text-left font-medium text-muted-foreground text-xs">Rule</th>
                                        <th v-if="tableGroupBy !== 'severity'" class="px-4 py-2 text-left font-medium text-muted-foreground text-xs">Severity</th>
                                        <th v-if="tableGroupBy !== 'source'" class="px-4 py-2 text-left font-medium text-muted-foreground text-xs">Source</th>
                                        <th v-if="tableGroupBy !== 'destination'" class="px-4 py-2 text-left font-medium text-muted-foreground text-xs">Destination</th>
                                        <th class="px-4 py-2 text-left font-medium text-muted-foreground text-xs">Status</th>
                                        <th class="px-4 py-2 text-right font-medium text-muted-foreground text-xs">Actions</th>
                                    </tr>
                                </thead>
                                <tbody class="divide-y divide-border">
                                    <tr
                                        v-for="alert in group.alerts"
                                        :key="alert.soc_id"
                                        :class="cn(
                                            'hover:bg-muted/30 transition-colors cursor-pointer',
                                            lastClickedAlertId === alert.soc_id && 'bg-primary/10 ring-1 ring-primary/30'
                                        )"
                                        @click="viewAlertDetail(alert)"
                                    >
                                        <td class="px-4 py-2 text-xs">{{ formatDate(alert.soc_timestamp || alert['@timestamp']) }}</td>
                                        <td v-if="tableGroupBy !== 'rule'" class="px-4 py-2 text-xs max-w-xs truncate" :title="alert['rule.name']">{{ alert['rule.name'] || '-' }}</td>
                                        <td v-if="tableGroupBy !== 'severity'" class="px-4 py-2">
                                            <span :class="cn('px-2 py-0.5 rounded-full border text-xs font-semibold', getSeverityStyles(alert['event.severity_label'] || 'unknown'))">
                                                {{ alert['event.severity_label'] || 'unknown' }}
                                            </span>
                                        </td>
                                        <td v-if="tableGroupBy !== 'source'" class="px-4 py-2 font-mono text-xs">{{ alert['source.ip'] || '-' }}</td>
                                        <td v-if="tableGroupBy !== 'destination'" class="px-4 py-2 font-mono text-xs">{{ alert['destination.ip'] || '-' }}</td>
                                        <td class="px-4 py-2">
                                            <span v-if="alert['event.acknowledged']" class="text-xs text-green-600">Ack</span>
                                            <span v-else class="text-xs text-muted-foreground">Unack</span>
                                        </td>
                                        <td class="px-4 py-2">
                                            <div class="flex items-center justify-end gap-1">
                                                <button
                                                    v-if="!alert['event.acknowledged']"
                                                    @click.stop="handleAcknowledge(alert, true)"
                                                    class="p-1 hover:bg-green-500/20 text-green-600 rounded"
                                                    title="Acknowledge"
                                                >
                                                    <Check class="h-3.5 w-3.5" />
                                                </button>
                                                <button
                                                    v-else
                                                    @click.stop="handleAcknowledge(alert, false)"
                                                    class="p-1 hover:bg-red-500/20 text-red-600 rounded"
                                                    title="Unacknowledge"
                                                >
                                                    <X class="h-3.5 w-3.5" />
                                                </button>
                                                <button @click.stop="handleEscalate(alert)" class="p-1 hover:bg-primary/20 text-primary rounded" title="Escalate">
                                                    <Briefcase class="h-3.5 w-3.5" />
                                                </button>
                                                <button @click.stop="handleInvestigate(alert)" class="p-1 hover:bg-purple-500/20 text-purple-600 rounded" title="AI Investigate">
                                                    <Sparkles class="h-3.5 w-3.5" />
                                                </button>
                                                <button @click.stop="drillIntoHunt(alert)" class="p-1 hover:bg-muted text-muted-foreground rounded" title="Open in Hunt">
                                                    <ExternalLink class="h-3.5 w-3.5" />
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Flat Table View (no grouping) -->
            <div v-else class="rounded-xl border border-border bg-card overflow-hidden">
                <div class="overflow-x-auto">
                    <table class="w-full text-sm">
                        <thead>
                            <tr class="bg-muted/50 border-b border-border">
                                <th
                                    @click="setTableSort('timestamp')"
                                    class="px-4 py-3 text-left font-medium text-muted-foreground cursor-pointer hover:text-foreground transition-colors"
                                >
                                    <div class="flex items-center gap-1">
                                        Timestamp
                                        <component v-if="tableSortField === 'timestamp'" :is="tableSortDirection === 'asc' ? ArrowUp : ArrowDown" class="h-3 w-3" />
                                        <ArrowUpDown v-else class="h-3 w-3 opacity-30" />
                                    </div>
                                </th>
                                <th
                                    @click="setTableSort('rule')"
                                    class="px-4 py-3 text-left font-medium text-muted-foreground cursor-pointer hover:text-foreground transition-colors"
                                >
                                    <div class="flex items-center gap-1">
                                        Rule
                                        <component v-if="tableSortField === 'rule'" :is="tableSortDirection === 'asc' ? ArrowUp : ArrowDown" class="h-3 w-3" />
                                        <ArrowUpDown v-else class="h-3 w-3 opacity-30" />
                                    </div>
                                </th>
                                <th
                                    @click="setTableSort('severity')"
                                    class="px-4 py-3 text-left font-medium text-muted-foreground cursor-pointer hover:text-foreground transition-colors"
                                >
                                    <div class="flex items-center gap-1">
                                        Severity
                                        <component v-if="tableSortField === 'severity'" :is="tableSortDirection === 'asc' ? ArrowUp : ArrowDown" class="h-3 w-3" />
                                        <ArrowUpDown v-else class="h-3 w-3 opacity-30" />
                                    </div>
                                </th>
                                <th
                                    @click="setTableSort('source')"
                                    class="px-4 py-3 text-left font-medium text-muted-foreground cursor-pointer hover:text-foreground transition-colors"
                                >
                                    <div class="flex items-center gap-1">
                                        Source
                                        <component v-if="tableSortField === 'source'" :is="tableSortDirection === 'asc' ? ArrowUp : ArrowDown" class="h-3 w-3" />
                                        <ArrowUpDown v-else class="h-3 w-3 opacity-30" />
                                    </div>
                                </th>
                                <th
                                    @click="setTableSort('destination')"
                                    class="px-4 py-3 text-left font-medium text-muted-foreground cursor-pointer hover:text-foreground transition-colors"
                                >
                                    <div class="flex items-center gap-1">
                                        Destination
                                        <component v-if="tableSortField === 'destination'" :is="tableSortDirection === 'asc' ? ArrowUp : ArrowDown" class="h-3 w-3" />
                                        <ArrowUpDown v-else class="h-3 w-3 opacity-30" />
                                    </div>
                                </th>
                                <th class="px-4 py-3 text-left font-medium text-muted-foreground">Status</th>
                                <th class="px-4 py-3 text-right font-medium text-muted-foreground">Actions</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-border">
                            <tr
                                v-for="alert in sortedAllAlerts"
                                :key="alert.soc_id"
                                :class="cn(
                                    'hover:bg-muted/30 transition-colors group cursor-pointer',
                                    lastClickedAlertId === alert.soc_id && 'bg-primary/10 ring-1 ring-primary/30'
                                )"
                                @click="viewAlertDetail(alert)"
                            >
                                <td class="px-4 py-3">
                                    <div class="flex items-center gap-2 text-xs">
                                        <Clock class="h-3 w-3 text-muted-foreground" />
                                        {{ formatDate(alert.soc_timestamp || alert['@timestamp']) }}
                                    </div>
                                </td>
                                <td class="px-4 py-3">
                                    <div class="font-medium text-sm line-clamp-1 max-w-xs" :title="alert['rule.name']">
                                        {{ alert['rule.name'] || '-' }}
                                    </div>
                                    <div class="text-xs text-muted-foreground font-mono">{{ alert['event.module'] || '-' }}</div>
                                </td>
                                <td class="px-4 py-3">
                                    <span :class="cn('px-2 py-0.5 rounded-full border text-xs font-semibold', getSeverityStyles(alert['event.severity_label'] || 'unknown'))">
                                        {{ alert['event.severity_label'] || 'unknown' }}
                                    </span>
                                </td>
                                <td class="px-4 py-3 font-mono text-xs">
                                    {{ alert['source.ip'] || '-' }}
                                    <span v-if="alert['source.port']" class="text-muted-foreground">:{{ alert['source.port'] }}</span>
                                </td>
                                <td class="px-4 py-3 font-mono text-xs">
                                    {{ alert['destination.ip'] || '-' }}
                                    <span v-if="alert['destination.port']" class="text-muted-foreground">:{{ alert['destination.port'] }}</span>
                                </td>
                                <td class="px-4 py-3">
                                    <span v-if="alert['event.acknowledged']" class="inline-flex items-center gap-1 text-xs text-green-600">
                                        <CheckCircle class="h-3 w-3" />
                                        Ack
                                    </span>
                                    <span v-else class="inline-flex items-center gap-1 text-xs text-muted-foreground">
                                        <X class="h-3 w-3" />
                                        Unack
                                    </span>
                                </td>
                                <td class="px-4 py-3">
                                    <div class="flex items-center justify-end gap-1">
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
                                        <button
                                            @click.stop="handleEscalate(alert)"
                                            class="p-1.5 hover:bg-primary/20 text-primary rounded transition-colors"
                                            title="Escalate to Case"
                                        >
                                            <Briefcase class="h-4 w-4" />
                                        </button>
                                        <button
                                            @click.stop="handleInvestigate(alert)"
                                            class="p-1.5 hover:bg-purple-500/20 text-purple-600 rounded transition-colors"
                                            title="AI Investigate"
                                        >
                                            <Sparkles class="h-4 w-4" />
                                        </button>
                                        <button
                                            @click.stop="drillIntoHunt(alert)"
                                            class="p-1.5 hover:bg-muted text-muted-foreground rounded transition-colors"
                                            title="Open in Hunt"
                                        >
                                            <ExternalLink class="h-4 w-4" />
                                        </button>
                                    </div>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>

                <!-- Loading More -->
                <div v-if="allAlertsLoadingMore" class="flex items-center justify-center py-4 border-t border-border">
                    <Loader2 class="h-5 w-5 animate-spin text-muted-foreground" />
                    <span class="ml-2 text-sm text-muted-foreground">Loading more...</span>
                </div>

                <!-- Load More Button -->
                <div v-else-if="hasMoreAllAlerts" class="p-4 border-t border-border text-center">
                    <button
                        @click="fetchAllAlerts(true)"
                        class="px-4 py-2 bg-muted hover:bg-muted/80 rounded-md text-sm font-medium transition-colors"
                    >
                        Load More
                    </button>
                </div>

                <!-- End of List -->
                <div v-else class="py-4 border-t border-border text-center text-sm text-muted-foreground">
                    End of results
                </div>
            </div>
        </template>

        <!-- Escalate Dialog -->
        <EscalateDialog
            ref="escalateDialogRef"
            :open="showEscalateDialog"
            :event="escalateTarget"
            @close="showEscalateDialog = false"
            @confirm="handleEscalateConfirm"
        />

        <!-- Disable Detection Confirmation Dialog -->
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
                    v-if="showDisableDetectionConfirm"
                    class="fixed inset-0 z-50 flex items-center justify-center p-4"
                >
                    <!-- Backdrop -->
                    <div
                        class="absolute inset-0 bg-background/80 backdrop-blur-sm"
                        @click="cancelDisableDetection"
                    />

                    <!-- Dialog -->
                    <div class="relative bg-card border border-border rounded-xl shadow-2xl w-full max-w-md animate-in zoom-in-95 duration-200">
                        <!-- Header -->
                        <div class="px-6 py-4 border-b border-border">
                            <div class="flex items-center gap-3">
                                <div class="p-2 rounded-lg bg-amber-500/10">
                                    <Power class="h-5 w-5 text-amber-500" />
                                </div>
                                <h3 class="text-lg font-semibold">Disable Detection</h3>
                            </div>
                        </div>

                        <!-- Content -->
                        <div class="px-6 py-5 space-y-4">
                            <p class="text-sm text-muted-foreground">
                                You are about to disable this detection. No new alerts will be generated for this rule.
                            </p>

                            <div class="bg-muted/50 rounded-lg p-4 space-y-2 text-sm">
                                <div class="flex justify-between">
                                    <span class="text-muted-foreground">Detection:</span>
                                    <span class="font-medium truncate max-w-[200px]" :title="pendingDisableRuleName || ''">
                                        {{ pendingDisableRuleName || 'Unknown' }}
                                    </span>
                                </div>
                            </div>

                            <!-- Acknowledge all alerts checkbox -->
                            <label class="flex items-start gap-3 cursor-pointer group">
                                <div class="relative mt-0.5">
                                    <input
                                        type="checkbox"
                                        v-model="disableDetectionAckAll"
                                        class="sr-only peer"
                                    />
                                    <div class="w-5 h-5 border-2 border-border rounded peer-checked:border-primary peer-checked:bg-primary transition-colors">
                                        <Check v-if="disableDetectionAckAll" class="h-4 w-4 text-primary-foreground" />
                                    </div>
                                </div>
                                <div class="flex-1">
                                    <span class="text-sm font-medium">Acknowledge all unacknowledged alerts</span>
                                    <p class="text-xs text-muted-foreground mt-0.5">
                                        Mark all existing alerts from this detection as acknowledged since they are no longer relevant.
                                    </p>
                                </div>
                            </label>
                        </div>

                        <!-- Footer -->
                        <div class="px-6 py-4 border-t border-border bg-muted/30 flex justify-end gap-3">
                            <button
                                @click="cancelDisableDetection"
                                class="px-4 py-2 text-sm font-medium rounded-lg border border-border hover:bg-muted transition-colors"
                            >
                                Cancel
                            </button>
                            <button
                                @click="confirmDisableDetection"
                                :disabled="detectionToggleLoading !== null"
                                class="px-4 py-2 text-sm font-medium rounded-lg bg-amber-600 text-white hover:bg-amber-700 transition-colors disabled:opacity-50 flex items-center gap-2"
                            >
                                <Loader2 v-if="detectionToggleLoading !== null" class="h-4 w-4 animate-spin" />
                                <span>{{ detectionToggleLoading !== null ? 'Disabling...' : 'Disable Detection' }}</span>
                            </button>
                        </div>
                    </div>
                </div>
            </Transition>
        </Teleport>
    </div>
</template>
