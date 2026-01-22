<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import {
    ArrowLeft,
    Clock,
    Network,
    Shield,
    ShieldOff,
    Server,
    AlertTriangle,
    Check,
    X,
    Sparkles,
    Briefcase,
    ExternalLink,
    Copy,
    CheckCircle,
    MapPin,
    Activity,
    Hash,
    FileText,
    ChevronDown,
    ChevronRight,
    ChevronUp,
    Code,
    Loader2,
    BookOpen,
    Crosshair,
    FlaskConical,
    Minimize2,
    Maximize2,
    Download,
    HardDrive,
    RefreshCw,
    Eye,
    EyeOff,
    Settings,
    List,
    LayoutGrid,
    Plus,
    Trash2,
    ToggleLeft,
    ToggleRight,
    Power,
    Bot,
    StickyNote,
    CheckSquare,
    Square
} from 'lucide-vue-next'
import { cn } from '../lib/utils'
import { useApi } from '../composables/useApi'
import { useTimeRange } from '../composables/useTimeRange'
import { useFormatters } from '../composables/useFormatters'
import { useStatusStyles } from '../composables/useStatusStyles'
import { useHuntActions } from '../composables/useHuntActions'
import { useChatWidget } from '../composables/useChatWidget'
import { usePlaybook, type PlaybookState } from '../composables/usePlaybook'
import { useMarkedEvents, type MarkedEvent } from '../composables/useMarkedEvents'
import EscalateDialog from '../components/alerts/EscalateDialog.vue'
import type { EventRecord, PlaybookQuestion } from '../types/hunt'

const route = useRoute()
const router = useRouter()

const props = defineProps<{ id?: string }>()
const alertId = computed(() => (route.params.id as string) || props.id || '')

const { get, post, put } = useApi()
const { formatDate, formatDateForApi } = useFormatters()
const { getSeverityStyles } = useStatusStyles()
const { zone } = useTimeRange()

const {
    acknowledgeEvent,
    escalateToNewCase,
    attachPcapToCase,
    generateInvestigationPrompt,
    bulkAcknowledgeByQuery,
    loading: actionLoading
} = useHuntActions()

const { openNewChatWithPrompt } = useChatWidget()
const { loadPlaybook, buildHuntQuery, toggleQuestion, expandAllQuestions, collapseAllQuestions, isQuestionExpanded } = usePlaybook()
const {
    markedEvents,
    markedCount,
    hasMarkedEvents,
    toggleMarked,
    isMarked,
    updateNote,
    getNote,
    getMarkedEvents,
    getMarkedEventIds,
    markAll,
    clearMarks,
    clearStorage
} = useMarkedEvents(alertId)

// Override interface for detection tuning
interface Override {
    type: 'suppress' | 'threshold' | 'modify' | 'customFilter'
    isEnabled: boolean
    note?: string
    createdAt?: string
    updatedAt?: string
    // Suricata suppress/threshold
    track?: 'by_src' | 'by_dst' | 'by_either'
    ip?: string
    // Threshold specific
    thresholdType?: string
    count?: number
    seconds?: number
    // Modify specific
    regex?: string
    value?: string
    // ElastAlert specific
    customFilter?: string
}

// Detection interface
interface Detection {
    id: string
    publicId: string
    title: string
    description: string
    severity: string
    engine: string
    language: string
    author: string
    category?: string
    content: string
    tags: string[]
    ruleset: string
    overrides?: Override[]
    isEnabled?: boolean
    isCommunity?: boolean
    aiSummary?: string
}

// PCAP Job interface
interface PcapJob {
    id: number
    nodeId: string
    userId: string
    status: number // 0=Pending, 1=Completed, 2=Incomplete, 3=Deleted
    createTime: string
    completeTime: string
    failure: string
    size: number
    fileExtension: string
    filter?: {
        srcIp?: string
        srcPort?: number
        dstIp?: string
        dstPort?: number
        protocol?: string
        beginTime?: string
        endTime?: string
        parameters?: Record<string, any>
    }
}

const JOB_STATUS = {
    PENDING: 0,
    COMPLETED: 1,
    INCOMPLETE: 2,
    DELETED: 3
} as const

// State
const alert = ref<EventRecord | null>(null)
const loading = ref(true)
const error = ref<string | null>(null)
const copied = ref(false)
const showAllFields = ref(false)
const showRuleContent = ref(false)
const showFullDetection = ref(false) // Toggle between signature only vs full detection details
const detection = ref<Detection | null>(null)
const detectionLoading = ref(false)
const detectionError = ref<string | null>(null)
const showGuidedAnalysis = ref(true)
const playbookState = ref<PlaybookState | null>(null)
const expandedResults = ref<Map<number, any[]>>(new Map())
const loadingResults = ref<Set<number>>(new Set())
const hasMoreResults = ref<Map<number, boolean>>(new Map()) // Track if more results might be available
const RESULTS_PAGE_SIZE = 100

// PCAP state
const pcapJob = ref<PcapJob | null>(null)
const pcapLoading = ref(false)
const pcapError = ref<string | null>(null)
let pcapPollInterval: ReturnType<typeof setInterval> | null = null

// PCAP packet viewer state
const showPcapDetails = ref(false)
const packets = ref<any[]>([])
const packetsLoading = ref(false)
const expandedPackets = ref<Set<number>>(new Set())
const packetViewMode = ref<'hex' | 'ascii'>('hex')
const pcapDisplayMode = ref<'packets' | 'transcript'>('packets')

// Escalate dialog state
const showEscalateDialog = ref(false)
const escalateDialogRef = ref<InstanceType<typeof EscalateDialog> | null>(null)

// Disable detection confirmation dialog state
const showDisableDetectionConfirm = ref(false)
const disableDetectionAckAll = ref(true) // Default to acknowledging all alerts

// Action menu state
const actionMenuVisible = ref(false)
const actionMenuX = ref(0)
const actionMenuY = ref(0)
const actionMenuField = ref('')
const actionMenuValue = ref<any>(null)

// Suppression confirmation dialog state
const showSuppressionConfirm = ref(false)
const pendingSuppressionTrack = ref<'by_src' | 'by_dst' | null>(null)
const pendingSuppressionIp = ref<string | null>(null)

// User preferences
interface AlertDetailPreferences {
    autoExpandDetectionDetails: boolean
    autoExpandGuidedAnalysis: boolean
    autoExpandAllFields: boolean
    allFieldsDisplayMode: 'list' | 'grid'
}

const PREFERENCES_KEY = 'alertDetailPreferences'
const showSettingsPanel = ref(false)

const defaultPreferences: AlertDetailPreferences = {
    autoExpandDetectionDetails: false,
    autoExpandGuidedAnalysis: true,
    autoExpandAllFields: false,
    allFieldsDisplayMode: 'list'
}

const preferences = ref<AlertDetailPreferences>({ ...defaultPreferences })

function loadPreferences() {
    try {
        const stored = localStorage.getItem(PREFERENCES_KEY)
        if (stored) {
            const parsed = JSON.parse(stored)
            preferences.value = { ...defaultPreferences, ...parsed }
        }
    } catch (e) {
        console.debug('Could not load alert detail preferences:', e)
    }

    // Apply preferences to initial expand states
    showRuleContent.value = preferences.value.autoExpandDetectionDetails
    showGuidedAnalysis.value = preferences.value.autoExpandGuidedAnalysis
    showAllFields.value = preferences.value.autoExpandAllFields
}

function savePreferences() {
    try {
        localStorage.setItem(PREFERENCES_KEY, JSON.stringify(preferences.value))
    } catch (e) {
        console.debug('Could not save alert detail preferences:', e)
    }
}

function togglePreference(key: keyof AlertDetailPreferences) {
    preferences.value[key] = !preferences.value[key]
    savePreferences()
}

function setAllFieldsDisplayMode(mode: 'list' | 'grid') {
    preferences.value.allFieldsDisplayMode = mode
    savePreferences()
}

function showActionMenu(e: MouseEvent, field: string, value: any) {
    e.preventDefault()
    e.stopPropagation()
    actionMenuField.value = field
    actionMenuValue.value = value
    actionMenuX.value = e.clientX
    actionMenuY.value = e.clientY
    actionMenuVisible.value = true
}

function closeActionMenu() {
    actionMenuVisible.value = false
}

function huntInNewTab(field: string, value: any) {
    // Build the filter query
    const filterValue = typeof value === 'string' ? `"${value}"` : value
    const query = `${field}:${filterValue}`

    // Build the Hunt URL with the query
    const huntUrl = router.resolve({
        name: 'hunt',
        query: { q: query }
    })

    // Open in new tab
    window.open(huntUrl.href, '_blank')
    closeActionMenu()
}

function copyFieldValue(value: any) {
    const val = value === null || value === undefined ? '' : String(value)
    navigator.clipboard.writeText(val)
    closeActionMenu()
}

function askAiAboutField(field: string, value: any) {
    const prompt = `Tell me about this field and value from the alert:\n\nField: ${field}\nValue: ${value}`
    openNewChatWithPrompt(prompt)
    closeActionMenu()
}

// Check if field is an IP address field
function isIpField(field: string): boolean {
    return field === 'source.ip' || field === 'destination.ip' ||
           field.endsWith('.ip') || field.includes('.ip.')
}

// Check if suppression is possible (Suricata detection exists)
const canAddSuppression = computed(() => {
    return detection.value && detection.value.engine === 'suricata'
})

// Suppression state
const suppressionLoading = ref(false)
const suppressionError = ref<string | null>(null)
const suppressionSuccess = ref(false)

// Add a suppression for the detection
async function addSuppression(track: 'by_src' | 'by_dst', ip: string) {
    if (!detection.value || !ip) return

    suppressionLoading.value = true
    suppressionError.value = null
    suppressionSuccess.value = false

    try {
        // Format IP as CIDR if not already
        const cidrIp = ip.includes('/') ? ip : `${ip}/32`

        // Create the new override
        const newOverride: Override = {
            type: 'suppress',
            isEnabled: true,
            track: track,
            ip: cidrIp,
            note: `Suppression added from Alert Detail for ${track === 'by_src' ? 'source' : 'destination'} IP`
        }

        // Fetch the full detection to get current overrides (use useApi for auth headers)
        const fullDetection = await get<Detection>(`/api/detection/${detection.value.id}`)
        if (!fullDetection) {
            throw new Error('Failed to fetch detection')
        }

        // Add the new override to existing overrides
        const updatedOverrides = [...(fullDetection.overrides || []), newOverride]

        // Update the detection with the new override (use useApi for CSRF token)
        const updatedDetection = await put<Detection>(`/api/detection/`, {
            ...fullDetection,
            overrides: updatedOverrides
        })

        if (!updatedDetection) {
            throw new Error('Failed to add suppression')
        }

        // Update local detection state
        detection.value = updatedDetection
        suppressionSuccess.value = true

        // Auto-hide success after 3 seconds
        setTimeout(() => {
            suppressionSuccess.value = false
        }, 3000)

    } catch (e: any) {
        suppressionError.value = e.message || 'Failed to add suppression'
        setTimeout(() => {
            suppressionError.value = null
        }, 5000)
    } finally {
        suppressionLoading.value = false
        closeActionMenu()
    }
}

// Show confirmation dialog for suppression by source IP
function addSuppressionBySource() {
    const ip = actionMenuValue.value
    if (ip) {
        pendingSuppressionTrack.value = 'by_src'
        pendingSuppressionIp.value = String(ip)
        showSuppressionConfirm.value = true
        closeActionMenu()
    }
}

// Show confirmation dialog for suppression by destination IP
function addSuppressionByDestination() {
    const ip = actionMenuValue.value
    if (ip) {
        pendingSuppressionTrack.value = 'by_dst'
        pendingSuppressionIp.value = String(ip)
        showSuppressionConfirm.value = true
        closeActionMenu()
    }
}

// Confirm and execute the suppression
function confirmSuppression() {
    if (pendingSuppressionTrack.value && pendingSuppressionIp.value) {
        addSuppression(pendingSuppressionTrack.value, pendingSuppressionIp.value)
    }
    cancelSuppression()
}

// Cancel the suppression
function cancelSuppression() {
    showSuppressionConfirm.value = false
    pendingSuppressionTrack.value = null
    pendingSuppressionIp.value = null
}

// Get human-readable track description
function getTrackDescription(track: 'by_src' | 'by_dst' | null): string {
    if (track === 'by_src') return 'source'
    if (track === 'by_dst') return 'destination'
    return ''
}

// Threshold confirmation dialog state
const showThresholdConfirm = ref(false)
const pendingThresholdTrack = ref<'by_src' | 'by_dst' | null>(null)
const pendingThresholdType = ref<'limit' | 'threshold' | 'both'>('limit')
const pendingThresholdCount = ref(5)
const pendingThresholdSeconds = ref(60)

// Show threshold dialog for source IP
function addThresholdBySource() {
    pendingThresholdTrack.value = 'by_src'
    pendingThresholdType.value = 'limit'
    pendingThresholdCount.value = 5
    pendingThresholdSeconds.value = 60
    showThresholdConfirm.value = true
    closeActionMenu()
}

// Show threshold dialog for destination IP
function addThresholdByDestination() {
    pendingThresholdTrack.value = 'by_dst'
    pendingThresholdType.value = 'limit'
    pendingThresholdCount.value = 5
    pendingThresholdSeconds.value = 60
    showThresholdConfirm.value = true
    closeActionMenu()
}

// Confirm and execute the threshold
async function confirmThreshold() {
    if (!detection.value || !pendingThresholdTrack.value) return

    suppressionLoading.value = true
    try {
        const fullDetection = await get<Detection>(`/api/detection/${detection.value.id}`)
        if (!fullDetection) {
            throw new Error('Failed to fetch detection')
        }

        const newOverride = {
            type: 'threshold',
            isEnabled: true,
            thresholdType: pendingThresholdType.value,
            track: pendingThresholdTrack.value,
            count: pendingThresholdCount.value,
            seconds: pendingThresholdSeconds.value,
            note: `Threshold added from Alert Detail for ${pendingThresholdTrack.value === 'by_src' ? 'source' : 'destination'} IP`
        }

        const updatedOverrides = [...(fullDetection.overrides || []), newOverride]
        const updatedDetection = await put<Detection>(`/api/detection/`, {
            ...fullDetection,
            overrides: updatedOverrides
        })

        if (updatedDetection) {
            detection.value = updatedDetection
            suppressionSuccess.value = true
            setTimeout(() => { suppressionSuccess.value = false }, 3000)
        }
    } catch (e: any) {
        suppressionError.value = e.message || 'Failed to add threshold'
        setTimeout(() => { suppressionError.value = null }, 5000)
    } finally {
        suppressionLoading.value = false
        cancelThreshold()
    }
}

// Cancel the threshold
function cancelThreshold() {
    showThresholdConfirm.value = false
    pendingThresholdTrack.value = null
}

// Detection management state
const detectionUpdating = ref(false)
const overrideActionIndex = ref<number | null>(null)

// Toggle detection enabled/disabled
function toggleDetectionEnabled() {
    if (!detection.value || detectionUpdating.value) return

    // If enabling, do it directly
    if (!detection.value.isEnabled) {
        performToggleDetection()
        return
    }

    // If disabling, show confirmation dialog
    disableDetectionAckAll.value = true
    showDisableDetectionConfirm.value = true
}

// Actually perform the detection toggle
async function performToggleDetection() {
    if (!detection.value || detectionUpdating.value) return

    detectionUpdating.value = true
    try {
        const updatedDetection = await put<Detection>(`/api/detection/`, {
            ...detection.value,
            isEnabled: !detection.value.isEnabled
        })

        if (updatedDetection) {
            detection.value = updatedDetection
            suppressionSuccess.value = true
            setTimeout(() => { suppressionSuccess.value = false }, 3000)
        }
    } catch (e: any) {
        suppressionError.value = e.message || 'Failed to update detection'
        setTimeout(() => { suppressionError.value = null }, 5000)
    } finally {
        detectionUpdating.value = false
    }
}

// Confirm disable detection and optionally acknowledge all alerts
async function confirmDisableDetection() {
    if (!detection.value) return

    showDisableDetectionConfirm.value = false

    // Disable the detection
    await performToggleDetection()

    // If user chose to acknowledge all alerts
    if (disableDetectionAckAll.value) {
        try {
            const ruleName = detection.value.title || detection.value.publicId
            const searchFilter = `tags:alert AND rule.name:"${ruleName.replace(/"/g, '\\"')}" AND NOT event.acknowledged:true`
            await bulkAcknowledgeByQuery(searchFilter, true, { timezone: zone.value })
        } catch (e: any) {
            console.error('Failed to acknowledge alerts:', e)
        }
    }
}

// Cancel disable detection
function cancelDisableDetection() {
    showDisableDetectionConfirm.value = false
    disableDetectionAckAll.value = true
}

// Toggle override enabled/disabled
async function toggleOverrideEnabled(index: number) {
    if (!detection.value?.overrides || detectionUpdating.value) return

    overrideActionIndex.value = index
    detectionUpdating.value = true

    try {
        const updatedOverrides = detection.value.overrides.map((o, i) =>
            i === index ? { ...o, isEnabled: !o.isEnabled } : o
        )

        const updatedDetection = await put<Detection>(`/api/detection/`, {
            ...detection.value,
            overrides: updatedOverrides
        })

        if (updatedDetection) {
            detection.value = updatedDetection
            suppressionSuccess.value = true
            setTimeout(() => { suppressionSuccess.value = false }, 3000)
        }
    } catch (e: any) {
        suppressionError.value = e.message || 'Failed to update override'
        setTimeout(() => { suppressionError.value = null }, 5000)
    } finally {
        detectionUpdating.value = false
        overrideActionIndex.value = null
    }
}

// Remove override confirmation state
const showRemoveOverrideConfirm = ref(false)
const pendingRemoveOverrideIndex = ref<number | null>(null)

// Show remove override confirmation
function confirmRemoveOverride(index: number) {
    pendingRemoveOverrideIndex.value = index
    showRemoveOverrideConfirm.value = true
}

// Cancel remove override
function cancelRemoveOverride() {
    showRemoveOverrideConfirm.value = false
    pendingRemoveOverrideIndex.value = null
}

// Remove an override from the detection
async function removeOverride() {
    if (!detection.value?.overrides || pendingRemoveOverrideIndex.value === null || detectionUpdating.value) return

    const index = pendingRemoveOverrideIndex.value
    overrideActionIndex.value = index
    detectionUpdating.value = true
    showRemoveOverrideConfirm.value = false

    try {
        const updatedOverrides = detection.value.overrides.filter((_, i) => i !== index)

        const updatedDetection = await put<Detection>(`/api/detection/`, {
            ...detection.value,
            overrides: updatedOverrides
        })

        if (updatedDetection) {
            detection.value = updatedDetection
            suppressionSuccess.value = true
            setTimeout(() => { suppressionSuccess.value = false }, 3000)
        }
    } catch (e: any) {
        suppressionError.value = e.message || 'Failed to remove override'
        setTimeout(() => { suppressionError.value = null }, 5000)
    } finally {
        detectionUpdating.value = false
        overrideActionIndex.value = null
        pendingRemoveOverrideIndex.value = null
    }
}

// Add suppression dialog state (for adding from full details view)
const showAddSuppressionFromDetails = ref(false)
const newSuppressionTrack = ref<'by_src' | 'by_dst'>('by_src')
const newSuppressionIp = ref('')

// Tuning dialog state
const showTuningDialog = ref(false)
const tuningType = ref<'suppress' | 'threshold'>('suppress')
const tuningTrack = ref<'by_src' | 'by_dst'>('by_src')
const tuningIp = ref('')
const tuningThresholdType = ref<'limit' | 'threshold' | 'both'>('limit')
const tuningCount = ref(5)
const tuningSeconds = ref(60)
const tuningNote = ref('')
const tuningSaving = ref(false)

function resetTuningForm() {
    tuningType.value = 'suppress'
    tuningTrack.value = 'by_src'
    tuningIp.value = ''
    tuningThresholdType.value = 'limit'
    tuningCount.value = 5
    tuningSeconds.value = 60
    tuningNote.value = ''
}

function closeTuningDialog() {
    showTuningDialog.value = false
    resetTuningForm()
}

async function saveTuning() {
    if (!detection.value) return

    tuningSaving.value = true
    try {
        const fullDetection = await get<Detection>(`/api/detection/${detection.value.id}`)
        if (!fullDetection) {
            throw new Error('Failed to fetch detection')
        }

        let newOverride: any = {
            type: tuningType.value,
            isEnabled: true,
            note: tuningNote.value || `Added from Alert Detail`
        }

        if (tuningType.value === 'suppress') {
            if (!tuningIp.value.trim()) {
                suppressionError.value = 'IP address is required'
                tuningSaving.value = false
                return
            }
            newOverride.track = tuningTrack.value
            newOverride.ip = tuningIp.value.trim()
        } else if (tuningType.value === 'threshold') {
            newOverride.thresholdType = tuningThresholdType.value
            newOverride.track = tuningTrack.value
            newOverride.count = tuningCount.value
            newOverride.seconds = tuningSeconds.value
        }

        const updatedOverrides = [...(fullDetection.overrides || []), newOverride]
        const updatedDetection = await put<Detection>(`/api/detection/`, {
            ...fullDetection,
            overrides: updatedOverrides
        })

        if (updatedDetection) {
            detection.value = updatedDetection
        }

        closeTuningDialog()
    } catch (e: any) {
        suppressionError.value = e.message || 'Failed to add tuning override'
    } finally {
        tuningSaving.value = false
    }
}

// Show add suppression dialog
function showAddSuppressionDialog() {
    newSuppressionTrack.value = 'by_src'
    newSuppressionIp.value = ''
    showAddSuppressionFromDetails.value = true
}

// Add suppression from details dialog
async function addSuppressionFromDetails() {
    if (!detection.value || !newSuppressionIp.value.trim()) return

    showAddSuppressionFromDetails.value = false
    await addSuppression(newSuppressionTrack.value, newSuppressionIp.value.trim())
    newSuppressionIp.value = ''
}

// Cancel add suppression from details
function cancelAddSuppressionFromDetails() {
    showAddSuppressionFromDetails.value = false
    newSuppressionIp.value = ''
}

onMounted(async () => {
    loadPreferences()
    await fetchAlert()
})

async function fetchDetection(ruleUuid: string) {
    if (!ruleUuid) return

    detectionLoading.value = true
    detectionError.value = null

    try {
        const response = await fetch(`/api/detection/public/${ruleUuid}`)
        if (response.ok) {
            detection.value = await response.json()
        } else if (response.status === 404) {
            detectionError.value = 'Detection rule not found'
        } else {
            detectionError.value = 'Failed to load detection rule'
        }
    } catch (e: any) {
        detectionError.value = e.message || 'Failed to load detection rule'
    } finally {
        detectionLoading.value = false
    }
}

async function fetchPlaybook() {
    if (!alert.value) return
    playbookState.value = await loadPlaybook(alert.value)
}

// Collect all unique events from guided analysis results
const guidedAnalysisEvents = computed(() => {
    if (!playbookState.value?.questions) return []

    const eventMap = new Map<string, { soc_id: string; question: string }>()

    for (const question of playbookState.value.questions) {
        if (question.queryResults && question.queryResults.length > 0) {
            for (const result of question.queryResults) {
                // Results come as { payload: { ... }, id: "..." } objects
                const payload = result.payload || result
                // The event ID is at result.id (top level), not in payload
                const socId = payload.soc_id || payload._id || result.id
                if (socId && !eventMap.has(socId)) {
                    eventMap.set(socId, {
                        soc_id: socId,
                        question: question.question
                    })
                }
            }
        }
    }

    return Array.from(eventMap.values())
})

function getQuestionColor(question: PlaybookQuestion): string {
    if (question.queryResults && question.queryResults.length > 0) {
        return 'text-green-500'
    }
    return 'text-muted-foreground'
}

function handleToggleQuestion(index: number) {
    if (!alert.value?.soc_id) return
    toggleQuestion(alert.value.soc_id, index)
}

function handleExpandAll() {
    if (!alert.value?.soc_id) return
    expandAllQuestions(alert.value.soc_id)
}

function handleCollapseAll() {
    if (!alert.value?.soc_id) return
    collapseAllQuestions(alert.value.soc_id)
}

function isExpanded(index: number): boolean {
    if (!alert.value?.soc_id) return false
    return isQuestionExpanded(alert.value.soc_id, index)
}

function huntWithQuestion(question: PlaybookQuestion) {
    if (!alert.value) return
    const { query, range } = buildHuntQuery(question, alert.value)
    const routeParams: any = { name: 'hunt', query: { q: query } }
    if (range) {
        routeParams.query.t = range
    }
    window.open(router.resolve(routeParams).href, '_blank')
}

function getVisibleResults(question: PlaybookQuestion, questionIndex: number): any[] {
    // If we've loaded full results, use those
    if (expandedResults.value.has(questionIndex)) {
        return expandedResults.value.get(questionIndex) || []
    }
    // Otherwise return the initial results from the API
    return question.queryResults || []
}

function isResultsExpanded(questionIndex: number): boolean {
    return expandedResults.value.has(questionIndex)
}

function isLoadingResults(questionIndex: number): boolean {
    return loadingResults.value.has(questionIndex)
}

function canLoadMoreResults(questionIndex: number): boolean {
    return hasMoreResults.value.get(questionIndex) === true
}

async function loadAllResults(question: PlaybookQuestion, questionIndex: number) {
    if (!alert.value || loadingResults.value.has(questionIndex)) return

    loadingResults.value.add(questionIndex)

    try {
        const { query, range } = buildHuntQuery(question, alert.value)

        // Use a reasonable default range if none specified
        let timeRange = range
        if (!timeRange) {
            const now = new Date()
            const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000)
            timeRange = `${formatDateForApi(oneDayAgo)} - ${formatDateForApi(now)}`
        }

        const response = await get<any>('/api/events/', {
            query,
            range: timeRange,
            format: '2006/01/02 3:04:05 PM',
            zone: zone.value,
            metricLimit: '10',
            eventLimit: String(RESULTS_PAGE_SIZE)
        })

        if (response?.events) {
            // Transform events to match the expected format
            const results = response.events.map((event: any) => ({
                payload: event.payload || {}
            }))
            expandedResults.value.set(questionIndex, results)
            // If we got exactly PAGE_SIZE results, there might be more
            hasMoreResults.value.set(questionIndex, results.length === RESULTS_PAGE_SIZE)
        }
    } catch (e) {
        console.error('Failed to load full results:', e)
    } finally {
        loadingResults.value.delete(questionIndex)
    }
}

async function loadMoreResults(question: PlaybookQuestion, questionIndex: number) {
    if (!alert.value || loadingResults.value.has(questionIndex)) return

    const existingResults = expandedResults.value.get(questionIndex) || []
    loadingResults.value.add(questionIndex)

    try {
        const { query, range } = buildHuntQuery(question, alert.value)

        // Use a reasonable default range if none specified
        let timeRange = range
        if (!timeRange) {
            const now = new Date()
            const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000)
            timeRange = `${formatDateForApi(oneDayAgo)} - ${formatDateForApi(now)}`
        }

        const response = await get<any>('/api/events/', {
            query,
            range: timeRange,
            format: '2006/01/02 3:04:05 PM',
            zone: zone.value,
            metricLimit: '10',
            eventLimit: String(RESULTS_PAGE_SIZE),
            eventOffset: String(existingResults.length)
        })

        if (response?.events) {
            // Transform events to match the expected format
            const newResults = response.events.map((event: any) => ({
                payload: event.payload || {}
            }))
            // Append to existing results
            expandedResults.value.set(questionIndex, [...existingResults, ...newResults])
            // If we got exactly PAGE_SIZE results, there might be more
            hasMoreResults.value.set(questionIndex, newResults.length === RESULTS_PAGE_SIZE)
        } else {
            // No more results
            hasMoreResults.value.set(questionIndex, false)
        }
    } catch (e) {
        console.error('Failed to load more results:', e)
    } finally {
        loadingResults.value.delete(questionIndex)
    }
}

function collapseResults(questionIndex: number) {
    expandedResults.value.delete(questionIndex)
    hasMoreResults.value.delete(questionIndex)
}

// =============================================================================
// Event Marking Functions for Guided Analysis
// =============================================================================

/**
 * Get the soc_id from a result object
 */
function getResultSocId(result: any): string {
    const payload = result.payload || result
    return payload.soc_id || payload._id || result.id || ''
}

/**
 * Toggle the marked state for an event from guided analysis results
 */
function handleToggleMarked(result: any, question: string) {
    const socId = getResultSocId(result)
    if (socId) {
        toggleMarked(socId, question)
    }
}

/**
 * Check if an event from guided analysis results is marked
 */
function isResultMarked(result: any): boolean {
    const socId = getResultSocId(result)
    return socId ? isMarked(socId) : false
}

/**
 * Get the note for a result
 */
function getResultNote(result: any): string {
    const socId = getResultSocId(result)
    return socId ? getNote(socId) : ''
}

/**
 * Update the note for a result
 */
function handleUpdateNote(result: any, note: string) {
    const socId = getResultSocId(result)
    if (socId) {
        updateNote(socId, note)
    }
}

/**
 * Mark all events from a question's results
 */
function markAllFromQuestion(question: PlaybookQuestion, questionIndex: number) {
    const results = getVisibleResults(question, questionIndex)
    const events = results.map(result => ({
        soc_id: getResultSocId(result),
        question: question.question
    })).filter(e => e.soc_id)
    markAll(events)
}

/**
 * Count marked events from a specific question's results
 */
function countMarkedFromQuestion(question: PlaybookQuestion, questionIndex: number): number {
    const results = getVisibleResults(question, questionIndex)
    return results.filter(result => isResultMarked(result)).length
}

// =============================================================================
// PCAP Functions
// =============================================================================

async function checkExistingPcapJob() {
    if (!alert.value) return

    // Check if this alert has a stored PCAP job ID
    const jobId = alert.value['soc_pcap_job_id']
    if (!jobId) return

    try {
        const response = await fetch(`/api/job?jobId=${jobId}`)
        if (response.ok) {
            pcapJob.value = await response.json()

            // If job is still pending, start polling
            if (pcapJob.value?.status === JOB_STATUS.PENDING) {
                startPcapPolling()
            }
        }
    } catch (e) {
        console.debug('Could not load existing PCAP job:', e)
    }
}

async function createPcapJob() {
    if (!alert.value) return

    const sensorId = alert.value['observer.name']
    if (!sensorId) {
        pcapError.value = 'No sensor information available for this alert'
        return
    }

    pcapLoading.value = true
    pcapError.value = null

    try {
        // Build time window: 2 minutes before and after the event
        const eventTime = new Date(alert.value.soc_timestamp || alert.value['@timestamp'])
        const beginTime = new Date(eventTime.getTime() - 2 * 60 * 1000)
        const endTime = new Date(eventTime.getTime() + 2 * 60 * 1000)

        const filter: any = {
            beginTime: beginTime.toISOString(),
            endTime: endTime.toISOString(),
            parameters: {
                alertId: alert.value.soc_id
            }
        }

        // Add network flow details if available
        const srcIp = alert.value['source.ip']
        const srcPort = alert.value['source.port']
        const dstIp = alert.value['destination.ip']
        const dstPort = alert.value['destination.port']
        const protocol = alert.value['network.transport']

        if (srcIp) filter.srcIp = srcIp
        if (srcPort) filter.srcPort = parseInt(srcPort)
        if (dstIp) filter.dstIp = dstIp
        if (dstPort) filter.dstPort = parseInt(dstPort)
        if (protocol) filter.protocol = protocol.toLowerCase()

        const payload = {
            nodeId: sensorId,
            filter
        }

        const response = await post<PcapJob>('/api/job/', payload)

        if (response) {
            pcapJob.value = response
            // Start polling for job status
            startPcapPolling()

            // Save job ID to the alert for other users
            await saveJobIdToAlert(response.id)
        }
    } catch (e: any) {
        console.error('Failed to create PCAP job:', e)
        pcapError.value = e.message || 'Failed to create PCAP job'
    } finally {
        pcapLoading.value = false
    }
}

async function saveJobIdToAlert(jobId: number) {
    if (!alert.value?.soc_id) return

    try {
        // Build a wide date range to find the alert
        // Add 24 hours buffer to end time to handle timezone differences
        const now = new Date()
        const endTime = new Date(now.getTime() + 24 * 60 * 60 * 1000) // tomorrow
        const oneYearAgo = new Date(now.getTime() - 365 * 24 * 60 * 60 * 1000)
        const dateRange = `${formatDateForApi(oneYearAgo)} - ${formatDateForApi(endTime)}`

        // Update the alert with the PCAP job ID so other users can access it
        // Use _id for the search since that's how alerts are stored in Elasticsearch
        const result = await post('/api/events/ack', {
            searchFilter: `_id:"${alert.value.soc_id}"`,
            eventFilter: { '_id': alert.value.soc_id },
            dateRange,
            dateRangeFormat: '2006/01/02 3:04:05 PM',
            timezone: 'Local',
            acknowledge: false,
            escalate: false,
            updateFields: {
                'soc_pcap_job_id': jobId
            }
        })

        // Update local state
        alert.value['soc_pcap_job_id'] = jobId
    } catch (e) {
        // Still update local state even if persist fails
        alert.value['soc_pcap_job_id'] = jobId
        console.error('Could not persist PCAP job ID to alert:', e)
    }
}

async function refreshPcapJobStatus() {
    if (!pcapJob.value) return

    try {
        const response = await fetch(`/api/job?jobId=${pcapJob.value.id}`)
        if (response.ok) {
            const job = await response.json()
            pcapJob.value = job

            // Stop polling if job is no longer pending
            if (job.status !== JOB_STATUS.PENDING) {
                stopPcapPolling()
            }
        }
    } catch (e) {
        console.error('Failed to refresh PCAP job status:', e)
    }
}

function startPcapPolling() {
    if (pcapPollInterval) return
    pcapPollInterval = setInterval(refreshPcapJobStatus, 5000) // Poll every 5 seconds
}

function stopPcapPolling() {
    if (pcapPollInterval) {
        clearInterval(pcapPollInterval)
        pcapPollInterval = null
    }
}

function downloadPcap() {
    if (!pcapJob.value || pcapJob.value.status !== JOB_STATUS.COMPLETED) return
    window.open(`/api/stream/${pcapJob.value.id}?ext=pcap`, '_blank')
}

function getPcapStatusText(status: number): string {
    switch (status) {
        case JOB_STATUS.PENDING: return 'Processing...'
        case JOB_STATUS.COMPLETED: return 'Ready'
        case JOB_STATUS.INCOMPLETE: return 'Failed'
        case JOB_STATUS.DELETED: return 'Deleted'
        default: return 'Unknown'
    }
}

function getPcapStatusColor(status: number): string {
    switch (status) {
        case JOB_STATUS.PENDING: return 'text-amber-500'
        case JOB_STATUS.COMPLETED: return 'text-green-500'
        case JOB_STATUS.INCOMPLETE: return 'text-red-500'
        case JOB_STATUS.DELETED: return 'text-muted-foreground'
        default: return 'text-muted-foreground'
    }
}

function formatBytes(bytes: number): string {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i]
}

// =============================================================================
// PCAP Packet Viewer Functions
// =============================================================================

async function fetchPackets() {
    if (!pcapJob.value || pcapJob.value.status !== JOB_STATUS.COMPLETED) return

    packetsLoading.value = true
    try {
        const response = await fetch(`/api/packets?jobId=${pcapJob.value.id}&offset=0&count=500&unwrap=false`)
        if (response.ok) {
            packets.value = await response.json()
        } else {
            console.error('Failed to fetch packets')
        }
    } catch (e) {
        console.error('Error fetching packets', e)
    } finally {
        packetsLoading.value = false
    }
}

function togglePacketExpand(packetNumber: number) {
    if (expandedPackets.value.has(packetNumber)) {
        expandedPackets.value.delete(packetNumber)
    } else {
        expandedPackets.value.add(packetNumber)
    }
}

function expandAllPackets() {
    packets.value.forEach(p => expandedPackets.value.add(p.number))
}

function collapseAllPackets() {
    expandedPackets.value.clear()
}

function formatPayload(payloadBase64: string, offset: number): string {
    if (!payloadBase64) return ''
    try {
        const binaryString = atob(payloadBase64)
        const bytes = Uint8Array.from(binaryString, c => c.charCodeAt(0))
        const sliced = bytes.slice(offset)

        if (packetViewMode.value === 'ascii') {
            return new TextDecoder('utf-8').decode(sliced).replace(/[^\x20-\x7E]/g, '.')
        } else {
            // Hex view
            let output = ''
            for (let i = 0; i < sliced.length; i += 16) {
                const chunk = sliced.slice(i, i + 16)

                // Offset
                output += i.toString(16).padStart(4, '0') + '  '

                // Hex
                let hex = ''
                let ascii = ''
                for (let j = 0; j < 16; j++) {
                    if (j < chunk.length) {
                        const byte = chunk[j]
                        hex += byte.toString(16).padStart(2, '0').toUpperCase() + ' '
                        ascii += (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.'
                    } else {
                        hex += '   '
                    }
                    if (j === 7) hex += ' '
                }
                output += hex + ' | ' + ascii + '\n'
            }
            return output
        }
    } catch (e) {
        return 'Error decoding payload'
    }
}

function getPacketTypeColor(type: string): string {
    if (!type) return 'bg-gray-100 text-gray-800'
    if (type.includes('TCP')) return 'bg-blue-100 text-blue-800 border-blue-200'
    if (type.includes('UDP')) return 'bg-green-100 text-green-800 border-green-200'
    if (type.includes('ICMP')) return 'bg-cyan-100 text-cyan-800 border-cyan-200'
    if (type.includes('DNS')) return 'bg-purple-100 text-purple-800 border-purple-200'
    return 'bg-gray-100 text-gray-800 border-gray-200'
}

async function togglePcapDetails() {
    showPcapDetails.value = !showPcapDetails.value
    if (showPcapDetails.value && packets.value.length === 0) {
        await fetchPackets()
    }
}

interface TranscriptSegment {
    text: string
    direction: 'client' | 'server'
    directionChanged: boolean
}

function getAsciiTranscriptSegments(): TranscriptSegment[] {
    if (packets.value.length === 0) return []

    const segments: TranscriptSegment[] = []
    // Use first packet's source as "client" direction
    const clientIp = packets.value[0]?.srcIp
    const clientPort = packets.value[0]?.srcPort
    let lastDirection: 'client' | 'server' | null = null

    for (const packet of packets.value) {
        if (!packet.payload) continue
        try {
            const binaryString = atob(packet.payload)
            const bytes = Uint8Array.from(binaryString, c => c.charCodeAt(0))
            const sliced = bytes.slice(packet.payloadOffset || 0)
            const ascii = new TextDecoder('utf-8').decode(sliced).replace(/[^\x20-\x7E\n\r\t]/g, '.')
            if (ascii.trim()) {
                const isClient = packet.srcIp === clientIp && packet.srcPort === clientPort
                const direction = isClient ? 'client' : 'server'
                const directionChanged = lastDirection !== null && lastDirection !== direction
                segments.push({
                    text: ascii,
                    direction,
                    directionChanged
                })
                lastDirection = direction
            }
        } catch (e) {
            // Skip packets with decode errors
        }
    }
    return segments
}

// Cleanup on unmount
onUnmounted(() => {
    stopPcapPolling()
})

async function fetchAlert() {
    loading.value = true
    error.value = null

    try {
        const now = new Date()
        const oneYearAgo = new Date(now.getTime() - 365 * 24 * 60 * 60 * 1000)
        const wideRange = `${formatDateForApi(oneYearAgo)} - ${formatDateForApi(now)}`

        const query = `_id:"${alertId.value}"`
        const response = await get<any>('/api/events/', {
            query,
            range: wideRange,
            format: '2006/01/02 3:04:05 PM',
            zone: zone.value,
            metricLimit: '0',
            eventLimit: '1'
        })

        if (response?.events?.length > 0) {
            const event = response.events[0]
            const payload = event.payload || {}
            alert.value = {
                soc_id: event.id || payload['soc_id'],
                soc_timestamp: event.timestamp || payload['@timestamp'],
                soc_type: event.type || payload['event.module'],
                soc_source: event.source || payload['observer.name'],
                ...payload
            }

            // Fetch the detection rule if we have a rule.uuid
            const ruleUuid = payload['rule.uuid']
            if (ruleUuid) {
                fetchDetection(ruleUuid)
            }

            // Fetch playbook data
            fetchPlaybook()

            // Initialize PCAP functionality
            checkExistingPcapJob()
        } else {
            error.value = 'Alert not found'
        }
    } catch (e: any) {
        error.value = e.message || 'Failed to load alert'
    } finally {
        loading.value = false
    }
}

function goBack() {
    router.back()
}

async function handleAcknowledge(acknowledge: boolean) {
    if (!alert.value) return
    const success = await acknowledgeEvent(alert.value, acknowledge, { timezone: 'Local' })
    if (success) {
        alert.value['event.acknowledged'] = acknowledge
    }
}

function handleEscalate() {
    if (!alert.value) return
    showEscalateDialog.value = true
}

type EscalationMode = 'none' | 'all' | 'marked' | 'all-highlight-marked'

async function handleEscalateConfirm(data: { title: string; description: string; severity: string; escalationMode: EscalationMode; includePcap: boolean }) {
    if (!alert.value) return

    console.log('[Escalate] Confirm data:', data)
    console.log('[Escalate] pcapJob:', pcapJob.value)
    console.log('[Escalate] markedEvents:', getMarkedEvents())
    console.log('[Escalate] guidedAnalysisEvents:', guidedAnalysisEvents.value)

    try {
        const caseId = await escalateToNewCase(alert.value, {
            title: data.title,
            description: data.description,
            severity: data.severity,
            escalationMode: data.escalationMode,
            allGuidedAnalysisEvents: guidedAnalysisEvents.value,
            markedEvents: getMarkedEvents()
        })

        console.log('[Escalate] Created case:', caseId)

        if (caseId) {
            // Attach PCAP if requested and available
            console.log('[Escalate] Should attach PCAP?', data.includePcap, 'pcapJob.id:', pcapJob.value?.id)
            if (data.includePcap && pcapJob.value?.id) {
                console.log('[Escalate] Attaching PCAP...')
                try {
                    const result = await attachPcapToCase(pcapJob.value.id, caseId, alert.value)
                    console.log('[Escalate] PCAP attach result:', result)
                } catch (pcapError) {
                    // Don't fail the escalation if PCAP attachment fails
                    console.warn('Failed to attach PCAP to case:', pcapError)
                }
            }

            alert.value['event.escalated'] = true
            showEscalateDialog.value = false
            // Clear localStorage for marked events since they've been escalated
            clearStorage()
            router.push({ name: 'case-detail', params: { id: caseId } })
        }
    } catch (e: any) {
        console.error('Escalation failed:', e)
        error.value = e.message || 'Failed to escalate alert to case'
    } finally {
        escalateDialogRef.value?.setLoading(false)
    }
}

function handleInvestigate() {
    if (!alert.value) return
    const prompt = generateInvestigationPrompt(alert.value)
    openNewChatWithPrompt(prompt)
}

function drillIntoHunt() {
    if (!alert.value) return
    router.push({ name: 'hunt', query: { q: `_id:"${alert.value.soc_id}"` } })
}

async function copyToClipboard(text: string) {
    await navigator.clipboard.writeText(text)
    copied.value = true
    setTimeout(() => copied.value = false, 2000)
}

function getField(field: string, defaultValue = '-'): string {
    if (!alert.value) return defaultValue
    const value = alert.value[field]
    if (value === null || value === undefined || value === '') return defaultValue
    return String(value)
}

// Get all fields for raw display
const allFields = computed(() => {
    if (!alert.value) return []
    const excluded = ['_row_idx_', '_isSelected', '_aiInvestigated', '_aiInvestigationData']
    return Object.entries(alert.value)
        .filter(([key, value]) => !excluded.includes(key) && !key.startsWith('_') && value !== null && value !== undefined && value !== '')
        .sort(([a], [b]) => a.localeCompare(b))
})

// Syntax highlighting for detection rule content
// Uses custom CSS classes defined in <style> block to work with Tailwind
const highlightedContent = computed(() => {
    if (!detection.value?.content) return ''
    const content = detection.value.content
    const engine = detection.value.engine?.toLowerCase()
    const language = detection.value.language?.toLowerCase()

    // Escape HTML first
    const escape = (str: string) => str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')

    const escaped = escape(content)

    if (language === 'sigma' || engine === 'elastalert') {
        // YAML syntax highlighting
        return escaped
            // Comments
            .replace(/(#.*)$/gm, '<span class="hl-comment">$1</span>')
            // Keys (word followed by colon)
            .replace(/^(\s*)([a-zA-Z_][\w-]*)(:)/gm, '$1<span class="hl-keyword">$2</span>$3')
            // Strings in quotes
            .replace(/(&quot;[^&]*&quot;|'[^']*')/g, '<span class="hl-string">$1</span>')
            // Numbers
            .replace(/\b(\d+)\b/g, '<span class="hl-number">$1</span>')
            // Boolean/null
            .replace(/\b(true|false|null)\b/gi, '<span class="hl-operator">$1</span>')
    } else if (language === 'suricata' || engine === 'suricata') {
        // Suricata rule syntax highlighting
        return escaped
            // Action keywords
            .replace(/^(alert|drop|pass|reject|log)\b/gm, '<span class="hl-action">$1</span>')
            // Protocol
            .replace(/\b(tcp|udp|icmp|ip|http|dns|tls|ssh|ftp|smtp)\b/gi, '<span class="hl-protocol">$1</span>')
            // Variables
            .replace(/(\$[A-Z_]+)/g, '<span class="hl-variable">$1</span>')
            // Direction arrows
            .replace(/(-&gt;|&lt;&gt;)/g, '<span class="hl-action">$1</span>')
            // Option keywords
            .replace(/\b(msg|content|nocase|sid|rev|classtype|reference|flow|pcre|metadata|threshold|priority|gid|offset|depth|distance|within|fast_pattern|flowbits|tag|detection_filter):/g, '<span class="hl-option">$1</span>:')
            // Strings in quotes
            .replace(/(&quot;[^&]*&quot;)/g, '<span class="hl-string">$1</span>')
            // Numbers
            .replace(/\b(\d+)\b/g, '<span class="hl-number">$1</span>')
    } else if (language === 'yara' || engine === 'strelka') {
        // YARA syntax highlighting
        return escaped
            // Keywords
            .replace(/\b(rule|strings|condition|meta|import|include|private|global)\b/g, '<span class="hl-keyword">$1</span>')
            // String identifiers
            .replace(/(\$[a-zA-Z_]\w*)/g, '<span class="hl-variable">$1</span>')
            // Comments
            .replace(/(\/\/.*)$/gm, '<span class="hl-comment">$1</span>')
            .replace(/(\/\*[\s\S]*?\*\/)/g, '<span class="hl-comment">$1</span>')
            // Strings in quotes
            .replace(/(&quot;[^&]*&quot;)/g, '<span class="hl-string">$1</span>')
            // Operators
            .replace(/\b(and|or|not|all|any|of|them|at|in|for)\b/g, '<span class="hl-operator">$1</span>')
            // Numbers
            .replace(/\b(0x[0-9a-fA-F]+|\d+)\b/g, '<span class="hl-number">$1</span>')
    }

    return escaped
})
</script>

<template>
    <div class="animate-in fade-in duration-500">
        <!-- Header -->
        <div class="flex items-center gap-4 mb-6">
            <button
                @click="goBack"
                class="p-2 hover:bg-muted rounded-lg transition-colors"
            >
                <ArrowLeft class="h-5 w-5" />
            </button>
            <div class="flex-1">
                <h1 class="text-2xl font-bold">Alert Details</h1>
            </div>
            <!-- Settings Button -->
            <div class="relative">
                <button
                    @click="showSettingsPanel = !showSettingsPanel"
                    class="p-2 hover:bg-muted rounded-lg transition-colors text-muted-foreground hover:text-foreground"
                    title="Display Settings"
                >
                    <Settings class="h-5 w-5" />
                </button>
                <!-- Settings Panel -->
                <div
                    v-if="showSettingsPanel"
                    class="absolute right-0 top-full mt-2 w-72 bg-popover border border-border rounded-lg shadow-xl z-50"
                >
                    <div class="p-3 border-b border-border">
                        <h3 class="font-semibold text-sm">Display Settings</h3>
                        <p class="text-xs text-muted-foreground mt-0.5">Auto-expand sections on page load</p>
                    </div>
                    <div class="p-2 space-y-1">
                        <label class="flex items-center gap-3 px-2 py-2 hover:bg-muted rounded-md cursor-pointer transition-colors">
                            <input
                                type="checkbox"
                                :checked="preferences.autoExpandDetectionDetails"
                                @change="togglePreference('autoExpandDetectionDetails')"
                                class="w-4 h-4 rounded border-border text-primary focus:ring-primary"
                            />
                            <span class="text-sm">Detection Details</span>
                        </label>
                        <label class="flex items-center gap-3 px-2 py-2 hover:bg-muted rounded-md cursor-pointer transition-colors">
                            <input
                                type="checkbox"
                                :checked="preferences.autoExpandGuidedAnalysis"
                                @change="togglePreference('autoExpandGuidedAnalysis')"
                                class="w-4 h-4 rounded border-border text-primary focus:ring-primary"
                            />
                            <span class="text-sm">Guided Analysis</span>
                        </label>
                        <label class="flex items-center gap-3 px-2 py-2 hover:bg-muted rounded-md cursor-pointer transition-colors">
                            <input
                                type="checkbox"
                                :checked="preferences.autoExpandAllFields"
                                @change="togglePreference('autoExpandAllFields')"
                                class="w-4 h-4 rounded border-border text-primary focus:ring-primary"
                            />
                            <span class="text-sm">All Fields</span>
                        </label>
                    </div>
                    <div class="border-t border-border px-3 py-2">
                        <div class="text-xs text-muted-foreground mb-2">All Fields Display</div>
                        <div class="flex items-center gap-1 bg-muted rounded-lg p-1">
                            <button
                                @click="setAllFieldsDisplayMode('list')"
                                :class="cn('flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-medium transition-colors', preferences.allFieldsDisplayMode === 'list' ? 'bg-background text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground')"
                            >
                                <List class="h-3.5 w-3.5" />
                                List
                            </button>
                            <button
                                @click="setAllFieldsDisplayMode('grid')"
                                :class="cn('flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-medium transition-colors', preferences.allFieldsDisplayMode === 'grid' ? 'bg-background text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground')"
                            >
                                <LayoutGrid class="h-3.5 w-3.5" />
                                Grid
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <!-- Settings Panel Backdrop -->
        <div
            v-if="showSettingsPanel"
            class="fixed inset-0 z-40"
            @click="showSettingsPanel = false"
        ></div>

        <!-- Loading State -->
        <div v-if="loading" class="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
            <div v-for="i in 6" :key="i" class="rounded-xl border border-border bg-card p-6 animate-pulse">
                <div class="h-4 w-24 bg-muted rounded mb-4"></div>
                <div class="h-6 w-full bg-muted rounded"></div>
            </div>
        </div>

        <!-- Error State -->
        <div v-else-if="error" class="rounded-xl border border-destructive/50 bg-destructive/10 p-12 text-center">
            <AlertTriangle class="h-16 w-16 text-destructive mx-auto mb-4" />
            <p class="text-destructive font-semibold text-xl">{{ error }}</p>
            <button
                @click="fetchAlert"
                class="mt-6 px-6 py-2 bg-destructive text-destructive-foreground rounded-lg hover:bg-destructive/90"
            >
                Retry
            </button>
        </div>

        <!-- Alert Content -->
        <template v-else-if="alert">
            <!-- Alert Overview Card (Consolidated) -->
            <div class="rounded-xl border border-border bg-card overflow-hidden mb-6">
                <!-- Header: Rule Name + Actions -->
                <div class="p-5 border-b border-border">
                    <div class="flex flex-col lg:flex-row lg:items-start lg:justify-between gap-4">
                        <div class="flex-1 min-w-0">
                            <div class="flex items-center gap-2 mb-1">
                                <Shield class="h-5 w-5 text-primary flex-shrink-0" />
                                <span class="text-xs text-muted-foreground uppercase tracking-wider">Detection</span>
                            </div>
                            <h2 class="text-lg font-bold leading-tight" :title="getField('rule.name', 'Unknown Rule')">
                                {{ getField('rule.name', 'Unknown Rule') }}
                            </h2>
                        </div>
                        <div class="flex flex-wrap gap-2 flex-shrink-0">
                            <button
                                v-if="!alert['event.acknowledged']"
                                @click="handleAcknowledge(true)"
                                :disabled="actionLoading"
                                class="inline-flex items-center gap-1.5 px-3 py-1.5 bg-green-500 text-white rounded-lg hover:bg-green-600 transition-colors text-sm font-medium"
                            >
                                <Check class="h-3.5 w-3.5" />
                                Ack
                            </button>
                            <button
                                v-else
                                @click="handleAcknowledge(false)"
                                :disabled="actionLoading"
                                class="inline-flex items-center gap-1.5 px-3 py-1.5 bg-amber-500 text-white rounded-lg hover:bg-amber-600 transition-colors text-sm font-medium"
                            >
                                <X class="h-3.5 w-3.5" />
                                Unack
                            </button>
                            <button
                                @click="handleEscalate"
                                :disabled="actionLoading"
                                class="inline-flex items-center gap-1.5 px-3 py-1.5 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition-colors text-sm font-medium"
                            >
                                <Briefcase class="h-3.5 w-3.5" />
                                Escalate
                            </button>
                            <button
                                @click="handleInvestigate"
                                :disabled="actionLoading"
                                class="inline-flex items-center gap-1.5 px-3 py-1.5 bg-purple-500 text-white rounded-lg hover:bg-purple-600 transition-colors text-sm font-medium"
                            >
                                <Sparkles class="h-3.5 w-3.5" />
                                AI
                            </button>
                            <button
                                @click="drillIntoHunt"
                                class="inline-flex items-center gap-1.5 px-3 py-1.5 bg-muted text-foreground rounded-lg hover:bg-muted/80 transition-colors text-sm font-medium"
                            >
                                <ExternalLink class="h-3.5 w-3.5" />
                                Hunt
                            </button>
                        </div>
                    </div>
                </div>

                <!-- Meta Row: Severity, Status, Timestamp, Module -->
                <div class="px-5 py-3 bg-muted/20 border-b border-border">
                    <div class="flex items-center flex-wrap gap-x-6 gap-y-2 text-sm">
                        <!-- Severity -->
                        <div class="flex items-center gap-2">
                            <AlertTriangle class="h-4 w-4 text-muted-foreground" />
                            <span :class="cn('px-2 py-0.5 rounded text-xs font-bold', getSeverityStyles(getField('event.severity_label', 'unknown')))">
                                {{ getField('event.severity_label', 'unknown').toUpperCase() }}
                            </span>
                        </div>

                        <!-- Status -->
                        <div class="flex items-center gap-2">
                            <Activity class="h-4 w-4 text-muted-foreground" />
                            <span v-if="alert['event.acknowledged']" class="text-green-500 font-medium flex items-center gap-1">
                                <CheckCircle class="h-3.5 w-3.5" />
                                Acknowledged
                            </span>
                            <span v-else class="text-muted-foreground font-medium">Unacknowledged</span>
                        </div>

                        <!-- Timestamp -->
                        <div class="flex items-center gap-2">
                            <Clock class="h-4 w-4 text-muted-foreground" />
                            <span class="font-medium">{{ formatDate(alert.soc_timestamp || alert['@timestamp']) }}</span>
                        </div>

                        <!-- Module -->
                        <div class="flex items-center gap-2">
                            <Server class="h-4 w-4 text-muted-foreground" />
                            <span class="font-mono">{{ getField('event.module') }}</span>
                        </div>
                    </div>
                </div>

                <!-- Network Row -->
                <div class="px-5 py-3 border-b border-border">
                    <div class="flex items-center flex-wrap gap-x-6 gap-y-2 text-sm">
                        <div class="flex items-center gap-2">
                            <Network class="h-4 w-4 text-muted-foreground" />
                            <button
                                v-if="getField('source.ip') !== '-'"
                                @click="showActionMenu($event, 'source.ip', getField('source.ip'))"
                                class="font-mono hover:bg-muted px-1.5 py-0.5 rounded transition-colors cursor-pointer"
                                title="Click for actions"
                            >
                                {{ getField('source.ip') }}<span v-if="getField('source.port') !== '-'" class="text-muted-foreground">:{{ getField('source.port') }}</span>
                            </button>
                            <span v-else class="font-mono">-</span>
                            <span class="text-primary font-bold">→</span>
                            <button
                                v-if="getField('destination.ip') !== '-'"
                                @click="showActionMenu($event, 'destination.ip', getField('destination.ip'))"
                                class="font-mono hover:bg-muted px-1.5 py-0.5 rounded transition-colors cursor-pointer"
                                title="Click for actions"
                            >
                                {{ getField('destination.ip') }}<span v-if="getField('destination.port') !== '-'" class="text-muted-foreground">:{{ getField('destination.port') }}</span>
                            </button>
                            <span v-else class="font-mono">-</span>
                        </div>

                        <div v-if="getField('network.transport') !== '-'" class="flex items-center gap-1">
                            <span class="text-muted-foreground">Protocol:</span>
                            <span class="font-mono uppercase font-medium">{{ getField('network.transport') }}</span>
                        </div>

                        <div v-if="getField('network.bytes') !== '-'" class="flex items-center gap-1">
                            <span class="text-muted-foreground">Bytes:</span>
                            <span class="font-mono">{{ getField('network.bytes') }}</span>
                        </div>

                        <div v-if="getField('network.direction') !== '-'" class="flex items-center gap-1">
                            <span class="text-muted-foreground">Direction:</span>
                            <span>{{ getField('network.direction') }}</span>
                        </div>
                    </div>
                </div>

                <!-- Context Row: Observer, Dataset, Event ID -->
                <div class="px-5 py-3">
                    <div class="flex items-center flex-wrap gap-x-6 gap-y-2 text-sm">
                        <div v-if="getField('observer.name') !== '-'" class="flex items-center gap-2">
                            <MapPin class="h-4 w-4 text-muted-foreground" />
                            <span class="text-muted-foreground">Observer:</span>
                            <span class="font-medium">{{ getField('observer.name') }}</span>
                        </div>

                        <div v-if="getField('event.dataset') !== '-'" class="flex items-center gap-2">
                            <FileText class="h-4 w-4 text-muted-foreground" />
                            <span class="text-muted-foreground">Dataset:</span>
                            <span class="font-mono">{{ getField('event.dataset') }}</span>
                        </div>

                        <div class="flex items-center gap-2">
                            <Hash class="h-4 w-4 text-muted-foreground" />
                            <span class="text-muted-foreground">ID:</span>
                            <span class="font-mono text-xs">{{ alert.soc_id }}</span>
                            <button
                                @click="copyToClipboard(alert.soc_id)"
                                class="p-1 hover:bg-muted rounded transition-colors text-muted-foreground hover:text-foreground"
                            >
                                <Copy class="h-3.5 w-3.5" />
                            </button>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Detection Rule Content -->
            <div v-if="alert['rule.uuid']" class="rounded-xl border border-border bg-card overflow-hidden mb-6">
                <button
                    @click="showRuleContent = !showRuleContent"
                    class="w-full px-6 py-4 flex items-center justify-between hover:bg-muted/30 transition-colors"
                >
                    <div class="flex items-center gap-2">
                        <Code class="h-4 w-4 text-muted-foreground" />
                        <span class="font-semibold">Detection Details</span>
                    </div>
                    <div class="flex items-center gap-2">
                        <Loader2 v-if="detectionLoading" class="h-4 w-4 animate-spin text-muted-foreground" />
                        <ChevronDown :class="cn('h-5 w-5 text-muted-foreground transition-transform', showRuleContent && 'rotate-180')" />
                    </div>
                </button>

                <div v-if="showRuleContent" class="border-t border-border">
                    <!-- Loading State -->
                    <div v-if="detectionLoading" class="p-6 text-center text-muted-foreground">
                        <Loader2 class="h-6 w-6 animate-spin mx-auto mb-2" />
                        Loading detection rule...
                    </div>

                    <!-- Error State -->
                    <div v-else-if="detectionError" class="p-6 text-center text-muted-foreground">
                        <AlertTriangle class="h-6 w-6 mx-auto mb-2 text-amber-500" />
                        {{ detectionError }}
                    </div>

                    <!-- Detection Content -->
                    <div v-else-if="detection" class="divide-y divide-border">
                        <!-- Detection Metadata Bar with View Toggle -->
                        <div class="px-6 py-3 bg-muted/20 flex flex-wrap items-center gap-x-6 gap-y-2 text-sm">
                            <div class="flex items-center gap-1">
                                <span class="text-muted-foreground">Engine:</span>
                                <span class="font-mono font-medium">{{ detection.engine }}</span>
                            </div>
                            <div v-if="detection.author && !showFullDetection" class="flex items-center gap-1">
                                <span class="text-muted-foreground">Author:</span>
                                <span>{{ detection.author }}</span>
                            </div>
                            <div v-if="detection.category && !showFullDetection" class="flex items-center gap-1">
                                <span class="text-muted-foreground">Category:</span>
                                <span>{{ detection.category }}</span>
                            </div>
                            <div v-if="detection.ruleset && !showFullDetection" class="flex items-center gap-1">
                                <span class="text-muted-foreground">Ruleset:</span>
                                <span>{{ detection.ruleset }}</span>
                            </div>

                            <!-- View Toggle and Link -->
                            <div class="ml-auto flex items-center gap-4">
                                <!-- View Toggle -->
                                <div class="flex items-center gap-2 border border-border rounded-lg p-0.5 bg-background">
                                    <button
                                        @click.stop="showFullDetection = false"
                                        :class="cn(
                                            'px-2.5 py-1 text-xs font-medium rounded-md transition-colors flex items-center gap-1.5',
                                            !showFullDetection ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:text-foreground'
                                        )"
                                        title="Show signature only"
                                    >
                                        <Code class="h-3.5 w-3.5" />
                                        Signature
                                    </button>
                                    <button
                                        @click.stop="showFullDetection = true"
                                        :class="cn(
                                            'px-2.5 py-1 text-xs font-medium rounded-md transition-colors flex items-center gap-1.5',
                                            showFullDetection ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:text-foreground'
                                        )"
                                        title="Show full detection details"
                                    >
                                        <FileText class="h-3.5 w-3.5" />
                                        Full Details
                                    </button>
                                </div>

                                <router-link
                                    :to="{ name: 'detection-detail', params: { id: detection.id } }"
                                    class="text-primary hover:underline flex items-center gap-1"
                                    @click.stop
                                >
                                    View Detection
                                    <ExternalLink class="h-3 w-3" />
                                </router-link>
                            </div>
                        </div>

                        <!-- Full Detection Details View -->
                        <div v-if="showFullDetection" class="divide-y divide-border">
                            <!-- AI Summary Section -->
                            <div class="px-6 py-4">
                                <div class="flex items-center gap-2 mb-2">
                                    <Bot class="h-4 w-4 text-primary" />
                                    <span class="text-muted-foreground text-xs uppercase tracking-wide">AI Summary</span>
                                </div>
                                <p v-if="detection.aiSummary" class="text-sm text-muted-foreground leading-relaxed">{{ detection.aiSummary }}</p>
                                <p v-else class="text-sm text-muted-foreground/60 italic">This rule doesn't have an AI Summary</p>
                            </div>

                            <!-- Description Section -->
                            <div v-if="detection.description" class="px-6 py-4">
                                <div class="flex items-center gap-2 mb-2">
                                    <BookOpen class="h-4 w-4 text-primary" />
                                    <span class="text-muted-foreground text-xs uppercase tracking-wide">Description</span>
                                </div>
                                <p class="text-sm text-muted-foreground leading-relaxed">{{ detection.description }}</p>
                            </div>

                            <!-- Metadata Section -->
                            <div class="px-6 py-4">
                                <div class="flex items-center gap-2 mb-3">
                                    <Shield class="h-4 w-4 text-primary" />
                                    <span class="text-muted-foreground text-xs uppercase tracking-wide">Metadata</span>
                                </div>
                                <div class="grid grid-cols-2 md:grid-cols-4 gap-x-6 gap-y-3 text-sm">
                                    <div class="flex items-center justify-between py-1.5 border-b border-border">
                                        <span class="text-muted-foreground">Status</span>
                                        <div class="flex items-center gap-2">
                                            <span :class="detection.isEnabled ? 'text-green-500' : 'text-amber-500'" class="font-medium flex items-center gap-1">
                                                <CheckCircle v-if="detection.isEnabled" class="h-3.5 w-3.5" />
                                                <X v-else class="h-3.5 w-3.5" />
                                                {{ detection.isEnabled ? 'Active' : 'Disabled' }}
                                            </span>
                                            <button
                                                @click="toggleDetectionEnabled"
                                                :disabled="detectionUpdating"
                                                :class="cn(
                                                    'relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-primary focus:ring-offset-2 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed',
                                                    detection.isEnabled ? 'bg-green-500' : 'bg-muted'
                                                )"
                                                :title="detection.isEnabled ? 'Disable detection' : 'Enable detection'"
                                            >
                                                <span
                                                    :class="cn(
                                                        'inline-block h-4 w-4 transform rounded-full bg-white shadow-sm transition-transform',
                                                        detection.isEnabled ? 'translate-x-6' : 'translate-x-1'
                                                    )"
                                                />
                                                <Loader2 v-if="detectionUpdating && overrideActionIndex === null" class="absolute inset-0 m-auto h-3 w-3 animate-spin text-white" />
                                            </button>
                                        </div>
                                    </div>
                                    <div class="flex items-center justify-between py-1.5 border-b border-border">
                                        <span class="text-muted-foreground">Severity</span>
                                        <span
                                            :class="cn(
                                                'inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium',
                                                getSeverityStyles(detection.severity)?.badge || 'bg-muted text-muted-foreground'
                                            )"
                                        >
                                            {{ detection.severity || 'Unknown' }}
                                        </span>
                                    </div>
                                    <div v-if="detection.author" class="flex items-center justify-between py-1.5 border-b border-border">
                                        <span class="text-muted-foreground">Author</span>
                                        <span class="font-medium text-foreground truncate ml-2">{{ detection.author }}</span>
                                    </div>
                                    <div v-if="detection.category" class="flex items-center justify-between py-1.5 border-b border-border">
                                        <span class="text-muted-foreground">Category</span>
                                        <span class="font-medium text-foreground truncate ml-2">{{ detection.category }}</span>
                                    </div>
                                    <div v-if="detection.publicId" class="flex items-center justify-between py-1.5 border-b border-border">
                                        <span class="text-muted-foreground">Public ID</span>
                                        <span class="font-mono text-foreground text-xs truncate ml-2">{{ detection.publicId }}</span>
                                    </div>
                                    <div v-if="detection.ruleset" class="flex items-center justify-between py-1.5 border-b border-border">
                                        <span class="text-muted-foreground">Ruleset</span>
                                        <span class="font-medium text-foreground truncate ml-2">{{ detection.ruleset }}</span>
                                    </div>
                                    <div v-if="detection.language" class="flex items-center justify-between py-1.5 border-b border-border">
                                        <span class="text-muted-foreground">Language</span>
                                        <span class="font-mono text-foreground truncate ml-2">{{ detection.language }}</span>
                                    </div>
                                    <div v-if="detection.overrides?.length" class="flex items-center justify-between py-1.5 border-b border-border">
                                        <span class="text-muted-foreground">Overrides</span>
                                        <span class="font-medium text-foreground">{{ detection.overrides.length }} active</span>
                                    </div>
                                </div>
                            </div>

                            <!-- Tags -->
                            <div v-if="detection.tags && detection.tags.length > 0" class="px-6 py-4">
                                <div class="flex items-center gap-2 mb-2">
                                    <Hash class="h-4 w-4 text-primary" />
                                    <span class="text-muted-foreground text-xs uppercase tracking-wide">Tags</span>
                                </div>
                                <div class="flex flex-wrap gap-1.5">
                                    <span
                                        v-for="tag in detection.tags"
                                        :key="tag"
                                        class="px-2 py-0.5 bg-muted text-muted-foreground rounded text-xs font-medium"
                                    >
                                        {{ tag }}
                                    </span>
                                </div>
                            </div>

                            <!-- Rule Content Section -->
                            <div class="relative">
                                <div class="px-6 pt-4 pb-2 flex items-center justify-between">
                                    <div class="flex items-center gap-2">
                                        <Code class="h-4 w-4 text-primary" />
                                        <span class="text-muted-foreground text-xs uppercase tracking-wide">Rule Content</span>
                                    </div>
                                    <button
                                        @click="copyToClipboard(detection.content)"
                                        class="text-xs font-medium px-2 py-1 bg-primary/10 text-primary rounded hover:bg-primary/20 transition-colors"
                                    >
                                        Copy
                                    </button>
                                </div>
                                <pre class="rule-content font-mono text-sm leading-relaxed bg-card text-foreground select-text selection:bg-primary/20 max-h-64 overflow-y-auto overflow-x-hidden px-6 pb-4"><code v-html="highlightedContent"></code></pre>
                            </div>

                            <!-- Overrides Section -->
                            <div class="px-6 py-4">
                                <div class="flex items-center justify-between mb-3">
                                    <div class="flex items-center gap-2">
                                        <Settings class="h-4 w-4 text-primary" />
                                        <span class="text-muted-foreground text-xs uppercase tracking-wide">
                                            Overrides {{ detection.overrides?.length ? `(${detection.overrides.length})` : '' }}
                                        </span>
                                    </div>
                                    <button
                                        v-if="canAddSuppression"
                                        @click="showTuningDialog = true"
                                        class="flex items-center gap-1.5 px-2 py-1 text-xs font-medium rounded-md bg-primary/10 text-primary hover:bg-primary/20 transition-colors"
                                    >
                                        <Plus class="h-3.5 w-3.5" />
                                        Tuning
                                    </button>
                                </div>

                                <!-- Override List -->
                                <div v-if="detection.overrides && detection.overrides.length > 0" class="space-y-2">
                                    <div
                                        v-for="(override, index) in detection.overrides"
                                        :key="index"
                                        :class="cn(
                                            'px-3 py-2 rounded-lg border text-sm',
                                            override.isEnabled ? 'bg-amber-500/10 border-amber-500/30' : 'bg-muted/50 border-border'
                                        )"
                                    >
                                        <div class="flex items-center justify-between gap-2">
                                            <div class="flex items-center gap-2">
                                                <span :class="cn(
                                                    'px-1.5 py-0.5 rounded text-xs font-medium',
                                                    override.isEnabled ? 'bg-green-500/10 text-green-500' : 'bg-muted text-muted-foreground'
                                                )">
                                                    {{ override.isEnabled ? 'Enabled' : 'Disabled' }}
                                                </span>
                                                <span :class="cn(
                                                    'px-1.5 py-0.5 rounded text-xs font-medium',
                                                    override.type === 'suppress' ? 'bg-amber-500/20 text-amber-600 dark:text-amber-400' :
                                                    override.type === 'threshold' ? 'bg-blue-500/20 text-blue-600 dark:text-blue-400' :
                                                    override.type === 'modify' ? 'bg-purple-500/20 text-purple-600 dark:text-purple-400' :
                                                    'bg-primary/10 text-primary'
                                                )">
                                                    {{ override.type }}
                                                </span>
                                                <span v-if="override.track" class="text-xs text-muted-foreground font-mono">{{ override.track }}</span>
                                                <span v-if="override.ip" class="text-xs text-muted-foreground font-mono">{{ override.ip }}</span>
                                            </div>
                                            <div class="flex items-center gap-1">
                                                <Loader2 v-if="overrideActionIndex === index" class="h-4 w-4 animate-spin text-muted-foreground" />
                                                <template v-else>
                                                    <button
                                                        @click="toggleOverrideEnabled(index)"
                                                        :disabled="detectionUpdating"
                                                        :class="cn(
                                                            'p-1 rounded-md transition-colors',
                                                            override.isEnabled
                                                                ? 'text-green-600 dark:text-green-400 hover:bg-green-500/10'
                                                                : 'text-muted-foreground hover:bg-muted'
                                                        )"
                                                        :title="override.isEnabled ? 'Disable override' : 'Enable override'"
                                                    >
                                                        <Eye v-if="override.isEnabled" class="h-3.5 w-3.5" />
                                                        <EyeOff v-else class="h-3.5 w-3.5" />
                                                    </button>
                                                    <button
                                                        @click="confirmRemoveOverride(index)"
                                                        :disabled="detectionUpdating"
                                                        class="p-1 rounded-md text-muted-foreground hover:text-destructive hover:bg-destructive/10 transition-colors"
                                                        title="Remove override"
                                                    >
                                                        <Trash2 class="h-3.5 w-3.5" />
                                                    </button>
                                                </template>
                                            </div>
                                        </div>
                                        <div v-if="override.note" class="text-xs text-muted-foreground mt-1 italic">
                                            {{ override.note }}
                                        </div>
                                    </div>
                                </div>

                                <!-- No Overrides -->
                                <div v-else class="text-sm text-muted-foreground py-4 text-center border border-dashed border-border rounded-lg">
                                    No overrides configured
                                </div>
                            </div>
                        </div>

                        <!-- Signature View Only: AI Summary + Rule Content -->
                        <template v-if="!showFullDetection">
                            <!-- AI Summary -->
                            <div class="px-6 py-4 border-b border-border">
                                <div class="flex items-center gap-2 mb-2">
                                    <Bot class="h-4 w-4 text-primary" />
                                    <span class="text-muted-foreground text-xs uppercase tracking-wide">AI Summary</span>
                                </div>
                                <p v-if="detection.aiSummary" class="text-sm text-muted-foreground leading-relaxed">{{ detection.aiSummary }}</p>
                                <p v-else class="text-sm text-muted-foreground/60 italic">This rule doesn't have an AI Summary</p>
                            </div>

                            <!-- Rule Content / Signature -->
                            <div class="relative">
                                <button
                                    @click="copyToClipboard(detection.content)"
                                    class="absolute top-3 right-3 p-2 bg-muted hover:bg-muted/80 rounded-md transition-colors text-muted-foreground hover:text-foreground z-10"
                                    title="Copy rule content"
                                >
                                    <Copy class="h-4 w-4" />
                                </button>
                                <pre class="rule-content font-mono text-sm leading-relaxed bg-card text-foreground select-text selection:bg-primary/20 max-h-96 overflow-y-auto overflow-x-hidden p-6"><code v-html="highlightedContent"></code></pre>
                            </div>
                        </template>
                    </div>

                    <!-- No Detection Found -->
                    <div v-else class="p-6 text-center text-muted-foreground">
                        <Shield class="h-6 w-6 mx-auto mb-2 opacity-50" />
                        Detection rule content not available
                    </div>
                </div>
            </div>

            <!-- Guided Analysis Card -->
            <div class="rounded-xl border border-border bg-card overflow-hidden mb-6">
                <button
                    @click="showGuidedAnalysis = !showGuidedAnalysis"
                    class="w-full px-6 py-4 flex items-center justify-between hover:bg-muted/30 transition-colors"
                >
                    <div class="flex items-center gap-2">
                        <BookOpen class="h-4 w-4 text-muted-foreground" />
                        <span class="font-semibold">Guided Analysis</span>
                        <span v-if="playbookState?.questions?.length" class="text-sm text-muted-foreground">
                            ({{ playbookState.questions.length }} questions)
                        </span>
                    </div>
                    <div class="flex items-center gap-2">
                        <Loader2 v-if="playbookState?.loading" class="h-4 w-4 animate-spin text-muted-foreground" />
                        <template v-if="showGuidedAnalysis && playbookState?.questions?.length">
                            <button
                                @click.stop="handleCollapseAll"
                                class="p-1 hover:bg-muted rounded transition-colors text-muted-foreground hover:text-foreground"
                                title="Collapse all"
                            >
                                <Minimize2 class="h-4 w-4" />
                            </button>
                            <button
                                @click.stop="handleExpandAll"
                                class="p-1 hover:bg-muted rounded transition-colors text-muted-foreground hover:text-foreground"
                                title="Expand all"
                            >
                                <Maximize2 class="h-4 w-4" />
                            </button>
                        </template>
                        <ChevronDown :class="cn('h-5 w-5 text-muted-foreground transition-transform', showGuidedAnalysis && 'rotate-180')" />
                    </div>
                </button>

                <div v-if="showGuidedAnalysis" class="border-t border-border">
                    <!-- Loading State -->
                    <div v-if="playbookState?.loading" class="p-6 text-center text-muted-foreground">
                        <Loader2 class="h-6 w-6 animate-spin mx-auto mb-2" />
                        Loading playbook questions...
                    </div>

                    <!-- Error State -->
                    <div v-else-if="playbookState?.error" class="p-6 text-center text-muted-foreground">
                        <AlertTriangle class="h-6 w-6 mx-auto mb-2 text-amber-500" />
                        Failed to load playbook questions
                    </div>

                    <!-- No Playbook -->
                    <div v-else-if="!playbookState || !playbookState.questions?.length" class="p-6 text-center text-muted-foreground">
                        <BookOpen class="h-6 w-6 mx-auto mb-2 opacity-50" />
                        No guided analysis questions available for this alert
                    </div>

                    <!-- Questions List -->
                    <div v-else class="divide-y divide-border">
                        <!-- AI Warning Banner -->
                        <div class="px-6 py-3 bg-amber-500/10 border-b border-amber-500/20 flex items-center gap-3 text-sm">
                            <FlaskConical class="h-4 w-4 text-amber-500 flex-shrink-0" />
                            <span class="text-amber-600 dark:text-amber-400">
                                Playbook questions are AI-generated and may not be accurate. Always verify results.
                            </span>
                        </div>

                        <!-- Question Expansion Panels -->
                        <div
                            v-for="(question, qIndex) in playbookState.questions"
                            :key="qIndex"
                            class="border-b border-border last:border-b-0"
                        >
                            <!-- Question Header (clickable) -->
                            <button
                                @click="handleToggleQuestion(qIndex)"
                                class="w-full px-6 py-3 flex items-start gap-3 hover:bg-muted/30 transition-colors text-left"
                            >
                                <component
                                    :is="isExpanded(qIndex) ? ChevronDown : ChevronRight"
                                    class="h-5 w-5 text-muted-foreground flex-shrink-0 mt-0.5"
                                />
                                <span :class="cn('font-medium leading-relaxed', getQuestionColor(question))">
                                    {{ question.question }}
                                </span>
                            </button>

                            <!-- Question Content (expanded) -->
                            <div v-if="isExpanded(qIndex)" class="px-6 pb-4 pl-14 space-y-4">
                                <!-- Context -->
                                <div>
                                    <div class="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">Context</div>
                                    <p class="text-sm text-foreground/80">{{ question.context }}</p>
                                </div>

                                <!-- Date Range -->
                                <div class="text-sm text-muted-foreground">
                                    <span class="font-medium">Date Range:</span> {{ question.range || 'Event time' }}
                                </div>

                                <!-- OQL Query with Hunt Link -->
                                <div class="flex items-start gap-2">
                                    <button
                                        @click="huntWithQuestion(question)"
                                        class="p-1.5 hover:bg-muted rounded transition-colors text-muted-foreground hover:text-primary flex-shrink-0"
                                        title="Hunt with this query"
                                    >
                                        <Crosshair class="h-4 w-4" />
                                    </button>
                                    <code class="flex-1 text-xs font-mono bg-muted/50 px-2 py-1.5 rounded break-all">
                                        {{ question.oqlQuery }}
                                    </code>
                                </div>

                                <!-- Instant Insights Results -->
                                <div v-if="question.queryResults">
                                    <div class="flex items-center justify-between mb-2">
                                        <div class="text-xs font-semibold text-muted-foreground uppercase tracking-wider flex items-center gap-2">
                                            <Sparkles class="h-3.5 w-3.5" />
                                            Instant Insights
                                        </div>
                                        <!-- Mark controls -->
                                        <div class="flex items-center gap-2">
                                            <span v-if="countMarkedFromQuestion(question, qIndex) > 0" class="text-xs text-amber-500 font-medium flex items-center gap-1">
                                                <CheckSquare class="h-3.5 w-3.5" />
                                                {{ countMarkedFromQuestion(question, qIndex) }} marked
                                            </span>
                                            <button
                                                @click="markAllFromQuestion(question, qIndex)"
                                                class="text-xs text-primary hover:text-primary/80 font-medium"
                                            >
                                                Mark All
                                            </button>
                                        </div>
                                    </div>
                                    <div class="text-xs text-muted-foreground mb-2">
                                        Event occurred at {{ formatDate(alert.soc_timestamp || alert['@timestamp']) }}
                                    </div>

                                    <div class="overflow-x-auto rounded border border-border">
                                        <table class="w-full text-sm">
                                            <thead>
                                                <tr class="bg-muted/50">
                                                    <!-- Checkbox column header -->
                                                    <th class="px-2 py-2 w-8 text-center">
                                                        <span class="sr-only">Mark</span>
                                                    </th>
                                                    <th
                                                        v-for="field in question.fields"
                                                        :key="field"
                                                        class="px-3 py-2 text-left font-medium text-muted-foreground text-xs"
                                                    >
                                                        {{ field }}
                                                    </th>
                                                </tr>
                                            </thead>
                                            <tbody class="divide-y divide-border">
                                                <template v-for="(result, rIndex) in getVisibleResults(question, qIndex)" :key="rIndex">
                                                    <tr
                                                        :class="cn(
                                                            'hover:bg-muted/20 transition-colors',
                                                            isResultMarked(result) && 'bg-amber-500/10 hover:bg-amber-500/15'
                                                        )"
                                                    >
                                                        <!-- Checkbox cell -->
                                                        <td class="px-2 py-2 w-8 text-center">
                                                            <button
                                                                @click.stop="handleToggleMarked(result, question.question)"
                                                                :class="cn(
                                                                    'p-0.5 rounded transition-colors',
                                                                    isResultMarked(result)
                                                                        ? 'text-amber-500 hover:text-amber-600'
                                                                        : 'text-muted-foreground hover:text-foreground'
                                                                )"
                                                                :title="isResultMarked(result) ? 'Unmark event' : 'Mark event for escalation'"
                                                            >
                                                                <CheckSquare v-if="isResultMarked(result)" class="h-4 w-4" />
                                                                <Square v-else class="h-4 w-4" />
                                                            </button>
                                                        </td>
                                                        <td
                                                            v-for="field in question.fields"
                                                            :key="field"
                                                            @click="showActionMenu($event, field, result.payload?.[field])"
                                                            class="px-3 py-2 font-mono text-xs cursor-pointer hover:text-primary hover:underline transition-colors"
                                                        >
                                                            {{ result.payload?.[field] ?? '-' }}
                                                        </td>
                                                    </tr>
                                                    <!-- Note input row (shown when marked) -->
                                                    <tr v-if="isResultMarked(result)" class="bg-amber-500/5">
                                                        <td :colspan="(question.fields?.length || 0) + 1" class="px-3 py-2">
                                                            <div class="flex items-start gap-2">
                                                                <StickyNote class="h-3.5 w-3.5 text-amber-500 mt-1.5 flex-shrink-0" />
                                                                <textarea
                                                                    :value="getResultNote(result)"
                                                                    @input="(e) => handleUpdateNote(result, (e.target as HTMLTextAreaElement).value)"
                                                                    placeholder="Add analyst notes for this event..."
                                                                    class="flex-1 text-xs bg-background border border-amber-500/30 rounded px-2 py-1.5 focus:outline-none focus:ring-1 focus:ring-amber-500/50 resize-none min-h-[2.5rem]"
                                                                    rows="1"
                                                                ></textarea>
                                                            </div>
                                                        </td>
                                                    </tr>
                                                </template>
                                                <tr v-if="question.queryResults.length === 0">
                                                    <td :colspan="(question.fields?.length || 1) + 1" class="px-3 py-4 text-center text-muted-foreground text-xs">
                                                        {{ question.error ? 'Error loading results' : 'No data found' }}
                                                    </td>
                                                </tr>
                                            </tbody>
                                        </table>
                                    </div>

                                    <!-- Load All / Collapse Results / Load More Buttons -->
                                    <div class="mt-2 flex items-center gap-2 flex-wrap">
                                        <button
                                            v-if="!isResultsExpanded(qIndex)"
                                            @click="loadAllResults(question, qIndex)"
                                            :disabled="isLoadingResults(qIndex)"
                                            class="text-xs text-primary hover:text-primary/80 font-medium flex items-center gap-1 disabled:opacity-50"
                                        >
                                            <Loader2 v-if="isLoadingResults(qIndex)" class="h-3.5 w-3.5 animate-spin" />
                                            <ChevronDown v-else class="h-3.5 w-3.5" />
                                            {{ isLoadingResults(qIndex) ? 'Loading...' : 'Load all results' }}
                                        </button>
                                        <template v-else>
                                            <button
                                                @click="collapseResults(qIndex)"
                                                class="text-xs text-muted-foreground hover:text-foreground font-medium flex items-center gap-1"
                                            >
                                                <ChevronUp class="h-3.5 w-3.5" />
                                                Show initial results ({{ question.queryResults?.length || 0 }})
                                            </button>
                                            <button
                                                v-if="canLoadMoreResults(qIndex)"
                                                @click="loadMoreResults(question, qIndex)"
                                                :disabled="isLoadingResults(qIndex)"
                                                class="text-xs text-primary hover:text-primary/80 font-medium flex items-center gap-1 disabled:opacity-50"
                                            >
                                                <Loader2 v-if="isLoadingResults(qIndex)" class="h-3.5 w-3.5 animate-spin" />
                                                <Plus v-else class="h-3.5 w-3.5" />
                                                {{ isLoadingResults(qIndex) ? 'Loading...' : 'Load more' }}
                                            </button>
                                            <span class="text-xs text-muted-foreground">
                                                Showing {{ getVisibleResults(question, qIndex).length }} results
                                            </span>
                                        </template>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- All Fields Expandable -->
            <div class="rounded-xl border border-border bg-card overflow-hidden">
                <button
                    @click="showAllFields = !showAllFields"
                    class="w-full px-6 py-4 flex items-center justify-between hover:bg-muted/30 transition-colors"
                >
                    <div class="flex items-center gap-2">
                        <FileText class="h-4 w-4 text-muted-foreground" />
                        <span class="font-semibold">All Fields</span>
                        <span class="text-sm text-muted-foreground">({{ allFields.length }})</span>
                    </div>
                    <ChevronDown :class="cn('h-5 w-5 text-muted-foreground transition-transform', showAllFields && 'rotate-180')" />
                </button>

                <div v-if="showAllFields" class="border-t border-border max-h-96 overflow-auto">
                    <!-- List View -->
                    <div v-if="preferences.allFieldsDisplayMode === 'list'" class="divide-y divide-border">
                        <div
                            v-for="[key, value] in allFields"
                            :key="key"
                            class="px-6 py-3 flex items-start gap-4 hover:bg-muted/20 min-w-0"
                        >
                            <div class="w-1/3 font-mono text-sm text-muted-foreground break-words min-w-0 flex-shrink-0">
                                {{ key }}
                            </div>
                            <div
                                @click="showActionMenu($event, key, value)"
                                class="flex-1 font-mono text-sm break-words min-w-0 overflow-hidden cursor-pointer hover:text-primary hover:underline transition-colors"
                                style="overflow-wrap: anywhere;"
                            >
                                {{ typeof value === 'object' ? JSON.stringify(value) : value }}
                            </div>
                            <button
                                @click="copyToClipboard(typeof value === 'object' ? JSON.stringify(value) : String(value))"
                                class="p-1 hover:bg-muted rounded transition-colors text-muted-foreground hover:text-foreground flex-shrink-0"
                            >
                                <Copy class="h-3 w-3" />
                            </button>
                        </div>
                    </div>
                    <!-- Grid View (Hunt-style) -->
                    <div v-else class="p-4 grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
                        <div
                            v-for="[key, value] in allFields"
                            :key="key"
                            class="text-xs group"
                        >
                            <div class="text-muted-foreground truncate" :title="key">{{ key }}</div>
                            <div
                                @click="showActionMenu($event, key, value)"
                                class="font-medium truncate cursor-pointer hover:text-primary hover:underline transition-colors"
                                :title="typeof value === 'object' ? JSON.stringify(value) : String(value)"
                            >
                                {{ typeof value === 'object' ? JSON.stringify(value) : value }}
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- PCAP Card -->
            <div class="rounded-xl border border-border bg-card overflow-hidden mt-6">
                <!-- Header -->
                <div class="p-4 flex items-center justify-between flex-wrap gap-4">
                    <div class="flex items-center gap-2 text-muted-foreground">
                        <HardDrive class="h-4 w-4" />
                        <span class="text-sm font-medium">PCAP</span>
                    </div>

                    <!-- No job yet - show fetch button -->
                    <div v-if="!pcapJob" class="flex items-center gap-3">
                        <button
                            @click="createPcapJob"
                            :disabled="pcapLoading"
                            class="inline-flex items-center gap-2 px-3 py-1.5 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 transition-colors text-sm font-medium disabled:opacity-50"
                        >
                            <Loader2 v-if="pcapLoading" class="h-4 w-4 animate-spin" />
                            <Download v-else class="h-4 w-4" />
                            Fetch PCAP
                        </button>
                    </div>

                    <!-- Job exists - show status -->
                    <div v-else class="flex items-center gap-4">
                        <!-- Pending status -->
                        <template v-if="pcapJob.status === JOB_STATUS.PENDING">
                            <div class="flex items-center gap-2">
                                <Loader2 class="h-4 w-4 animate-spin text-amber-500" />
                                <span class="text-sm font-medium text-amber-500">Processing...</span>
                            </div>
                            <div class="text-xs text-muted-foreground">Job #{{ pcapJob.id }}</div>
                            <button
                                @click="refreshPcapJobStatus"
                                class="p-1.5 hover:bg-muted rounded transition-colors text-muted-foreground hover:text-foreground"
                                title="Refresh status"
                            >
                                <RefreshCw class="h-4 w-4" />
                            </button>
                        </template>

                        <!-- Completed - show expand/collapse and actions -->
                        <template v-else-if="pcapJob.status === JOB_STATUS.COMPLETED">
                            <div class="flex items-center gap-2">
                                <CheckCircle class="h-4 w-4 text-green-500" />
                                <span class="text-sm font-medium text-green-500">Ready</span>
                                <span v-if="pcapJob.size > 0" class="text-xs text-muted-foreground">
                                    ({{ formatBytes(pcapJob.size) }})
                                </span>
                            </div>
                            <button
                                @click="togglePcapDetails"
                                class="inline-flex items-center gap-2 px-3 py-1.5 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 transition-colors text-sm font-medium"
                            >
                                <Eye class="h-4 w-4" />
                                {{ showPcapDetails ? 'Hide' : 'View' }} Packets
                            </button>
                            <a
                                :href="router.resolve({ name: 'job-detail', params: { id: pcapJob.id } }).href"
                                target="_blank"
                                class="inline-flex items-center gap-2 px-3 py-1.5 border border-border rounded-md hover:bg-muted transition-colors text-sm font-medium"
                                title="Open in new tab"
                            >
                                <ExternalLink class="h-4 w-4" />
                            </a>
                            <button
                                @click="downloadPcap"
                                class="inline-flex items-center gap-2 px-3 py-1.5 border border-border rounded-md hover:bg-muted transition-colors text-sm font-medium"
                            >
                                <Download class="h-4 w-4" />
                                Download
                            </button>
                        </template>

                        <!-- Failed -->
                        <template v-else-if="pcapJob.status === JOB_STATUS.INCOMPLETE">
                            <div class="flex items-center gap-2">
                                <AlertTriangle class="h-4 w-4 text-red-500" />
                                <span class="text-sm font-medium text-red-500">Failed</span>
                            </div>
                            <div v-if="pcapJob.failure" class="text-xs text-red-500">
                                {{ pcapJob.failure }}
                            </div>
                            <a
                                :href="router.resolve({ name: 'job-detail', params: { id: pcapJob.id } }).href"
                                target="_blank"
                                class="text-xs text-muted-foreground hover:text-foreground"
                            >
                                View details
                            </a>
                        </template>
                    </div>

                    <!-- Error message -->
                    <div v-if="pcapError" class="w-full text-xs text-red-500 mt-2">
                        {{ pcapError }}
                    </div>
                </div>

                <!-- Expanded Packet View -->
                <div v-if="showPcapDetails && pcapJob?.status === JOB_STATUS.COMPLETED" class="border-t border-border">
                    <!-- Toolbar -->
                    <div class="flex items-center justify-between p-3 border-b border-border bg-muted/30">
                        <!-- Left side: View mode toggle -->
                        <div class="flex items-center gap-1 bg-muted rounded-lg p-1">
                            <button
                                @click="pcapDisplayMode = 'packets'"
                                :class="cn('px-3 py-1 rounded-md text-xs font-medium transition-colors', pcapDisplayMode === 'packets' ? 'bg-background text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground')"
                            >
                                Packets
                            </button>
                            <button
                                @click="pcapDisplayMode = 'transcript'"
                                :class="cn('px-3 py-1 rounded-md text-xs font-medium transition-colors', pcapDisplayMode === 'transcript' ? 'bg-background text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground')"
                            >
                                Transcript
                            </button>
                        </div>

                        <!-- Right side: Tools -->
                        <div class="flex items-center gap-2">
                            <button
                                @click="fetchPackets"
                                class="p-2 hover:bg-muted rounded-md transition-colors text-muted-foreground"
                                title="Refresh Packets"
                            >
                                <RefreshCw class="h-4 w-4" :class="{ 'animate-spin': packetsLoading }" />
                            </button>
                            <template v-if="pcapDisplayMode === 'packets'">
                                <div class="h-5 w-px bg-border mx-1"></div>
                                <button
                                    @click="packetViewMode = 'hex'"
                                    :class="cn('px-2.5 py-1 rounded-md text-xs font-medium transition-colors border', packetViewMode === 'hex' ? 'bg-primary/10 text-primary border-primary/20' : 'text-muted-foreground border-transparent hover:bg-muted')"
                                >
                                    Hex
                                </button>
                                <button
                                    @click="packetViewMode = 'ascii'"
                                    :class="cn('px-2.5 py-1 rounded-md text-xs font-medium transition-colors border', packetViewMode === 'ascii' ? 'bg-primary/10 text-primary border-primary/20' : 'text-muted-foreground border-transparent hover:bg-muted')"
                                >
                                    ASCII
                                </button>
                                <div class="h-5 w-px bg-border mx-1"></div>
                                <button
                                    @click="expandAllPackets"
                                    class="p-2 hover:bg-muted rounded-md transition-colors text-muted-foreground"
                                    title="Expand All"
                                >
                                    <Maximize2 class="h-4 w-4" />
                                </button>
                                <button
                                    @click="collapseAllPackets"
                                    class="p-2 hover:bg-muted rounded-md transition-colors text-muted-foreground"
                                    title="Collapse All"
                                >
                                    <Minimize2 class="h-4 w-4" />
                                </button>
                            </template>
                        </div>
                    </div>

                    <!-- Packets Table -->
                    <div v-if="pcapDisplayMode === 'packets'" class="overflow-x-auto">
                        <table class="w-full text-sm font-mono">
                            <thead>
                                <tr class="bg-muted/50 border-b border-border">
                                    <th class="w-8"></th>
                                    <th class="px-3 py-2 text-left font-semibold text-muted-foreground text-xs">No.</th>
                                    <th class="px-3 py-2 text-left font-semibold text-muted-foreground text-xs">Time</th>
                                    <th class="px-3 py-2 text-left font-semibold text-muted-foreground text-xs">Type</th>
                                    <th class="px-3 py-2 text-left font-semibold text-muted-foreground text-xs">Source</th>
                                    <th class="px-3 py-2 text-left font-semibold text-muted-foreground text-xs">Src Port</th>
                                    <th class="px-3 py-2 text-left font-semibold text-muted-foreground text-xs">Destination</th>
                                    <th class="px-3 py-2 text-left font-semibold text-muted-foreground text-xs">Dst Port</th>
                                    <th class="px-3 py-2 text-left font-semibold text-muted-foreground text-xs">Flags</th>
                                    <th class="px-3 py-2 text-left font-semibold text-muted-foreground text-xs">Length</th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-border">
                                <tr v-if="packetsLoading && packets.length === 0">
                                    <td colspan="10" class="h-24 text-center text-muted-foreground font-sans">
                                        <Loader2 class="h-5 w-5 animate-spin mx-auto mb-2" />
                                        Loading packets...
                                    </td>
                                </tr>
                                <tr v-else-if="!packetsLoading && packets.length === 0">
                                    <td colspan="10" class="h-24 text-center text-muted-foreground font-sans">
                                        No packets found
                                    </td>
                                </tr>
                                <template v-for="packet in packets" :key="packet.number">
                                    <tr
                                        @click="togglePacketExpand(packet.number)"
                                        class="hover:bg-muted/50 cursor-pointer transition-colors"
                                        :class="{ 'bg-muted/20': expandedPackets.has(packet.number) }"
                                    >
                                        <td class="px-2 py-2 text-center">
                                            <ChevronDown
                                                class="h-4 w-4 text-muted-foreground transition-transform duration-200"
                                                :class="{ '-rotate-90': !expandedPackets.has(packet.number) }"
                                            />
                                        </td>
                                        <td class="px-3 py-2 text-xs">{{ packet.number }}</td>
                                        <td class="px-3 py-2 text-xs whitespace-nowrap">{{ new Date(packet.timestamp).toLocaleTimeString() }}</td>
                                        <td class="px-3 py-2">
                                            <span :class="cn('px-1.5 py-0.5 rounded text-xs font-bold border', getPacketTypeColor(packet.type))">
                                                {{ packet.type }}
                                            </span>
                                        </td>
                                        <td class="px-3 py-2 text-xs">{{ packet.srcIp }}</td>
                                        <td class="px-3 py-2 text-xs">{{ packet.srcPort }}</td>
                                        <td class="px-3 py-2 text-xs">{{ packet.dstIp }}</td>
                                        <td class="px-3 py-2 text-xs">{{ packet.dstPort }}</td>
                                        <td class="px-3 py-2">
                                            <span v-for="flag in packet.flags" :key="flag" class="inline-block px-1 py-0.5 rounded text-xs bg-muted mr-1">
                                                {{ flag }}
                                            </span>
                                        </td>
                                        <td class="px-3 py-2 text-xs">{{ packet.length }}</td>
                                    </tr>
                                    <!-- Payload Row -->
                                    <tr v-if="expandedPackets.has(packet.number)">
                                        <td colspan="10" class="bg-muted/10 p-3 border-b border-border">
                                            <div class="bg-card border border-border rounded-lg p-3 font-mono text-xs leading-relaxed select-text shadow-inner whitespace-pre-wrap break-words" style="overflow-wrap: anywhere;">
                                                {{ formatPayload(packet.payload, packet.payloadOffset) || 'No payload data' }}
                                            </div>
                                        </td>
                                    </tr>
                                </template>
                            </tbody>
                        </table>
                    </div>

                    <!-- ASCII Transcript -->
                    <div v-else-if="pcapDisplayMode === 'transcript'" class="p-4">
                        <div v-if="packetsLoading" class="h-24 flex items-center justify-center text-muted-foreground">
                            <Loader2 class="h-5 w-5 animate-spin mr-2" />
                            Loading packets...
                        </div>
                        <div v-else-if="packets.length === 0" class="h-24 flex items-center justify-center text-muted-foreground">
                            No packets found
                        </div>
                        <template v-else>
                            <div class="flex items-center gap-4 mb-3 text-xs">
                                <div class="flex items-center gap-2">
                                    <span class="w-3 h-3 rounded bg-red-500"></span>
                                    <span class="text-muted-foreground">Client → Server</span>
                                </div>
                                <div class="flex items-center gap-2">
                                    <span class="w-3 h-3 rounded bg-blue-500"></span>
                                    <span class="text-muted-foreground">Server → Client</span>
                                </div>
                            </div>
                            <div class="bg-card border border-border rounded-lg p-4 font-mono text-xs leading-relaxed select-text shadow-inner whitespace-pre-wrap break-words" style="overflow-wrap: anywhere;"><template
                                v-for="(segment, idx) in getAsciiTranscriptSegments()"
                                :key="idx"
                            ><span v-if="segment.directionChanged" class="block my-3 border-t border-border"></span><span
                                :class="segment.direction === 'client' ? 'text-red-500' : 'text-blue-500'"
                            >{{ segment.text }}</span></template></div>
                        </template>
                    </div>
                </div>
            </div>
        </template>

        <!-- Copied Toast -->
        <Teleport to="body">
            <Transition
                enter-active-class="transition-all duration-300"
                enter-from-class="opacity-0 translate-y-2"
                enter-to-class="opacity-100 translate-y-0"
                leave-active-class="transition-all duration-300"
                leave-from-class="opacity-100 translate-y-0"
                leave-to-class="opacity-0 translate-y-2"
            >
                <div
                    v-if="copied"
                    class="fixed bottom-4 right-4 px-4 py-2 bg-foreground text-background rounded-lg shadow-lg flex items-center gap-2 z-50"
                >
                    <CheckCircle class="h-4 w-4" />
                    Copied!
                </div>
            </Transition>
        </Teleport>

        <!-- Action Menu -->
        <Teleport to="body">
            <div
                v-if="actionMenuVisible"
                class="fixed inset-0 z-50"
                @click="closeActionMenu"
            >
                <div
                    class="absolute bg-popover border border-border rounded-lg shadow-xl py-1 min-w-[200px]"
                    :style="{ left: `${actionMenuX}px`, top: `${actionMenuY}px` }"
                    @click.stop
                >
                    <button
                        @click="huntInNewTab(actionMenuField, actionMenuValue)"
                        class="w-full px-3 py-2 text-sm text-left hover:bg-muted flex items-center gap-2 transition-colors"
                    >
                        <Crosshair class="h-4 w-4 text-primary" />
                        Hunt
                    </button>
                    <button
                        @click="copyFieldValue(actionMenuValue)"
                        class="w-full px-3 py-2 text-sm text-left hover:bg-muted flex items-center gap-2 transition-colors"
                    >
                        <Copy class="h-4 w-4 text-muted-foreground" />
                        Copy Value
                    </button>
                    <button
                        @click="askAiAboutField(actionMenuField, actionMenuValue)"
                        class="w-full px-3 py-2 text-sm text-left hover:bg-muted flex items-center gap-2 transition-colors"
                    >
                        <Sparkles class="h-4 w-4 text-purple-500" />
                        Ask AI
                    </button>

                    <!-- Tuning options (only for IP fields with Suricata detections) -->
                    <template v-if="isIpField(actionMenuField) && canAddSuppression">
                        <div class="my-1 border-t border-border"></div>
                        <div class="px-3 py-1 text-xs text-muted-foreground font-medium">
                            Suppress
                        </div>
                        <button
                            @click="addSuppressionBySource"
                            :disabled="suppressionLoading"
                            class="w-full px-3 py-2 text-sm text-left hover:bg-muted flex items-center gap-2 transition-colors disabled:opacity-50"
                        >
                            <ShieldOff class="h-4 w-4 text-amber-500" />
                            By Source IP
                        </button>
                        <button
                            @click="addSuppressionByDestination"
                            :disabled="suppressionLoading"
                            class="w-full px-3 py-2 text-sm text-left hover:bg-muted flex items-center gap-2 transition-colors disabled:opacity-50"
                        >
                            <ShieldOff class="h-4 w-4 text-amber-500" />
                            By Destination IP
                        </button>
                        <div class="px-3 py-1 text-xs text-muted-foreground font-medium">
                            Threshold
                        </div>
                        <button
                            @click="addThresholdBySource"
                            :disabled="suppressionLoading"
                            class="w-full px-3 py-2 text-sm text-left hover:bg-muted flex items-center gap-2 transition-colors disabled:opacity-50"
                        >
                            <Activity class="h-4 w-4 text-blue-500" />
                            By Source IP
                        </button>
                        <button
                            @click="addThresholdByDestination"
                            :disabled="suppressionLoading"
                            class="w-full px-3 py-2 text-sm text-left hover:bg-muted flex items-center gap-2 transition-colors disabled:opacity-50"
                        >
                            <Activity class="h-4 w-4 text-blue-500" />
                            By Destination IP
                        </button>
                    </template>

                    <!-- Show message if suppression not available -->
                    <template v-else-if="isIpField(actionMenuField) && detection && detection.engine !== 'suricata'">
                        <div class="my-1 border-t border-border"></div>
                        <div class="px-3 py-2 text-xs text-muted-foreground">
                            Suppression only available for Suricata detections
                        </div>
                    </template>
                </div>
            </div>
        </Teleport>

        <!-- Suppression Toast -->
        <Teleport to="body">
            <Transition
                enter-active-class="transition-all duration-300"
                enter-from-class="opacity-0 translate-y-2"
                enter-to-class="opacity-100 translate-y-0"
                leave-active-class="transition-all duration-300"
                leave-from-class="opacity-100 translate-y-0"
                leave-to-class="opacity-0 translate-y-2"
            >
                <div
                    v-if="suppressionSuccess"
                    class="fixed bottom-4 right-4 px-4 py-2 bg-green-600 text-white rounded-lg shadow-lg flex items-center gap-2 z-50"
                >
                    <CheckCircle class="h-4 w-4" />
                    Suppression added successfully
                </div>
            </Transition>
            <Transition
                enter-active-class="transition-all duration-300"
                enter-from-class="opacity-0 translate-y-2"
                enter-to-class="opacity-100 translate-y-0"
                leave-active-class="transition-all duration-300"
                leave-from-class="opacity-100 translate-y-0"
                leave-to-class="opacity-0 translate-y-2"
            >
                <div
                    v-if="suppressionError"
                    class="fixed bottom-4 right-4 px-4 py-2 bg-destructive text-destructive-foreground rounded-lg shadow-lg flex items-center gap-2 z-50"
                >
                    <AlertTriangle class="h-4 w-4" />
                    {{ suppressionError }}
                </div>
            </Transition>
        </Teleport>

        <!-- Suppression Confirmation Dialog -->
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
                    v-if="showSuppressionConfirm"
                    class="fixed inset-0 z-50 flex items-center justify-center bg-black/50"
                    @click.self="cancelSuppression"
                >
                    <div class="bg-card border border-border rounded-xl shadow-2xl w-full max-w-md mx-4 overflow-hidden">
                        <!-- Header -->
                        <div class="px-6 py-4 border-b border-border bg-muted/30">
                            <div class="flex items-center gap-3">
                                <div class="p-2 rounded-lg bg-amber-500/10">
                                    <ShieldOff class="h-5 w-5 text-amber-500" />
                                </div>
                                <h3 class="text-lg font-semibold">Add Suppression</h3>
                            </div>
                        </div>

                        <!-- Content -->
                        <div class="px-6 py-5 space-y-4">
                            <p class="text-sm text-muted-foreground">
                                Suppress alerts from this detection for the specified IP address or range.
                            </p>

                            <!-- IP Address Input -->
                            <div>
                                <label class="block text-sm font-medium mb-2">IP Address</label>
                                <input
                                    v-model="pendingSuppressionIp"
                                    type="text"
                                    placeholder="e.g., 192.168.1.100 or 10.0.0.0/24"
                                    class="w-full px-3 py-2 text-sm font-mono border border-border rounded-lg bg-background focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent"
                                />
                                <p class="text-xs text-muted-foreground mt-1">
                                    Single IP or CIDR range (e.g., 10.0.0.0/24)
                                </p>
                            </div>

                            <div class="bg-muted/50 rounded-lg p-4 space-y-2 text-sm">
                                <div class="flex justify-between">
                                    <span class="text-muted-foreground">Detection:</span>
                                    <span class="font-medium truncate max-w-[200px]" :title="detection?.title">
                                        {{ detection?.title || 'Unknown' }}
                                    </span>
                                </div>
                                <div class="flex justify-between">
                                    <span class="text-muted-foreground">Track:</span>
                                    <span class="font-mono">{{ pendingSuppressionTrack === 'by_src' ? 'Source IP' : 'Destination IP' }}</span>
                                </div>
                            </div>
                        </div>

                        <!-- Footer -->
                        <div class="px-6 py-4 border-t border-border bg-muted/30 flex justify-end gap-3">
                            <button
                                @click="cancelSuppression"
                                class="px-4 py-2 text-sm font-medium rounded-lg border border-border hover:bg-muted transition-colors"
                            >
                                Cancel
                            </button>
                            <button
                                @click="confirmSuppression"
                                :disabled="suppressionLoading || !pendingSuppressionIp?.trim()"
                                class="px-4 py-2 text-sm font-medium rounded-lg bg-amber-600 text-white hover:bg-amber-700 transition-colors disabled:opacity-50 flex items-center gap-2"
                            >
                                <Loader2 v-if="suppressionLoading" class="h-4 w-4 animate-spin" />
                                <span>{{ suppressionLoading ? 'Adding...' : 'Add Suppression' }}</span>
                            </button>
                        </div>
                    </div>
                </div>
            </Transition>

            <!-- Threshold Confirmation Dialog -->
            <Transition
                enter-active-class="transition-opacity duration-200"
                enter-from-class="opacity-0"
                enter-to-class="opacity-100"
                leave-active-class="transition-opacity duration-200"
                leave-from-class="opacity-100"
                leave-to-class="opacity-0"
            >
                <div
                    v-if="showThresholdConfirm"
                    class="fixed inset-0 z-50 flex items-center justify-center bg-black/50"
                    @click.self="cancelThreshold"
                >
                    <div class="bg-card border border-border rounded-xl shadow-2xl w-full max-w-md mx-4 overflow-hidden">
                        <!-- Header -->
                        <div class="px-6 py-4 border-b border-border bg-muted/30">
                            <div class="flex items-center gap-3">
                                <div class="p-2 rounded-lg bg-blue-500/10">
                                    <Activity class="h-5 w-5 text-blue-500" />
                                </div>
                                <h3 class="text-lg font-semibold">Add Threshold</h3>
                            </div>
                        </div>

                        <!-- Content -->
                        <div class="px-6 py-5 space-y-4">
                            <p class="text-sm text-muted-foreground">
                                Limit alert frequency for this detection based on {{ getTrackDescription(pendingThresholdTrack) }} IP.
                            </p>

                            <!-- Threshold Type -->
                            <div>
                                <label class="block text-sm font-medium mb-2">Threshold Type</label>
                                <div class="flex gap-2">
                                    <button
                                        @click="pendingThresholdType = 'limit'"
                                        :class="cn(
                                            'flex-1 px-3 py-2 text-sm font-medium rounded-lg border transition-colors',
                                            pendingThresholdType === 'limit'
                                                ? 'bg-blue-500 text-white border-blue-500'
                                                : 'border-border hover:bg-muted'
                                        )"
                                    >
                                        Limit
                                    </button>
                                    <button
                                        @click="pendingThresholdType = 'threshold'"
                                        :class="cn(
                                            'flex-1 px-3 py-2 text-sm font-medium rounded-lg border transition-colors',
                                            pendingThresholdType === 'threshold'
                                                ? 'bg-blue-500 text-white border-blue-500'
                                                : 'border-border hover:bg-muted'
                                        )"
                                    >
                                        Threshold
                                    </button>
                                    <button
                                        @click="pendingThresholdType = 'both'"
                                        :class="cn(
                                            'flex-1 px-3 py-2 text-sm font-medium rounded-lg border transition-colors',
                                            pendingThresholdType === 'both'
                                                ? 'bg-blue-500 text-white border-blue-500'
                                                : 'border-border hover:bg-muted'
                                        )"
                                    >
                                        Both
                                    </button>
                                </div>
                                <p class="text-xs text-muted-foreground mt-1">
                                    <span v-if="pendingThresholdType === 'limit'">Alert on first N events, then suppress</span>
                                    <span v-else-if="pendingThresholdType === 'threshold'">Alert only after N events</span>
                                    <span v-else>Alert after N events, then once per time window</span>
                                </p>
                            </div>

                            <!-- Count and Seconds -->
                            <div class="grid grid-cols-2 gap-4">
                                <div>
                                    <label class="block text-sm font-medium mb-2">Count</label>
                                    <input
                                        v-model.number="pendingThresholdCount"
                                        type="number"
                                        min="1"
                                        class="w-full px-3 py-2 text-sm font-mono border border-border rounded-lg bg-background focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent"
                                    />
                                </div>
                                <div>
                                    <label class="block text-sm font-medium mb-2">Seconds</label>
                                    <input
                                        v-model.number="pendingThresholdSeconds"
                                        type="number"
                                        min="1"
                                        class="w-full px-3 py-2 text-sm font-mono border border-border rounded-lg bg-background focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent"
                                    />
                                </div>
                            </div>

                            <div class="bg-muted/50 rounded-lg p-4 space-y-2 text-sm">
                                <div class="flex justify-between">
                                    <span class="text-muted-foreground">Detection:</span>
                                    <span class="font-medium truncate max-w-[200px]" :title="detection?.title">
                                        {{ detection?.title || 'Unknown' }}
                                    </span>
                                </div>
                                <div class="flex justify-between">
                                    <span class="text-muted-foreground">Track:</span>
                                    <span class="font-mono">{{ pendingThresholdTrack }}</span>
                                </div>
                            </div>
                        </div>

                        <!-- Footer -->
                        <div class="px-6 py-4 border-t border-border bg-muted/30 flex justify-end gap-3">
                            <button
                                @click="cancelThreshold"
                                class="px-4 py-2 text-sm font-medium rounded-lg border border-border hover:bg-muted transition-colors"
                            >
                                Cancel
                            </button>
                            <button
                                @click="confirmThreshold"
                                :disabled="suppressionLoading"
                                class="px-4 py-2 text-sm font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-700 transition-colors disabled:opacity-50 flex items-center gap-2"
                            >
                                <Loader2 v-if="suppressionLoading" class="h-4 w-4 animate-spin" />
                                <span>{{ suppressionLoading ? 'Adding...' : 'Add Threshold' }}</span>
                            </button>
                        </div>
                    </div>
                </div>
            </Transition>

            <!-- Remove Override Confirmation Dialog -->
            <Transition
                enter-active-class="transition-opacity duration-200"
                enter-from-class="opacity-0"
                enter-to-class="opacity-100"
                leave-active-class="transition-opacity duration-200"
                leave-from-class="opacity-100"
                leave-to-class="opacity-0"
            >
                <div
                    v-if="showRemoveOverrideConfirm"
                    class="fixed inset-0 z-50 flex items-center justify-center bg-black/50"
                    @click.self="cancelRemoveOverride"
                >
                    <div class="bg-card border border-border rounded-xl shadow-2xl w-full max-w-md mx-4 overflow-hidden">
                        <!-- Header -->
                        <div class="px-6 py-4 border-b border-border bg-muted/30">
                            <div class="flex items-center gap-3">
                                <div class="p-2 rounded-lg bg-destructive/10">
                                    <Trash2 class="h-5 w-5 text-destructive" />
                                </div>
                                <h3 class="text-lg font-semibold">Remove Override</h3>
                            </div>
                        </div>

                        <!-- Content -->
                        <div class="px-6 py-5">
                            <p class="text-sm text-muted-foreground mb-4">
                                Are you sure you want to remove this override? This action cannot be undone.
                            </p>

                            <div v-if="detection?.overrides && pendingRemoveOverrideIndex !== null" class="bg-muted/50 rounded-lg p-4 space-y-2 text-sm">
                                <div class="flex justify-between">
                                    <span class="text-muted-foreground">Type:</span>
                                    <span class="font-medium">{{ detection.overrides[pendingRemoveOverrideIndex]?.type }}</span>
                                </div>
                                <div v-if="detection.overrides[pendingRemoveOverrideIndex]?.track" class="flex justify-between">
                                    <span class="text-muted-foreground">Track:</span>
                                    <span class="font-mono">{{ detection.overrides[pendingRemoveOverrideIndex]?.track }}</span>
                                </div>
                                <div v-if="detection.overrides[pendingRemoveOverrideIndex]?.ip" class="flex justify-between">
                                    <span class="text-muted-foreground">IP:</span>
                                    <span class="font-mono">{{ detection.overrides[pendingRemoveOverrideIndex]?.ip }}</span>
                                </div>
                            </div>
                        </div>

                        <!-- Footer -->
                        <div class="px-6 py-4 border-t border-border bg-muted/30 flex justify-end gap-3">
                            <button
                                @click="cancelRemoveOverride"
                                class="px-4 py-2 text-sm font-medium rounded-lg border border-border hover:bg-muted transition-colors"
                            >
                                Cancel
                            </button>
                            <button
                                @click="removeOverride"
                                :disabled="detectionUpdating"
                                class="px-4 py-2 text-sm font-medium rounded-lg bg-destructive text-destructive-foreground hover:bg-destructive/90 transition-colors disabled:opacity-50 flex items-center gap-2"
                            >
                                <Loader2 v-if="detectionUpdating" class="h-4 w-4 animate-spin" />
                                <span>{{ detectionUpdating ? 'Removing...' : 'Remove Override' }}</span>
                            </button>
                        </div>
                    </div>
                </div>
            </Transition>

            <!-- Tuning Dialog -->
            <Transition
                enter-active-class="transition-opacity duration-200"
                enter-from-class="opacity-0"
                enter-to-class="opacity-100"
                leave-active-class="transition-opacity duration-200"
                leave-from-class="opacity-100"
                leave-to-class="opacity-0"
            >
                <div
                    v-if="showTuningDialog"
                    class="fixed inset-0 z-50 flex items-center justify-center bg-black/50"
                    @click.self="closeTuningDialog"
                >
                    <div class="bg-card border border-border rounded-xl shadow-2xl w-full max-w-md mx-4 overflow-hidden">
                        <!-- Header -->
                        <div class="px-6 py-4 border-b border-border bg-muted/30">
                            <div class="flex items-center gap-3">
                                <div class="p-2 rounded-lg bg-primary/10">
                                    <Settings class="h-5 w-5 text-primary" />
                                </div>
                                <h3 class="text-lg font-semibold">Add Tuning Override</h3>
                            </div>
                        </div>

                        <!-- Content -->
                        <div class="px-6 py-5 space-y-4">
                            <!-- Override Type -->
                            <div>
                                <label class="block text-sm font-medium mb-2">Override Type</label>
                                <div class="flex gap-2">
                                    <button
                                        @click="tuningType = 'suppress'"
                                        :class="cn(
                                            'flex-1 px-4 py-2 text-sm font-medium rounded-lg border transition-colors',
                                            tuningType === 'suppress'
                                                ? 'bg-primary text-primary-foreground border-primary'
                                                : 'border-border hover:bg-muted'
                                        )"
                                    >
                                        Suppress
                                    </button>
                                    <button
                                        @click="tuningType = 'threshold'"
                                        :class="cn(
                                            'flex-1 px-4 py-2 text-sm font-medium rounded-lg border transition-colors',
                                            tuningType === 'threshold'
                                                ? 'bg-primary text-primary-foreground border-primary'
                                                : 'border-border hover:bg-muted'
                                        )"
                                    >
                                        Threshold
                                    </button>
                                </div>
                            </div>

                            <!-- Suppress Options -->
                            <template v-if="tuningType === 'suppress'">
                                <p class="text-sm text-muted-foreground">
                                    Suppress alerts from this detection for a specific IP address.
                                </p>

                                <!-- Track Type -->
                                <div>
                                    <label class="block text-sm font-medium mb-2">Track By</label>
                                    <div class="flex gap-2">
                                        <button
                                            @click="tuningTrack = 'by_src'"
                                            :class="cn(
                                                'flex-1 px-4 py-2 text-sm font-medium rounded-lg border transition-colors',
                                                tuningTrack === 'by_src'
                                                    ? 'bg-amber-500 text-white border-amber-500'
                                                    : 'border-border hover:bg-muted'
                                            )"
                                        >
                                            Source IP
                                        </button>
                                        <button
                                            @click="tuningTrack = 'by_dst'"
                                            :class="cn(
                                                'flex-1 px-4 py-2 text-sm font-medium rounded-lg border transition-colors',
                                                tuningTrack === 'by_dst'
                                                    ? 'bg-amber-500 text-white border-amber-500'
                                                    : 'border-border hover:bg-muted'
                                            )"
                                        >
                                            Destination IP
                                        </button>
                                    </div>
                                </div>

                                <!-- IP Address -->
                                <div>
                                    <label class="block text-sm font-medium mb-2">IP Address</label>
                                    <input
                                        v-model="tuningIp"
                                        type="text"
                                        placeholder="e.g., 192.168.1.100 or 10.0.0.0/24"
                                        class="w-full px-3 py-2 text-sm font-mono border border-border rounded-lg bg-background focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent"
                                    />
                                    <p class="text-xs text-muted-foreground mt-1">
                                        Single IP or CIDR range
                                    </p>
                                </div>
                            </template>

                            <!-- Threshold Options -->
                            <template v-if="tuningType === 'threshold'">
                                <p class="text-sm text-muted-foreground">
                                    Limit alert frequency based on count and time window.
                                </p>

                                <!-- Threshold Type -->
                                <div>
                                    <label class="block text-sm font-medium mb-2">Threshold Type</label>
                                    <div class="flex gap-2">
                                        <button
                                            @click="tuningThresholdType = 'limit'"
                                            :class="cn(
                                                'flex-1 px-3 py-2 text-sm font-medium rounded-lg border transition-colors',
                                                tuningThresholdType === 'limit'
                                                    ? 'bg-blue-500 text-white border-blue-500'
                                                    : 'border-border hover:bg-muted'
                                            )"
                                        >
                                            Limit
                                        </button>
                                        <button
                                            @click="tuningThresholdType = 'threshold'"
                                            :class="cn(
                                                'flex-1 px-3 py-2 text-sm font-medium rounded-lg border transition-colors',
                                                tuningThresholdType === 'threshold'
                                                    ? 'bg-blue-500 text-white border-blue-500'
                                                    : 'border-border hover:bg-muted'
                                            )"
                                        >
                                            Threshold
                                        </button>
                                        <button
                                            @click="tuningThresholdType = 'both'"
                                            :class="cn(
                                                'flex-1 px-3 py-2 text-sm font-medium rounded-lg border transition-colors',
                                                tuningThresholdType === 'both'
                                                    ? 'bg-blue-500 text-white border-blue-500'
                                                    : 'border-border hover:bg-muted'
                                            )"
                                        >
                                            Both
                                        </button>
                                    </div>
                                    <p class="text-xs text-muted-foreground mt-1">
                                        <span v-if="tuningThresholdType === 'limit'">Alert on first N events, then suppress</span>
                                        <span v-else-if="tuningThresholdType === 'threshold'">Alert only after N events</span>
                                        <span v-else>Alert after N events, then once per time window</span>
                                    </p>
                                </div>

                                <!-- Track Type -->
                                <div>
                                    <label class="block text-sm font-medium mb-2">Track By</label>
                                    <div class="flex gap-2">
                                        <button
                                            @click="tuningTrack = 'by_src'"
                                            :class="cn(
                                                'flex-1 px-4 py-2 text-sm font-medium rounded-lg border transition-colors',
                                                tuningTrack === 'by_src'
                                                    ? 'bg-blue-500 text-white border-blue-500'
                                                    : 'border-border hover:bg-muted'
                                            )"
                                        >
                                            Source IP
                                        </button>
                                        <button
                                            @click="tuningTrack = 'by_dst'"
                                            :class="cn(
                                                'flex-1 px-4 py-2 text-sm font-medium rounded-lg border transition-colors',
                                                tuningTrack === 'by_dst'
                                                    ? 'bg-blue-500 text-white border-blue-500'
                                                    : 'border-border hover:bg-muted'
                                            )"
                                        >
                                            Destination IP
                                        </button>
                                    </div>
                                </div>

                                <!-- Count and Seconds -->
                                <div class="grid grid-cols-2 gap-4">
                                    <div>
                                        <label class="block text-sm font-medium mb-2">Count</label>
                                        <input
                                            v-model.number="tuningCount"
                                            type="number"
                                            min="1"
                                            class="w-full px-3 py-2 text-sm font-mono border border-border rounded-lg bg-background focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent"
                                        />
                                    </div>
                                    <div>
                                        <label class="block text-sm font-medium mb-2">Seconds</label>
                                        <input
                                            v-model.number="tuningSeconds"
                                            type="number"
                                            min="1"
                                            class="w-full px-3 py-2 text-sm font-mono border border-border rounded-lg bg-background focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent"
                                        />
                                    </div>
                                </div>
                            </template>

                            <!-- Note -->
                            <div>
                                <label class="block text-sm font-medium mb-2">Note (optional)</label>
                                <input
                                    v-model="tuningNote"
                                    type="text"
                                    placeholder="Reason for this override"
                                    class="w-full px-3 py-2 text-sm border border-border rounded-lg bg-background focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent"
                                />
                            </div>

                            <!-- Detection Info -->
                            <div class="bg-muted/50 rounded-lg p-3 text-sm">
                                <div class="flex justify-between text-muted-foreground">
                                    <span>Detection:</span>
                                    <span class="font-medium text-foreground truncate max-w-[200px]" :title="detection?.title">
                                        {{ detection?.title || 'Unknown' }}
                                    </span>
                                </div>
                            </div>
                        </div>

                        <!-- Footer -->
                        <div class="px-6 py-4 border-t border-border bg-muted/30 flex justify-end gap-3">
                            <button
                                @click="closeTuningDialog"
                                class="px-4 py-2 text-sm font-medium rounded-lg border border-border hover:bg-muted transition-colors"
                            >
                                Cancel
                            </button>
                            <button
                                @click="saveTuning"
                                :disabled="tuningSaving || (tuningType === 'suppress' && !tuningIp.trim())"
                                class="px-4 py-2 text-sm font-medium rounded-lg bg-primary text-primary-foreground hover:bg-primary/90 transition-colors disabled:opacity-50 flex items-center gap-2"
                            >
                                <Loader2 v-if="tuningSaving" class="h-4 w-4 animate-spin" />
                                <span>{{ tuningSaving ? 'Saving...' : 'Add Override' }}</span>
                            </button>
                        </div>
                    </div>
                </div>
            </Transition>

            <!-- Add Suppression From Details Dialog -->
            <Transition
                enter-active-class="transition-opacity duration-200"
                enter-from-class="opacity-0"
                enter-to-class="opacity-100"
                leave-active-class="transition-opacity duration-200"
                leave-from-class="opacity-100"
                leave-to-class="opacity-0"
            >
                <div
                    v-if="showAddSuppressionFromDetails"
                    class="fixed inset-0 z-50 flex items-center justify-center bg-black/50"
                    @click.self="cancelAddSuppressionFromDetails"
                >
                    <div class="bg-card border border-border rounded-xl shadow-2xl w-full max-w-md mx-4 overflow-hidden">
                        <!-- Header -->
                        <div class="px-6 py-4 border-b border-border bg-muted/30">
                            <div class="flex items-center gap-3">
                                <div class="p-2 rounded-lg bg-amber-500/10">
                                    <ShieldOff class="h-5 w-5 text-amber-500" />
                                </div>
                                <h3 class="text-lg font-semibold">Add Suppression</h3>
                            </div>
                        </div>

                        <!-- Content -->
                        <div class="px-6 py-5 space-y-4">
                            <p class="text-sm text-muted-foreground">
                                Add a suppression to prevent this detection from generating alerts for a specific IP address.
                            </p>

                            <!-- Track Type -->
                            <div>
                                <label class="block text-sm font-medium mb-2">Track By</label>
                                <div class="flex gap-2">
                                    <button
                                        @click="newSuppressionTrack = 'by_src'"
                                        :class="cn(
                                            'flex-1 px-4 py-2 text-sm font-medium rounded-lg border transition-colors',
                                            newSuppressionTrack === 'by_src'
                                                ? 'bg-primary text-primary-foreground border-primary'
                                                : 'border-border hover:bg-muted'
                                        )"
                                    >
                                        Source IP
                                    </button>
                                    <button
                                        @click="newSuppressionTrack = 'by_dst'"
                                        :class="cn(
                                            'flex-1 px-4 py-2 text-sm font-medium rounded-lg border transition-colors',
                                            newSuppressionTrack === 'by_dst'
                                                ? 'bg-primary text-primary-foreground border-primary'
                                                : 'border-border hover:bg-muted'
                                        )"
                                    >
                                        Destination IP
                                    </button>
                                </div>
                            </div>

                            <!-- IP Address -->
                            <div>
                                <label class="block text-sm font-medium mb-2">IP Address (CIDR format)</label>
                                <input
                                    v-model="newSuppressionIp"
                                    type="text"
                                    placeholder="e.g., 192.168.1.100 or 10.0.0.0/24"
                                    class="w-full px-3 py-2 text-sm font-mono border border-border rounded-lg bg-background focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent"
                                />
                                <p class="text-xs text-muted-foreground mt-1">
                                    Enter a single IP (e.g., 192.168.1.1) or CIDR range (e.g., 10.0.0.0/24)
                                </p>
                            </div>

                            <div class="bg-muted/50 rounded-lg p-3 text-sm">
                                <div class="flex justify-between text-muted-foreground">
                                    <span>Detection:</span>
                                    <span class="font-medium text-foreground truncate max-w-[200px]" :title="detection?.title">
                                        {{ detection?.title || 'Unknown' }}
                                    </span>
                                </div>
                            </div>
                        </div>

                        <!-- Footer -->
                        <div class="px-6 py-4 border-t border-border bg-muted/30 flex justify-end gap-3">
                            <button
                                @click="cancelAddSuppressionFromDetails"
                                class="px-4 py-2 text-sm font-medium rounded-lg border border-border hover:bg-muted transition-colors"
                            >
                                Cancel
                            </button>
                            <button
                                @click="addSuppressionFromDetails"
                                :disabled="suppressionLoading || !newSuppressionIp.trim()"
                                class="px-4 py-2 text-sm font-medium rounded-lg bg-amber-600 text-white hover:bg-amber-700 transition-colors disabled:opacity-50 flex items-center gap-2"
                            >
                                <Loader2 v-if="suppressionLoading" class="h-4 w-4 animate-spin" />
                                <span>{{ suppressionLoading ? 'Adding...' : 'Add Suppression' }}</span>
                            </button>
                        </div>
                    </div>
                </div>
            </Transition>
        </Teleport>

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
                    class="fixed inset-0 z-50 flex items-center justify-center bg-black/50"
                    @click.self="cancelDisableDetection"
                >
                    <div class="bg-card border border-border rounded-xl shadow-2xl w-full max-w-md mx-4 overflow-hidden">
                        <!-- Header -->
                        <div class="px-6 py-4 border-b border-border bg-muted/30">
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
                                    <span class="font-medium truncate max-w-[200px]" :title="detection?.title">
                                        {{ detection?.title || 'Unknown' }}
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
                                :disabled="detectionUpdating"
                                class="px-4 py-2 text-sm font-medium rounded-lg bg-amber-600 text-white hover:bg-amber-700 transition-colors disabled:opacity-50 flex items-center gap-2"
                            >
                                <Loader2 v-if="detectionUpdating" class="h-4 w-4 animate-spin" />
                                <span>{{ detectionUpdating ? 'Disabling...' : 'Disable Detection' }}</span>
                            </button>
                        </div>
                    </div>
                </div>
            </Transition>
        </Teleport>

        <!-- Escalate Dialog -->
        <EscalateDialog
            ref="escalateDialogRef"
            :open="showEscalateDialog"
            :event="alert"
            :guidedAnalysisEvents="guidedAnalysisEvents"
            :markedEvents="getMarkedEvents()"
            :pcapJob="pcapJob"
            @close="showEscalateDialog = false"
            @confirm="handleEscalateConfirm"
        />
    </div>
</template>

<style scoped>
/* Word wrap for rule content */
.rule-content {
    white-space: pre-wrap;
    word-wrap: break-word;
    word-break: break-word;
    overflow-wrap: anywhere;
}

.rule-content code {
    white-space: pre-wrap;
    word-wrap: break-word;
    word-break: break-word;
    overflow-wrap: anywhere;
    display: block;
}

/* Syntax highlighting classes for detection rules */
:deep(.hl-keyword) {
    @apply text-fuchsia-400 font-semibold;
}
:deep(.hl-string) {
    @apply text-amber-400;
}
:deep(.hl-comment) {
    @apply text-emerald-400;
}
:deep(.hl-number) {
    @apply text-blue-400;
}
:deep(.hl-variable) {
    @apply text-cyan-400;
}
:deep(.hl-operator) {
    @apply text-pink-400;
}
:deep(.hl-action) {
    @apply text-rose-400 font-semibold;
}
:deep(.hl-protocol) {
    @apply text-purple-400;
}
:deep(.hl-option) {
    @apply text-blue-400;
}
</style>
