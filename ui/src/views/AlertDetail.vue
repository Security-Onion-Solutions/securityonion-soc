<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import {
    ArrowLeft,
    Clock,
    Network,
    Shield,
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
    Eye
} from 'lucide-vue-next'
import { cn } from '../lib/utils'
import { useApi } from '../composables/useApi'
import { useTimeRange } from '../composables/useTimeRange'
import { useFormatters } from '../composables/useFormatters'
import { useStatusStyles } from '../composables/useStatusStyles'
import { useHuntActions } from '../composables/useHuntActions'
import { useChatWidget } from '../composables/useChatWidget'
import { usePlaybook, type PlaybookState } from '../composables/usePlaybook'
import type { EventRecord, PlaybookQuestion } from '../types/hunt'

const route = useRoute()
const router = useRouter()

const props = defineProps<{ id?: string }>()
const alertId = computed(() => (route.params.id as string) || props.id || '')

const { get, post } = useApi()
const { formatDate, formatDateForApi } = useFormatters()
const { getSeverityStyles } = useStatusStyles()
const { zone } = useTimeRange()

const {
    acknowledgeEvent,
    escalateToNewCase,
    generateInvestigationPrompt,
    loading: actionLoading
} = useHuntActions()

const { openNewChatWithPrompt } = useChatWidget()
const { loadPlaybook, buildHuntQuery, toggleQuestion, expandAllQuestions, collapseAllQuestions, isQuestionExpanded } = usePlaybook()

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
const detection = ref<Detection | null>(null)
const detectionLoading = ref(false)
const detectionError = ref<string | null>(null)
const showGuidedAnalysis = ref(true)
const playbookState = ref<PlaybookState | null>(null)
const expandedResults = ref<Map<number, any[]>>(new Map())
const loadingResults = ref<Set<number>>(new Set())

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

onMounted(async () => {
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
            eventLimit: '100'
        })

        if (response?.events) {
            // Transform events to match the expected format
            const results = response.events.map((event: any) => ({
                payload: event.payload || {}
            }))
            expandedResults.value.set(questionIndex, results)
        }
    } catch (e) {
        console.error('Failed to load full results:', e)
    } finally {
        loadingResults.value.delete(questionIndex)
    }
}

function collapseResults(questionIndex: number) {
    expandedResults.value.delete(questionIndex)
}

// =============================================================================
// PCAP Functions
// =============================================================================

async function checkExistingPcapJob() {
    if (!alert.value) return

    // Check if this alert has a stored PCAP job ID
    const jobId = alert.value['alert.pcap_id']
    if (!jobId) return

    try {
        const response = await get<PcapJob>(`/api/job/${jobId}`)
        if (response) {
            pcapJob.value = response

            // If job is still pending, start polling
            if (pcapJob.value.status === JOB_STATUS.PENDING) {
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
        // Update the alert with the PCAP job ID so other users can access it
        await post('/api/events/ack', {
            searchFilter: `soc_id:"${alert.value.soc_id}"`,
            eventFilter: { 'soc_id': alert.value.soc_id },
            acknowledge: false,
            escalate: false,
            updateFields: {
                'alert.pcap_id': jobId
            }
        })

        // Update local state
        alert.value['alert.pcap_id'] = jobId
    } catch (e) {
        // Still update local state even if persist fails
        alert.value['alert.pcap_id'] = jobId
        console.debug('Could not persist PCAP job ID to alert:', e)
    }
}

async function refreshPcapJobStatus() {
    if (!pcapJob.value) return

    try {
        const response = await get<PcapJob>(`/api/job/${pcapJob.value.id}`)
        if (response) {
            pcapJob.value = response

            // Stop polling if job is no longer pending
            if (response.status !== JOB_STATUS.PENDING) {
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

async function handleEscalate() {
    if (!alert.value) return
    const caseId = await escalateToNewCase(alert.value)
    if (caseId) {
        router.push({ name: 'case-detail', params: { id: caseId } })
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
        </div>

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
            <!-- Top Section: Rule Name & Actions -->
            <div class="rounded-xl border border-border bg-card p-6 mb-6">
                <div class="flex flex-col lg:flex-row lg:items-start lg:justify-between gap-4">
                    <div class="flex-1">
                        <div class="flex items-center gap-3 mb-2">
                            <Shield class="h-6 w-6 text-primary" />
                            <span class="text-sm text-muted-foreground uppercase tracking-wider">Detection Rule</span>
                        </div>
                        <h2 class="text-xl font-bold leading-tight">{{ getField('rule.name', 'Unknown Rule') }}</h2>
                        <p v-if="alert['rule.description']" class="text-muted-foreground mt-2 text-sm">
                            {{ alert['rule.description'] }}
                        </p>
                    </div>
                    <div class="flex flex-wrap gap-2">
                        <button
                            v-if="!alert['event.acknowledged']"
                            @click="handleAcknowledge(true)"
                            :disabled="actionLoading"
                            class="inline-flex items-center gap-2 px-4 py-2 bg-green-500 text-white rounded-lg hover:bg-green-600 transition-colors font-medium shadow-sm"
                        >
                            <Check class="h-4 w-4" />
                            Acknowledge
                        </button>
                        <button
                            v-else
                            @click="handleAcknowledge(false)"
                            :disabled="actionLoading"
                            class="inline-flex items-center gap-2 px-4 py-2 bg-amber-500 text-white rounded-lg hover:bg-amber-600 transition-colors font-medium shadow-sm"
                        >
                            <X class="h-4 w-4" />
                            Unacknowledge
                        </button>
                        <button
                            @click="handleEscalate"
                            :disabled="actionLoading"
                            class="inline-flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition-colors font-medium shadow-sm"
                        >
                            <Briefcase class="h-4 w-4" />
                            Escalate
                        </button>
                        <button
                            @click="handleInvestigate"
                            :disabled="actionLoading"
                            class="inline-flex items-center gap-2 px-4 py-2 bg-purple-500 text-white rounded-lg hover:bg-purple-600 transition-colors font-medium shadow-sm"
                        >
                            <Sparkles class="h-4 w-4" />
                            AI Investigate
                        </button>
                        <button
                            @click="drillIntoHunt"
                            class="inline-flex items-center gap-2 px-4 py-2 bg-muted text-foreground rounded-lg hover:bg-muted/80 transition-colors font-medium"
                        >
                            <ExternalLink class="h-4 w-4" />
                            Hunt
                        </button>
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
                        <span v-if="detection" class="text-sm text-muted-foreground">({{ detection.engine }})</span>
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
                        <!-- Detection Metadata -->
                        <div class="px-6 py-3 bg-muted/20 flex flex-wrap gap-x-6 gap-y-2 text-sm">
                            <div class="flex items-center gap-1">
                                <span class="text-muted-foreground">Engine:</span>
                                <span class="font-mono font-medium">{{ detection.engine }}</span>
                            </div>
                            <div v-if="detection.author" class="flex items-center gap-1">
                                <span class="text-muted-foreground">Author:</span>
                                <span>{{ detection.author }}</span>
                            </div>
                            <div v-if="detection.category" class="flex items-center gap-1">
                                <span class="text-muted-foreground">Category:</span>
                                <span>{{ detection.category }}</span>
                            </div>
                            <div v-if="detection.ruleset" class="flex items-center gap-1">
                                <span class="text-muted-foreground">Ruleset:</span>
                                <span>{{ detection.ruleset }}</span>
                            </div>
                            <router-link
                                :to="{ name: 'detection-detail', params: { id: detection.id } }"
                                class="ml-auto text-primary hover:underline flex items-center gap-1"
                            >
                                View Detection
                                <ExternalLink class="h-3 w-3" />
                            </router-link>
                        </div>

                        <!-- Rule Content -->
                        <div class="relative">
                            <button
                                @click="copyToClipboard(detection.content)"
                                class="absolute top-3 right-3 p-2 bg-muted hover:bg-muted/80 rounded-md transition-colors text-muted-foreground hover:text-foreground z-10"
                                title="Copy rule content"
                            >
                                <Copy class="h-4 w-4" />
                            </button>
                            <pre class="p-6 font-mono text-sm leading-relaxed bg-card text-foreground select-text selection:bg-primary/20 max-h-96 overflow-y-auto whitespace-pre-wrap break-words"><code v-html="highlightedContent"></code></pre>
                        </div>
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
                                    <div class="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2 flex items-center gap-2">
                                        <Sparkles class="h-3.5 w-3.5" />
                                        Instant Insights
                                    </div>
                                    <div class="text-xs text-muted-foreground mb-2">
                                        Event occurred at {{ formatDate(alert.soc_timestamp || alert['@timestamp']) }}
                                    </div>

                                    <div class="overflow-x-auto rounded border border-border">
                                        <table class="w-full text-sm">
                                            <thead>
                                                <tr class="bg-muted/50">
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
                                                <tr v-for="(result, rIndex) in getVisibleResults(question, qIndex)" :key="rIndex" class="hover:bg-muted/20">
                                                    <td
                                                        v-for="field in question.fields"
                                                        :key="field"
                                                        class="px-3 py-2 font-mono text-xs"
                                                    >
                                                        {{ result.payload?.[field] ?? '-' }}
                                                    </td>
                                                </tr>
                                                <tr v-if="question.queryResults.length === 0">
                                                    <td :colspan="question.fields?.length || 1" class="px-3 py-4 text-center text-muted-foreground text-xs">
                                                        {{ question.error ? 'Error loading results' : 'No data found' }}
                                                    </td>
                                                </tr>
                                            </tbody>
                                        </table>
                                    </div>

                                    <!-- Load All / Collapse Results Button -->
                                    <div class="mt-2 flex items-center gap-2">
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
                                        <button
                                            v-else
                                            @click="collapseResults(qIndex)"
                                            class="text-xs text-muted-foreground hover:text-foreground font-medium flex items-center gap-1"
                                        >
                                            <ChevronUp class="h-3.5 w-3.5" />
                                            Show initial results ({{ question.queryResults?.length || 0 }})
                                        </button>
                                        <span v-if="isResultsExpanded(qIndex)" class="text-xs text-muted-foreground">
                                            Showing {{ getVisibleResults(question, qIndex).length }} results
                                        </span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Cards Grid -->
            <div class="grid gap-4 md:grid-cols-2 lg:grid-cols-4 mb-6">
                <!-- Severity Card -->
                <div class="rounded-xl border border-border bg-card p-5">
                    <div class="flex items-center gap-2 text-muted-foreground mb-3">
                        <AlertTriangle class="h-4 w-4" />
                        <span class="text-sm font-medium">Severity</span>
                    </div>
                    <span :class="cn('inline-flex px-3 py-1.5 rounded-lg text-sm font-bold', getSeverityStyles(getField('event.severity_label', 'unknown')))">
                        {{ getField('event.severity_label', 'unknown').toUpperCase() }}
                    </span>
                </div>

                <!-- Status Card -->
                <div class="rounded-xl border border-border bg-card p-5">
                    <div class="flex items-center gap-2 text-muted-foreground mb-3">
                        <Activity class="h-4 w-4" />
                        <span class="text-sm font-medium">Status</span>
                    </div>
                    <div v-if="alert['event.acknowledged']" class="flex items-center gap-2 text-green-500 font-bold">
                        <CheckCircle class="h-5 w-5" />
                        Acknowledged
                    </div>
                    <div v-else class="flex items-center gap-2 text-muted-foreground font-bold">
                        <X class="h-5 w-5" />
                        Unacknowledged
                    </div>
                </div>

                <!-- Timestamp Card -->
                <div class="rounded-xl border border-border bg-card p-5">
                    <div class="flex items-center gap-2 text-muted-foreground mb-3">
                        <Clock class="h-4 w-4" />
                        <span class="text-sm font-medium">Timestamp</span>
                    </div>
                    <div class="font-semibold">
                        {{ formatDate(alert.soc_timestamp || alert['@timestamp']) }}
                    </div>
                </div>

                <!-- Module Card -->
                <div class="rounded-xl border border-border bg-card p-5">
                    <div class="flex items-center gap-2 text-muted-foreground mb-3">
                        <Server class="h-4 w-4" />
                        <span class="text-sm font-medium">Module</span>
                    </div>
                    <div class="font-mono font-semibold">
                        {{ getField('event.module') }}
                    </div>
                </div>
            </div>

            <!-- Network Flow Card (Compact) -->
            <div class="rounded-xl border border-border bg-card p-4 mb-6">
                <div class="flex items-center flex-wrap gap-x-6 gap-y-2">
                    <div class="flex items-center gap-2 text-muted-foreground">
                        <Network class="h-4 w-4" />
                        <span class="text-sm font-medium">Network</span>
                    </div>

                    <!-- Source → Destination -->
                    <div class="flex items-center gap-2">
                        <span class="font-mono text-sm">
                            {{ getField('source.ip') }}<span v-if="getField('source.port') !== '-'" class="text-muted-foreground">:{{ getField('source.port') }}</span>
                        </span>
                        <span class="text-primary">→</span>
                        <span class="font-mono text-sm">
                            {{ getField('destination.ip') }}<span v-if="getField('destination.port') !== '-'" class="text-muted-foreground">:{{ getField('destination.port') }}</span>
                        </span>
                    </div>

                    <!-- Protocol/Bytes/Direction inline -->
                    <div v-if="getField('network.transport') !== '-'" class="flex items-center gap-1 text-sm">
                        <span class="text-muted-foreground">Protocol:</span>
                        <span class="font-mono uppercase">{{ getField('network.transport') }}</span>
                    </div>
                    <div v-if="getField('network.bytes') !== '-'" class="flex items-center gap-1 text-sm">
                        <span class="text-muted-foreground">Bytes:</span>
                        <span class="font-mono">{{ getField('network.bytes') }}</span>
                    </div>
                    <div v-if="getField('network.direction') !== '-'" class="flex items-center gap-1 text-sm">
                        <span class="text-muted-foreground">Direction:</span>
                        <span>{{ getField('network.direction') }}</span>
                    </div>
                </div>
            </div>

            <!-- Context Cards Row -->
            <div class="grid gap-4 md:grid-cols-3 mb-6">
                <!-- Observer Card -->
                <div v-if="getField('observer.name') !== '-'" class="rounded-xl border border-border bg-card p-5">
                    <div class="flex items-center gap-2 text-muted-foreground mb-3">
                        <MapPin class="h-4 w-4" />
                        <span class="text-sm font-medium">Observer</span>
                    </div>
                    <div class="font-semibold">{{ getField('observer.name') }}</div>
                </div>

                <!-- Dataset Card -->
                <div v-if="getField('event.dataset') !== '-'" class="rounded-xl border border-border bg-card p-5">
                    <div class="flex items-center gap-2 text-muted-foreground mb-3">
                        <FileText class="h-4 w-4" />
                        <span class="text-sm font-medium">Dataset</span>
                    </div>
                    <div class="font-mono font-semibold">{{ getField('event.dataset') }}</div>
                </div>

                <!-- Event ID Card -->
                <div class="rounded-xl border border-border bg-card p-5">
                    <div class="flex items-center gap-2 text-muted-foreground mb-3">
                        <Hash class="h-4 w-4" />
                        <span class="text-sm font-medium">Event ID</span>
                    </div>
                    <div class="flex items-center gap-2">
                        <div class="font-mono text-sm truncate flex-1">{{ alert.soc_id }}</div>
                        <button
                            @click="copyToClipboard(alert.soc_id)"
                            class="p-1.5 hover:bg-muted rounded transition-colors text-muted-foreground hover:text-foreground flex-shrink-0"
                        >
                            <Copy class="h-4 w-4" />
                        </button>
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
                    <div class="divide-y divide-border">
                        <div
                            v-for="[key, value] in allFields"
                            :key="key"
                            class="px-6 py-3 flex items-start gap-4 hover:bg-muted/20 min-w-0"
                        >
                            <div class="w-1/3 font-mono text-sm text-muted-foreground break-words min-w-0 flex-shrink-0">
                                {{ key }}
                            </div>
                            <div class="flex-1 font-mono text-sm break-words min-w-0 overflow-hidden" style="overflow-wrap: anywhere;">
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
    </div>
</template>

<style scoped>
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
