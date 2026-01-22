<script setup lang="ts">
import { ref, onMounted, watch, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import {
  ArrowLeft,
  Code,
  MessageSquare,
  History,
  Settings2,
  BookOpen,
  User,
  ExternalLink,
  ChevronRight,
  Shield,
  Clock,
  Fingerprint,
  RefreshCw,
  CheckCircle2,
  Circle,
  AlertCircle,
  Tag,
  FileText,
  Bot,
  Plus
} from 'lucide-vue-next'
import { cn } from '../lib/utils'
import { useFormatters } from '../composables/useFormatters'
import { useStatusStyles } from '../composables/useStatusStyles'
import { useUsers } from '../composables/useUsers'
import { useChatWidget } from '../composables/useChatWidget'
import { useAssistant } from '../composables/useAssistant'
import { usePlaybook, type Playbook, type GroupedPlaybooks } from '../composables/usePlaybook'
import PlaybookCard from '../components/playbook/PlaybookCard.vue'
import PlaybookEditor from '../components/playbook/PlaybookEditor.vue'

const route = useRoute()
const router = useRouter()

const { formatDate } = useFormatters()
const { getSeverityStyles } = useStatusStyles()
const { getUserName, fetchUsers } = useUsers()
const { expand: expandChatWidget } = useChatWidget()
const { sendMessage, startNewChat, canChat } = useAssistant()
const {
  getPlaybooksForDetectionGrouped,
  createPlaybook,
  updatePlaybook,
  deletePlaybook
} = usePlaybook()

// Get ID from route params (with fallback to props for compatibility)
const props = defineProps<{ id?: string }>()
const detectionId = computed(() => (route.params.id as string) || detectionId.value || '')

const goBack = () => router.push({ name: 'detections' })

interface DetectionComment {
  id: string
  detectionId: string
  value: string
  userId: string
  userName?: string
  createTime: string
  updateTime: string
}

interface HistoryEntry {
  id: string
  updateTime: string
  userId: string
  userName?: string
  kind: string
  operation: string
}

interface Override {
  type: string
  isEnabled: boolean
  note?: string
  createdAt: string
  updatedAt: string
  // Suricata-specific
  regex?: string
  value?: string
  thresholdType?: string
  track?: string
  ip?: string
  count?: number
  seconds?: number
  // ElastAlert-specific
  customFilter?: string
}

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
  isEnabled: boolean
  isReporting: boolean
  isCommunity: boolean
  content: string
  overrides: Override[]
  tags: string[]
  ruleset: string
  license: string
  createTime: string
  updateTime: string
  aiSummary?: string
  aiSummaryReviewed?: boolean
  isAiSummaryStale?: boolean
}

const detection = ref<Detection | null>(null)
const comments = ref<DetectionComment[]>([])
const history = ref<HistoryEntry[]>([])
const loading = ref(true)
const commentsLoading = ref(false)
const historyLoading = ref(false)
const playbookLoading = ref(false)
const error = ref<string | null>(null)
const activeTab = ref('summary')
const newComment = ref('')
const submittingComment = ref(false)
const groupedPlaybooks = ref<GroupedPlaybooks>({ detectionLevel: [], categoryLevel: [], engineLevel: [] })
const playbooksFetched = ref(false)
const showPlaybookEditor = ref(false)
const editingPlaybook = ref<Playbook | null>(null)
const playbookSaving = ref(false)

const tabs = [
  { id: 'summary', name: 'Summary', icon: BookOpen },
  { id: 'logic', name: 'Logic', icon: Code },
  { id: 'comments', name: 'Comments', icon: MessageSquare },
  { id: 'history', name: 'History', icon: History },
  { id: 'tuning', name: 'Tuning', icon: Settings2 },
  { id: 'playbook', name: 'Playbook', icon: Shield }
]

// Extract summary from rule content based on engine type
const extractedSummary = computed(() => {
  if (!detection.value) return ''
  const content = detection.value.content || ''
  const engine = detection.value.engine

  switch (engine) {
    case 'suricata': {
      const classTypeMatch = content.match(/classtype:([^;]+);/i)
      return classTypeMatch ? classTypeMatch[1].trim() : detection.value.title
    }
    case 'elastalert': {
      const descMatch = content.match(/description:\s*['"]?([^'"\n]+)['"]?/i)
      return descMatch ? descMatch[1].trim() : detection.value.description
    }
    default:
      return detection.value.description || detection.value.title
  }
})

// Extract references from rule content
const extractedReferences = computed(() => {
  if (!detection.value) return []
  const content = detection.value.content || ''
  const engine = detection.value.engine
  const refs: { type: string; text: string; link?: string }[] = []

  if (engine === 'suricata') {
    const refRegex = /reference:\s*([^,;]+),\s*([^;]+);/gi
    let match
    while ((match = refRegex.exec(content)) !== null) {
      const type = match[1].trim()
      const value = match[2].trim()
      let link: string | undefined

      if (type === 'cve') {
        link = `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${value}`
      } else if (type === 'url') {
        link = value.startsWith('http') ? value : `https://${value}`
      }

      refs.push({ type, text: value, link })
    }
  } else if (engine === 'elastalert') {
    // Parse YAML references
    const refsMatch = content.match(/references:\s*\n((?:\s+-\s+[^\n]+\n?)*)/i)
    if (refsMatch) {
      const refLines = refsMatch[1].match(/-\s+([^\n]+)/g) || []
      refLines.forEach(line => {
        const value = line.replace(/^-\s+/, '').trim()
        refs.push({
          type: value.includes('://') ? 'url' : 'text',
          text: value,
          link: value.includes('://') ? value : undefined
        })
      })
    }
  }

  return refs
})

// Extract detection logic for display
const extractedLogic = computed(() => {
  if (!detection.value) return ''
  const content = detection.value.content || ''
  const engine = detection.value.engine

  if (engine === 'suricata') {
    // Remove msg, reference, metadata, rev, sid - show detection logic
    let logic = content
      .replace(/msg:"[^"]*";\s*/gi, '')
      .replace(/reference:[^;]*;\s*/gi, '')
      .replace(/metadata:[^;]*;\s*/gi, '')
      .replace(/sid:\s*\d+;\s*/gi, '')
      .replace(/rev:\s*\d+;\s*/gi, '')
      .replace(/classtype:[^;]*;\s*/gi, '')
    // Extract just the options portion (inside parentheses)
    const optionsMatch = logic.match(/\(([^)]+)\)/s)
    return optionsMatch ? optionsMatch[1].trim() : logic
  } else if (engine === 'elastalert') {
    // Extract logsource and detection sections
    const logsourceMatch = content.match(/(logsource:\s*\n(?:\s+[^\n]+\n?)*)/i)
    const detectionMatch = content.match(/(detection:\s*\n(?:\s+[^\n]+\n?)*)/i)
    const parts = []
    if (logsourceMatch) parts.push(logsourceMatch[1].trim())
    if (detectionMatch) parts.push(detectionMatch[1].trim())
    return parts.join('\n')
  } else if (engine === 'strelka') {
    // Extract strings and condition
    const stringsMatch = content.match(/(strings:\s*\n(?:\s+[^\n]+\n?)*)/i)
    const conditionMatch = content.match(/(condition:\s*[^\n]+)/i)
    const parts = []
    if (stringsMatch) parts.push(stringsMatch[1].trim())
    if (conditionMatch) parts.push(conditionMatch[1].trim())
    return parts.join('\n')
  }

  return content
})

const extractedLogicClass = computed(() => {
  if (!detection.value) return 'language-text'
  const engine = detection.value.engine
  switch (engine) {
    case 'elastalert':
      return 'language-yaml'
    case 'strelka':
      return 'language-c' // YARA is similar to C syntax
    default:
      return 'language-text'
  }
})

const fetchDetectionDetail = async () => {
  loading.value = true
  error.value = null

  try {
    const response = await fetch(`/api/detection/${detectionId.value}`)
    if (!response.ok) {
      if (response.status === 404) {
        throw new Error('Detection not found')
      }
      throw new Error(`Failed to fetch detection details: ${response.status}`)
    }
    detection.value = await response.json()
  } catch (err: any) {
    console.error('Error fetching detection detail:', err)
    error.value = err.message
    detection.value = null
  } finally {
    loading.value = false
  }
}

const fetchComments = async () => {
  if (!detection.value) return
  commentsLoading.value = true

  try {
    const response = await fetch(`/api/detection/${detectionId.value}/comment`)
    if (!response.ok) {
      throw new Error('Failed to fetch comments')
    }
    const data = await response.json()
    comments.value = (data || []).map((c: any) => ({
      ...c,
      userName: getUserName(c.userId) || c.userId
    }))
  } catch (err) {
    console.error('Error fetching comments:', err)
    comments.value = []
  } finally {
    commentsLoading.value = false
  }
}

const fetchHistory = async () => {
  if (!detection.value) return
  historyLoading.value = true

  try {
    const response = await fetch(`/api/detection/${detectionId.value}/history`)
    if (!response.ok) {
      throw new Error('Failed to fetch history')
    }
    const data = await response.json()
    history.value = (data || []).map((h: any) => ({
      ...h,
      userName: getUserName(h.userId) || h.userId
    }))
  } catch (err) {
    console.error('Error fetching history:', err)
    history.value = []
  } finally {
    historyLoading.value = false
  }
}

const fetchPlaybooks = async () => {
  if (!detection.value) return
  playbookLoading.value = true

  try {
    const data = await getPlaybooksForDetectionGrouped(detection.value.publicId)
    console.log('Fetched grouped playbooks:', data)
    groupedPlaybooks.value = data
  } catch (err) {
    console.error('Error fetching playbooks:', err)
    groupedPlaybooks.value = { detectionLevel: [], categoryLevel: [], engineLevel: [] }
  } finally {
    playbookLoading.value = false
    playbooksFetched.value = true
  }
}

// Computed for total playbook count
const totalPlaybookCount = computed(() => {
  const g = groupedPlaybooks.value
  return g.detectionLevel.length + g.categoryLevel.length + g.engineLevel.length
})

const openCreatePlaybook = () => {
  editingPlaybook.value = null
  showPlaybookEditor.value = true
}

const openEditPlaybook = (playbook: Playbook) => {
  editingPlaybook.value = playbook
  showPlaybookEditor.value = true
}

const handleSavePlaybook = async (playbook: Playbook) => {
  if (!detection.value) return
  playbookSaving.value = true

  try {
    if (playbook.id) {
      await updatePlaybook(playbook)
    } else {
      // Ensure detection association for new playbooks
      playbook.detection_id = detection.value.publicId
      playbook.detection_category = detection.value.category
      playbook.detection_type = detection.value.engine
      await createPlaybook(playbook)
    }
    showPlaybookEditor.value = false
    editingPlaybook.value = null
    await fetchPlaybooks()
  } catch (err) {
    console.error('Error saving playbook:', err)
  } finally {
    playbookSaving.value = false
  }
}

const handleDeletePlaybook = async (playbook: Playbook) => {
  if (!playbook.id) return

  if (!confirm(`Are you sure you want to delete the playbook "${playbook.name}"?`)) {
    return
  }

  try {
    await deletePlaybook(playbook.id)
    await fetchPlaybooks()
  } catch (err) {
    console.error('Error deleting playbook:', err)
  }
}

const handleCancelEditor = () => {
  showPlaybookEditor.value = false
  editingPlaybook.value = null
}

const handleDuplicatePlaybook = (playbook: Playbook) => {
  // Create a copy without the id (so it creates a new one)
  const duplicate: Playbook = {
    name: `${playbook.name} (Copy)`,
    description: playbook.description,
    detection_id: playbook.detection_id || detection.value?.publicId,
    detection_category: playbook.detection_category,
    detection_type: playbook.detection_type,
    contributors: playbook.contributors ? [...playbook.contributors] : [],
    questions: playbook.questions ? playbook.questions.map(q => ({ ...q })) : []
    // Note: no id, isCommunity, or ruleset - these will be set by the backend
  }
  editingPlaybook.value = duplicate
  showPlaybookEditor.value = true
}

const submitComment = async () => {
  if (!newComment.value.trim() || !detection.value) return
  submittingComment.value = true

  try {
    const response = await fetch(`/api/detection/${detectionId.value}/comment`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ value: newComment.value })
    })

    if (!response.ok) {
      throw new Error('Failed to post comment')
    }

    newComment.value = ''
    await fetchComments()
  } catch (err) {
    console.error('Error posting comment:', err)
  } finally {
    submittingComment.value = false
  }
}

const copyToClipboard = async (text: string) => {
  try {
    await navigator.clipboard.writeText(text)
  } catch (err) {
    console.error('Failed to copy to clipboard', err)
  }
}

const toggleEnabled = async () => {
  if (!detection.value) return
  const previousState = detection.value.isEnabled
  detection.value.isEnabled = !detection.value.isEnabled

  try {
    const updateResponse = await fetch('/api/detection', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(detection.value)
    })

    if (!updateResponse.ok) {
      throw new Error('Failed to update detection')
    }

    const updatedDetection = await updateResponse.json()
    detection.value = updatedDetection
  } catch (err) {
    console.error('Error toggling detection:', err)
    if (detection.value) {
      detection.value.isEnabled = previousState
    }
  }
}

const investigateWithAI = async () => {
  if (!detection.value || !canChat.value) return

  // Build an investigation prompt about this detection
  const prompt = `I'm looking at a detection rule and need your help analyzing it.

**Detection Details:**
- **Title:** ${detection.value.title}
- **Public ID:** ${detection.value.publicId}
- **Severity:** ${detection.value.severity}
- **Engine:** ${detection.value.engine}
- **Author:** ${detection.value.author}
${detection.value.description ? `- **Description:** ${detection.value.description}` : ''}
${detection.value.category ? `- **Category:** ${detection.value.category}` : ''}
${detection.value.tags?.length > 0 ? `- **Tags:** ${detection.value.tags.join(', ')}` : ''}

Please help me:
1. Explain what this detection rule looks for and what kind of threat or activity it detects
2. Query for recent alerts from this detection (search for rule.name:"${detection.value.title}" or the public ID)
3. If you find any alerts, use the playbook tool to get the investigation steps for those alerts
4. Summarize what I should investigate and any potential false positive scenarios`

  // Start a new chat for this investigation
  startNewChat()

  // Expand the chat widget
  expandChatWidget()

  // Send the investigation prompt after a brief delay to let the widget open
  setTimeout(() => {
    sendMessage(prompt)
  }, 300)
}

// Watch for tab changes to load data lazily
watch(activeTab, (tab) => {
  if (tab === 'comments' && comments.value.length === 0 && !commentsLoading.value) {
    fetchComments()
  }
  if (tab === 'history' && history.value.length === 0 && !historyLoading.value) {
    fetchHistory()
  }
  if (tab === 'playbook' && !playbooksFetched.value && !playbookLoading.value) {
    fetchPlaybooks()
  }
})

onMounted(async () => {
  // Check for tab query parameter
  const tabParam = route.query.tab as string
  const validTabs = tabs.map(t => t.id)
  if (tabParam && validTabs.includes(tabParam)) {
    activeTab.value = tabParam
  }

  await fetchDetectionDetail()
  // Pre-fetch comments and history for a smoother experience
  if (detection.value) {
    fetchComments()
    fetchHistory()
  }
  fetchUsers()
})
</script>

<template>
  <div class="space-y-6 animate-in slide-in-from-right duration-500">
    <!-- Header -->
    <div class="flex flex-col gap-4">
      <button @click="goBack()" class="flex items-center gap-2 text-sm text-muted-foreground hover:text-primary transition-colors w-fit group">
        <ArrowLeft class="h-4 w-4 group-hover:-translate-x-1 transition-transform" />
        Back to Detections
      </button>

      <!-- Error State -->
      <div v-if="error && !detection" class="p-8 rounded-xl bg-red-500/10 border border-red-500/20 text-center">
        <AlertCircle class="h-12 w-12 text-red-500 mx-auto mb-4" />
        <h3 class="text-lg font-semibold text-red-500 mb-2">Error Loading Detection</h3>
        <p class="text-muted-foreground">{{ error }}</p>
        <button @click="fetchDetectionDetail" class="mt-4 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90">
          Try Again
        </button>
      </div>

      <div v-if="detection" class="flex flex-col md:flex-row md:items-start md:justify-between gap-4">
        <div class="space-y-2">
          <div class="flex items-center gap-3 flex-wrap">
             <span :class="cn('px-2.5 py-0.5 rounded-full text-xs font-bold border', getSeverityStyles(detection.severity))">
                {{ detection.severity }}
             </span>
             <span class="text-xs font-medium text-muted-foreground uppercase tracking-widest">{{ detection.engine }}</span>
             <span v-if="detection.isCommunity" class="text-xs font-medium text-blue-500 bg-blue-500/10 px-2 py-0.5 rounded">Community</span>
             <span v-if="detection.language" class="text-xs font-medium text-muted-foreground bg-muted px-2 py-0.5 rounded">{{ detection.language }}</span>
          </div>
          <h2 class="text-3xl font-bold tracking-tight text-foreground">{{ detection.title }}</h2>
          <div class="flex items-center gap-4 text-sm text-muted-foreground flex-wrap">
             <div class="flex items-center gap-1.5 font-mono">
                <Fingerprint class="h-4 w-4 text-primary" />
                {{ detection.publicId }}
             </div>
             <div class="flex items-center gap-1.5">
                <User class="h-4 w-4" />
                {{ detection.author }}
             </div>
             <div class="flex items-center gap-1.5">
                <Clock class="h-4 w-4" />
                Updated {{ formatDate(detection.updateTime || detection.createTime) }}
             </div>
             <div v-if="detection.ruleset" class="flex items-center gap-1.5">
                <FileText class="h-4 w-4" />
                {{ detection.ruleset }}
             </div>
          </div>
          <!-- Tags -->
          <div v-if="detection.tags?.length > 0" class="flex items-center gap-2 flex-wrap pt-2">
            <Tag class="h-4 w-4 text-muted-foreground" />
            <span v-for="tag in detection.tags" :key="tag" class="text-xs bg-muted px-2 py-0.5 rounded">{{ tag }}</span>
          </div>
        </div>

        <div class="flex items-center gap-2">
           <button
             @click="toggleEnabled"
             :disabled="detection.isCommunity"
             :class="cn(
               'px-4 py-2 rounded-md font-medium transition-all shadow-lg active:scale-95',
               detection.isEnabled ? 'bg-red-500/10 text-red-500 hover:bg-red-500/20' : 'bg-green-500 text-white hover:bg-green-600',
               detection.isCommunity && 'opacity-50 cursor-not-allowed'
             )"
           >
             {{ detection.isEnabled ? 'Disable Rule' : 'Enable Rule' }}
           </button>
           <button
             v-if="!detection.isCommunity"
             class="px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 transition-all shadow-lg active:scale-95"
           >
             Edit Rule
           </button>
        </div>
      </div>
    </div>

    <div v-if="loading" class="h-64 flex items-center justify-center">
        <RefreshCw class="h-8 w-8 text-primary animate-spin" />
    </div>

    <div v-else-if="detection" class="grid grid-cols-1 lg:grid-cols-4 gap-8">
      <!-- Sidebar Navigation -->
      <div class="lg:col-span-1 space-y-1">
        <button
          v-for="tab in tabs"
          :key="tab.id"
          @click="activeTab = tab.id"
          :class="cn(
            'w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all text-left border-2',
            activeTab === tab.id
              ? 'bg-primary/10 text-primary border-primary/20'
              : 'text-muted-foreground hover:bg-muted/50 border-transparent'
          )"
        >
          <component :is="tab.icon" class="h-5 w-5" />
          {{ tab.name }}
          <ChevronRight v-if="activeTab === tab.id" class="h-4 w-4 ml-auto" />
        </button>

        <!-- AI Investigation Button -->
        <div class="pt-4 mt-4 border-t border-border">
          <button
            @click="investigateWithAI"
            :disabled="!canChat"
            :class="cn(
              'w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all text-left border-2',
              'bg-gradient-to-r from-primary/10 to-purple-500/10 text-primary border-primary/20 hover:from-primary/20 hover:to-purple-500/20',
              !canChat && 'opacity-50 cursor-not-allowed'
            )"
          >
            <Bot class="h-5 w-5" />
            Ask AI
            <span class="ml-auto text-xs bg-primary/20 px-1.5 py-0.5 rounded">New</span>
          </button>
          <p class="text-xs text-muted-foreground mt-2 px-2">
            Get AI insights about this detection and check for recent alerts
          </p>
        </div>
      </div>

      <!-- Content Area -->
      <div class="lg:col-span-3 min-h-[500px]">
        <div class="bg-card border border-border rounded-xl shadow-sm overflow-hidden min-h-full flex flex-col">
          <!-- Summary Tab -->
          <div v-if="activeTab === 'summary'" class="p-8 space-y-8 animate-in fade-in duration-500">
             <!-- AI Summary if available -->
             <section v-if="detection.aiSummary" class="space-y-3">
                <h3 class="text-lg font-semibold flex items-center gap-2">
                    <Shield class="h-5 w-5 text-primary" />
                    AI Summary
                    <span v-if="detection.isAiSummaryStale" class="text-xs bg-amber-500/10 text-amber-500 px-2 py-0.5 rounded">Stale</span>
                </h3>
                <p class="text-muted-foreground leading-relaxed bg-muted/30 p-4 rounded-lg border border-border">{{ detection.aiSummary }}</p>
             </section>

             <section class="space-y-3">
                <h3 class="text-lg font-semibold flex items-center gap-2">
                    <BookOpen class="h-5 w-5 text-primary" />
                    Description
                </h3>
                <p class="text-muted-foreground leading-relaxed">{{ detection.description || extractedSummary }}</p>
             </section>

             <section v-if="extractedReferences.length > 0" class="space-y-3">
                <h3 class="text-lg font-semibold flex items-center gap-2">
                    <ExternalLink class="h-5 w-5 text-primary" />
                    References
                </h3>
                <ul class="grid md:grid-cols-2 gap-3">
                    <li v-for="ref in extractedReferences" :key="ref.text" class="flex items-center gap-2 p-3 bg-muted/30 rounded-lg border border-border group hover:border-primary/50 transition-colors">
                        <span class="text-xs font-bold uppercase py-0.5 px-2 bg-primary/10 text-primary rounded">{{ ref.type }}</span>
                        <a v-if="ref.link" :href="ref.link" target="_blank" class="text-sm font-medium hover:text-primary transition-colors flex items-center gap-1">
                            {{ ref.text }}
                            <ExternalLink class="h-3 w-3 opacity-0 group-hover:opacity-100 transition-opacity" />
                        </a>
                        <span v-else class="text-sm font-medium">{{ ref.text }}</span>
                    </li>
                </ul>
             </section>

             <section class="grid md:grid-cols-2 gap-8">
                <div class="space-y-3">
                    <h3 class="text-lg font-semibold">Metadata</h3>
                    <div class="space-y-4">
                        <div class="flex items-center justify-between py-2 border-b border-border text-sm">
                            <span class="text-muted-foreground">Status</span>
                            <span :class="detection.isEnabled ? 'text-green-500' : 'text-amber-500'" class="font-bold flex items-center gap-1.5">
                                <CheckCircle2 v-if="detection.isEnabled" class="h-4 w-4" />
                                <Circle v-else class="h-4 w-4" />
                                {{ detection.isEnabled ? 'Active' : 'Disabled' }}
                            </span>
                        </div>
                        <div class="flex items-center justify-between py-2 border-b border-border text-sm">
                            <span class="text-muted-foreground">Reporting</span>
                            <span :class="detection.isReporting ? 'text-blue-500' : 'text-muted-foreground'" class="font-bold">
                                {{ detection.isReporting ? 'Enabled' : 'Disabled' }}
                            </span>
                        </div>
                        <div v-if="detection.license" class="flex items-center justify-between py-2 border-b border-border text-sm">
                            <span class="text-muted-foreground">License</span>
                            <span class="font-medium text-foreground">{{ detection.license }}</span>
                        </div>
                        <div v-if="detection.overrides?.length > 0" class="flex items-center justify-between py-2 border-b border-border text-sm">
                            <span class="text-muted-foreground">Overrides</span>
                            <span class="font-medium text-foreground">{{ detection.overrides.length }} active</span>
                        </div>
                    </div>
                </div>
                <div class="space-y-3">
                    <h3 class="text-lg font-semibold">Registry</h3>
                    <div class="space-y-4">
                        <div class="flex items-center justify-between py-2 border-b border-border text-sm">
                            <span class="text-muted-foreground">Created</span>
                            <span class="font-medium text-foreground">{{ formatDate(detection.createTime) }}</span>
                        </div>
                        <div class="flex items-center justify-between py-2 border-b border-border text-sm">
                            <span class="text-muted-foreground">Last Modified</span>
                            <span class="font-medium text-foreground">{{ formatDate(detection.updateTime) }}</span>
                        </div>
                        <div v-if="detection.category" class="flex items-center justify-between py-2 border-b border-border text-sm">
                            <span class="text-muted-foreground">Category</span>
                            <span class="font-medium text-foreground">{{ detection.category }}</span>
                        </div>
                    </div>
                </div>
             </section>
          </div>

          <!-- Logic Tab -->
          <div v-else-if="activeTab === 'logic'" class="flex flex-col h-full animate-in fade-in duration-500">
             <div class="p-4 border-b border-border bg-muted/20 flex items-center justify-between">
                <span class="text-sm font-mono text-muted-foreground">{{ detection.engine }} source code ({{ detection.language }})</span>
                <button
                  @click="copyToClipboard(detection.content)"
                  class="text-xs font-semibold px-2 py-1 bg-primary/10 text-primary rounded hover:bg-primary/20 transition-colors"
                >
                  Copy to Clipboard
                </button>
             </div>
             <pre class="flex-1 p-6 font-mono text-sm leading-relaxed overflow-auto bg-card text-foreground select-text selection:bg-primary/20"><code>{{ detection.content }}</code></pre>
             <div v-if="extractedLogic" class="p-6 bg-muted/30 border-t border-border mt-auto">
                <h4 class="text-sm font-bold uppercase mb-3 text-muted-foreground tracking-widest">Extracted Logic</h4>
                <div :class="cn('p-4 bg-black/10 rounded-lg border border-border shadow-inner font-mono text-xs whitespace-pre-wrap leading-loose', extractedLogicClass)">{{ extractedLogic }}</div>
             </div>
          </div>

          <!-- Comments Tab -->
          <div v-else-if="activeTab === 'comments'" class="p-8 space-y-6 animate-in fade-in duration-500">
             <div v-if="commentsLoading" class="h-32 flex items-center justify-center">
                <RefreshCw class="h-6 w-6 text-primary animate-spin" />
             </div>
             <div v-else-if="comments.length > 0" class="space-y-4">
                <div v-for="comment in comments" :key="comment.id" class="p-4 rounded-xl bg-muted/30 border border-border space-y-2 group relative">
                    <div class="flex items-center justify-between">
                        <span class="text-sm font-bold text-primary">{{ comment.userName || comment.userId }}</span>
                        <span class="text-xs text-muted-foreground">{{ formatDate(comment.createTime) }}</span>
                    </div>
                    <p class="text-sm text-foreground leading-relaxed whitespace-pre-wrap">{{ comment.value }}</p>
                    <div v-if="comment.updateTime !== comment.createTime" class="text-xs text-muted-foreground italic">
                      Edited {{ formatDate(comment.updateTime) }}
                    </div>
                </div>
             </div>
             <div v-else class="h-32 flex items-center justify-center text-muted-foreground italic border-2 border-dashed border-border rounded-xl">
                No comments yet.
             </div>
             <div class="mt-8 space-y-4">
                <h4 class="text-sm font-bold">Add a Comment</h4>
                <textarea
                    v-model="newComment"
                    placeholder="Write your analysis or notes here..."
                    class="w-full h-32 p-4 bg-muted/20 border border-border rounded-xl focus:outline-none focus:ring-2 focus:ring-primary/50 transition-all text-sm"
                ></textarea>
                <div class="flex justify-end">
                    <button
                      @click="submitComment"
                      :disabled="!newComment.trim() || submittingComment"
                      :class="cn(
                        'px-6 py-2 bg-primary text-primary-foreground rounded-lg font-medium shadow-md hover:shadow-lg transition-all active:scale-95',
                        (!newComment.trim() || submittingComment) && 'opacity-50 cursor-not-allowed'
                      )"
                    >
                      {{ submittingComment ? 'Posting...' : 'Post Comment' }}
                    </button>
                </div>
             </div>
          </div>

          <!-- History Tab -->
          <div v-else-if="activeTab === 'history'" class="p-8 animate-in fade-in duration-500">
             <div v-if="historyLoading" class="h-32 flex items-center justify-center">
                <RefreshCw class="h-6 w-6 text-primary animate-spin" />
             </div>
             <div v-else-if="history.length > 0" class="rounded-xl border border-border overflow-hidden">
                <table class="w-full text-sm">
                    <thead>
                        <tr class="bg-muted/30 border-b border-border">
                            <th class="px-6 py-3 text-left font-semibold text-muted-foreground">Time</th>
                            <th class="px-6 py-3 text-left font-semibold text-muted-foreground">User</th>
                            <th class="px-6 py-3 text-left font-semibold text-muted-foreground">Kind</th>
                            <th class="px-6 py-3 text-left font-semibold text-muted-foreground">Operation</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-border">
                        <tr v-for="entry in history" :key="entry.id" class="hover:bg-muted/20 transition-colors">
                            <td class="px-6 py-4 text-muted-foreground">{{ formatDate(entry.updateTime) }}</td>
                            <td class="px-6 py-4 font-medium">{{ entry.userName || entry.userId }}</td>
                            <td class="px-6 py-4">
                                <span class="px-2 py-0.5 rounded text-xs font-bold uppercase bg-muted text-muted-foreground">
                                  {{ entry.kind }}
                                </span>
                            </td>
                            <td class="px-6 py-4">
                                <span :class="cn(
                                    'px-2 py-0.5 rounded text-xs font-bold uppercase',
                                    entry.operation === 'create' ? 'bg-blue-500/10 text-blue-500' :
                                    entry.operation === 'delete' ? 'bg-red-500/10 text-red-500' :
                                    'bg-green-500/10 text-green-500'
                                )">{{ entry.operation }}</span>
                            </td>
                        </tr>
                    </tbody>
                </table>
             </div>
             <div v-else class="h-32 flex items-center justify-center text-muted-foreground italic border-2 border-dashed border-border rounded-xl">
                No history available.
             </div>
          </div>

          <!-- Tuning Tab -->
          <div v-else-if="activeTab === 'tuning'" class="p-8 animate-in fade-in duration-500">
             <div v-if="detection.overrides?.length > 0" class="space-y-6">
                <div class="flex items-center justify-between">
                   <h3 class="text-lg font-semibold">Active Overrides</h3>
                   <span class="text-sm text-muted-foreground">{{ detection.overrides.length }} override(s)</span>
                </div>
                <div class="space-y-4">
                   <div v-for="(override, index) in detection.overrides" :key="index" class="p-4 rounded-xl bg-muted/30 border border-border space-y-3">
                      <div class="flex items-center justify-between">
                         <div class="flex items-center gap-3">
                            <span :class="cn(
                              'px-2 py-0.5 rounded text-xs font-bold uppercase',
                              override.isEnabled ? 'bg-green-500/10 text-green-500' : 'bg-muted text-muted-foreground'
                            )">
                              {{ override.isEnabled ? 'Enabled' : 'Disabled' }}
                            </span>
                            <span class="px-2 py-0.5 rounded text-xs font-bold uppercase bg-primary/10 text-primary">
                              {{ override.type }}
                            </span>
                         </div>
                         <span class="text-xs text-muted-foreground">
                            Updated {{ formatDate(override.updatedAt) }}
                         </span>
                      </div>

                      <!-- Override-specific fields -->
                      <div class="text-sm space-y-2">
                         <!-- Suppress Override (Suricata) -->
                         <template v-if="override.type === 'suppress'">
                            <div class="flex gap-4">
                               <span class="text-muted-foreground">Track:</span>
                               <span class="font-mono">{{ override.track }}</span>
                            </div>
                            <div class="flex gap-4">
                               <span class="text-muted-foreground">IP:</span>
                               <span class="font-mono">{{ override.ip }}</span>
                            </div>
                         </template>

                         <!-- Threshold Override (Suricata) -->
                         <template v-else-if="override.type === 'threshold'">
                            <div class="flex gap-4">
                               <span class="text-muted-foreground">Type:</span>
                               <span class="font-mono">{{ override.thresholdType }}</span>
                            </div>
                            <div class="flex gap-4">
                               <span class="text-muted-foreground">Track:</span>
                               <span class="font-mono">{{ override.track }}</span>
                            </div>
                            <div class="flex gap-4">
                               <span class="text-muted-foreground">Count:</span>
                               <span class="font-mono">{{ override.count }} / {{ override.seconds }}s</span>
                            </div>
                         </template>

                         <!-- Modify Override (Suricata) -->
                         <template v-else-if="override.type === 'modify'">
                            <div class="flex gap-4">
                               <span class="text-muted-foreground">Regex:</span>
                               <span class="font-mono text-xs bg-black/10 px-2 py-1 rounded">{{ override.regex }}</span>
                            </div>
                            <div class="flex gap-4">
                               <span class="text-muted-foreground">Value:</span>
                               <span class="font-mono text-xs bg-black/10 px-2 py-1 rounded">{{ override.value }}</span>
                            </div>
                         </template>

                         <!-- Custom Filter (ElastAlert) -->
                         <template v-else-if="override.type === 'customFilter'">
                            <div class="space-y-2">
                               <span class="text-muted-foreground">Custom Filter:</span>
                               <pre class="font-mono text-xs bg-black/10 p-3 rounded overflow-auto">{{ override.customFilter }}</pre>
                            </div>
                         </template>
                      </div>

                      <!-- Note if present -->
                      <div v-if="override.note" class="pt-2 border-t border-border">
                         <span class="text-xs text-muted-foreground">Note:</span>
                         <p class="text-sm text-foreground mt-1">{{ override.note }}</p>
                      </div>
                   </div>
                </div>
             </div>
             <div v-else class="h-64 flex flex-col items-center justify-center text-muted-foreground">
                <Settings2 class="h-12 w-12 mb-4 opacity-20" />
                <p class="text-center">No tuning overrides configured for this detection.</p>
                <p class="text-sm text-center mt-2">
                   {{ detection.engine === 'strelka' ? 'Strelka (YARA) rules do not support overrides.' : 'Use the classic interface to add overrides.' }}
                </p>
             </div>
          </div>

          <!-- Playbook Tab -->
          <div v-else-if="activeTab === 'playbook'" class="flex flex-col h-full animate-in fade-in duration-500">
             <div v-if="playbookLoading" class="h-64 flex items-center justify-center">
                <RefreshCw class="h-8 w-8 text-primary animate-spin" />
             </div>
             <div v-else class="flex flex-col h-full">
                <!-- Toolbar -->
                <div class="p-4 border-b border-border bg-muted/20 flex items-center justify-between">
                   <div class="flex items-center gap-3">
                      <Shield class="h-5 w-5 text-primary" />
                      <span class="text-sm font-medium">
                         {{ totalPlaybookCount }} playbook{{ totalPlaybookCount !== 1 ? 's' : '' }} available
                      </span>
                   </div>
                   <button
                     @click="openCreatePlaybook"
                     class="flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium text-primary-foreground bg-primary hover:bg-primary/90 rounded-lg transition-colors"
                   >
                     <Plus class="h-4 w-4" />
                     Add Playbook
                   </button>
                </div>

                <!-- Playbook List - Grouped by Level -->
                <div v-if="totalPlaybookCount > 0" class="flex-1 overflow-y-auto p-6 space-y-6">
                   <!-- Detection Level Playbooks -->
                   <div v-if="groupedPlaybooks.detectionLevel.length > 0" class="space-y-3">
                      <h4 class="text-sm font-semibold text-primary flex items-center gap-2">
                         <Fingerprint class="h-4 w-4" />
                         Detection-Specific Playbooks
                         <span class="text-xs font-normal text-muted-foreground">({{ groupedPlaybooks.detectionLevel.length }})</span>
                      </h4>
                      <div class="space-y-3">
                         <PlaybookCard
                           v-for="pb in groupedPlaybooks.detectionLevel"
                           :key="pb.id || pb.name"
                           :playbook="pb"
                           :current-detection-id="detection?.publicId"
                           @edit="openEditPlaybook(pb)"
                           @delete="handleDeletePlaybook(pb)"
                           @duplicate="handleDuplicatePlaybook(pb)"
                         />
                      </div>
                   </div>

                   <!-- Category Level Playbooks -->
                   <div v-if="groupedPlaybooks.categoryLevel.length > 0" class="space-y-3">
                      <h4 class="text-sm font-semibold text-blue-500 flex items-center gap-2">
                         <Tag class="h-4 w-4" />
                         Category Playbooks
                         <span class="text-xs font-normal text-muted-foreground">({{ groupedPlaybooks.categoryLevel.length }})</span>
                      </h4>
                      <p class="text-xs text-muted-foreground -mt-1">
                         Applies to all {{ detection?.category }} detections
                      </p>
                      <div class="space-y-3">
                         <PlaybookCard
                           v-for="pb in groupedPlaybooks.categoryLevel"
                           :key="pb.id || pb.name"
                           :playbook="pb"
                           :current-detection-id="detection?.publicId"
                           @edit="openEditPlaybook(pb)"
                           @delete="handleDeletePlaybook(pb)"
                           @duplicate="handleDuplicatePlaybook(pb)"
                         />
                      </div>
                   </div>

                   <!-- Engine Level Playbooks -->
                   <div v-if="groupedPlaybooks.engineLevel.length > 0" class="space-y-3">
                      <h4 class="text-sm font-semibold text-amber-500 flex items-center gap-2">
                         <Shield class="h-4 w-4" />
                         Engine Playbooks
                         <span class="text-xs font-normal text-muted-foreground">({{ groupedPlaybooks.engineLevel.length }})</span>
                      </h4>
                      <p class="text-xs text-muted-foreground -mt-1">
                         Applies to all {{ detection?.engine }} detections
                      </p>
                      <div class="space-y-3">
                         <PlaybookCard
                           v-for="pb in groupedPlaybooks.engineLevel"
                           :key="pb.id || pb.name"
                           :playbook="pb"
                           :current-detection-id="detection?.publicId"
                           @edit="openEditPlaybook(pb)"
                           @delete="handleDeletePlaybook(pb)"
                           @duplicate="handleDuplicatePlaybook(pb)"
                         />
                      </div>
                   </div>
                </div>

                <!-- Empty State -->
                <div v-else class="flex-1 flex flex-col items-center justify-center p-8 text-center text-muted-foreground">
                   <Shield class="h-16 w-16 mb-4 opacity-10" />
                   <h3 class="text-lg font-semibold mb-2">No Playbooks Available</h3>
                   <p class="max-w-sm text-sm mb-4">
                      No playbooks have been configured for this detection.
                      Playbooks provide investigation guidance and pre-built queries for analyzing alerts.
                   </p>
                   <button
                     @click="openCreatePlaybook"
                     class="flex items-center gap-1.5 px-4 py-2 text-sm font-medium text-primary-foreground bg-primary hover:bg-primary/90 rounded-lg transition-colors"
                   >
                     <Plus class="h-4 w-4" />
                     Create First Playbook
                   </button>
                </div>
             </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Playbook Editor Modal -->
    <PlaybookEditor
      v-if="showPlaybookEditor"
      :playbook="editingPlaybook"
      :detection-id="detection?.publicId"
      :detection-category="detection?.category"
      :detection-type="detection?.engine"
      @save="handleSavePlaybook"
      @cancel="handleCancelEditor"
    />
  </div>
</template>
