<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import {
  ArrowLeft,
  MessageSquare,
  History,
  User,
  Briefcase,
  Clock,
  Paperclip,
  FileText,
  Activity,
  CheckSquare,
  ChevronRight,
  Info,
  Send,
  Loader2,
  Eye,
  Edit3,
  File,
  Crosshair,
  Sparkles,
  Star,
  StickyNote,
  ArrowUpDown,
  X,
  Save
} from 'lucide-vue-next'
import { marked } from 'marked'
import DOMPurify from 'dompurify'
import { cn } from '../lib/utils'
import { useUsers } from '../composables/useUsers'
import { useFormatters } from '../composables/useFormatters'
import { useApi } from '../composables/useApi'
import { useChatWidget } from '../composables/useChatWidget'
import AttachmentsPanel from '../components/cases/AttachmentsPanel.vue'
import EvidencePanel from '../components/cases/EvidencePanel.vue'

const route = useRoute()
const router = useRouter()

const { getUserName } = useUsers()
const { formatDate, formatDateOnly } = useFormatters()
const { post } = useApi()
const { openNewChatWithPrompt } = useChatWidget()

// Configure marked for GFM
marked.setOptions({
  breaks: true,
  gfm: true
})

// Render markdown to sanitized HTML
function renderMarkdown(content: string): string {
  if (!content) return ''
  const html = marked.parse(content) as string
  return DOMPurify.sanitize(html)
}

// Get ID from route params (with fallback to props for compatibility)
const props = defineProps<{ id?: string }>()
const caseId = computed(() => (route.params.id as string) || props.id || '')

const goBack = () => router.push({ name: 'cases' })

const caseObj = ref<any>(null)
const associations = ref<any>({
  comments: [],
  attachments: [],
  evidence: [],
  events: [],
  tasks: [],
  history: []
})
const loading = ref(true)
const error = ref<string | null>(null)
const activeTab = ref('summary')

// Events expansion state
const expandedEvents = ref<Set<string>>(new Set())
const sortHighlightedFirst = ref(true)
const editingNoteEventId = ref<string | null>(null)
const editingNoteText = ref('')
const savingNote = ref(false)

// Comment form state
const newCommentText = ref('')
const newCommentHours = ref<number | null>(null)
const addingComment = ref(false)
const commentError = ref<string | null>(null)
const showPreview = ref(false)

async function addComment() {
  if (!newCommentText.value.trim()) {
    commentError.value = 'Comment cannot be empty'
    return
  }

  addingComment.value = true
  commentError.value = null

  try {
    await post('/api/case/comments', {
      caseId: caseId.value,
      description: newCommentText.value.trim(),
      hours: newCommentHours.value || 0
    })

    // Clear form and reload comments
    newCommentText.value = ''
    newCommentHours.value = null
    showPreview.value = false
    await loadAssociation('comments')
  } catch (err: any) {
    commentError.value = err.message || 'Failed to add comment'
  } finally {
    addingComment.value = false
  }
}

const tabs = [
  { id: 'summary', name: 'Summary', icon: Info },
  { id: 'comments', name: 'Comments', icon: MessageSquare },
  { id: 'observables', name: 'Observables', icon: Crosshair },
  { id: 'attachments', name: 'Attachments', icon: Paperclip },
  { id: 'events', name: 'Events', icon: Activity },
  { id: 'tasks', name: 'Tasks', icon: CheckSquare },
  { id: 'history', name: 'History', icon: History }
]

const fetchCaseDetail = async () => {
  loading.value = true
  try {
    const response = await fetch(`/api/case/?id=${caseId.value}`)
    if (!response.ok) throw new Error('Failed to fetch case details')
    
    caseObj.value = await response.json()
    
    // Initial load for summary or active tab
    loadAssociation('comments')
    
    loading.value = false
  } catch (err: any) {
    console.error('Fetch case detail error:', err)
    error.value = err.message || 'Failed to fetch case details'
    loading.value = false
  }
}

const loadAssociation = async (association: string) => {
  try {
    let path = association
    if (association === 'attachments' || association === 'evidence') {
      path = `artifacts/${association}`
    }

    const response = await fetch(`/api/case/${path}?id=${caseId.value}`)
    if (!response.ok) throw new Error(`Failed to fetch ${association}`)
    
    associations.value[association] = await response.json()
  } catch (err) {
    console.error(`Error loading ${association}:`, err)
  }
}

const handleTabChange = (tabId: string) => {
  activeTab.value = tabId
  if (tabId === 'comments') loadAssociation('comments')
  if (tabId === 'observables') loadAssociation('evidence')
  if (tabId === 'attachments') loadAssociation('attachments')
  if (tabId === 'events') loadAssociation('events')
  if (tabId === 'tasks') loadAssociation('tasks')
  if (tabId === 'history') loadAssociation('history')
}

onMounted(() => {
  fetchCaseDetail()
})

const getSeverityStyles = (severity: string) => {
  switch (severity?.toLowerCase()) {
    case 'high': return 'bg-red-500/10 text-red-500 border-red-500/20'
    case 'medium': return 'bg-amber-500/10 text-amber-500 border-amber-500/20'
    case 'low': return 'bg-blue-500/10 text-blue-500 border-blue-500/20'
    default: return 'bg-slate-500/10 text-slate-500 border-slate-500/20'
  }
}

const getTLPStyles = (tlp: string) => {
  switch (tlp?.toUpperCase()) {
    case 'RED': return 'bg-red-600 text-white'
    case 'AMBER': return 'bg-amber-500 text-black'
    case 'GREEN': return 'bg-green-600 text-white'
    case 'WHITE': return 'bg-white text-black border border-border'
    default: return 'bg-slate-500 text-white'
  }
}

// Refresh attachments
const refreshAttachments = () => {
  loadAssociation('attachments')
}

// Refresh evidence
const refreshEvidence = () => {
  loadAssociation('evidence')
}

// Switch to observables tab and pre-fill (from attachment panel)
const addHashAsObservable = (hash: string, hashType: string) => {
  // TODO: Pre-fill observable form with hash value
  activeTab.value = 'observables'
  loadAssociation('evidence')
}

// History helper functions
const getHistoryDotColor = (operation: string) => {
  switch (operation?.toLowerCase()) {
    case 'create': return 'bg-green-500 text-white'
    case 'update': return 'bg-blue-500 text-white'
    case 'delete': return 'bg-red-500 text-white'
    default: return 'bg-muted-foreground text-background'
  }
}

const getHistoryIcon = (kind: string) => {
  switch (kind?.toLowerCase()) {
    case 'case': return Briefcase
    case 'comment': return MessageSquare
    case 'artifact': return Paperclip
    case 'relatedevent': return Activity
    default: return History
  }
}

const getOperationStyles = (operation: string) => {
  switch (operation?.toLowerCase()) {
    case 'create': return 'bg-green-500/10 text-green-500 border border-green-500/20'
    case 'update': return 'bg-blue-500/10 text-blue-500 border border-blue-500/20'
    case 'delete': return 'bg-red-500/10 text-red-500 border border-red-500/20'
    default: return 'bg-muted text-muted-foreground border border-border'
  }
}

const getKindLabel = (kind: string) => {
  switch (kind?.toLowerCase()) {
    case 'case': return 'Case'
    case 'comment': return 'Comment'
    case 'artifact': return 'Artifact'
    case 'relatedevent': return 'Related Event'
    default: return kind || 'Unknown'
  }
}

// Events helper functions
const toggleEventExpanded = (eventId: string) => {
  if (expandedEvents.value.has(eventId)) {
    expandedEvents.value.delete(eventId)
  } else {
    expandedEvents.value.add(eventId)
  }
  // Force reactivity update
  expandedEvents.value = new Set(expandedEvents.value)
}

const getEventField = (event: any, fieldPath: string): string | null => {
  if (!event?.fields) return null

  // Try direct field access
  if (event.fields[fieldPath] !== undefined) {
    return String(event.fields[fieldPath])
  }

  // Try nested access (e.g., 'source.ip' -> fields['source.ip'] or fields.source?.ip)
  const parts = fieldPath.split('.')
  let value = event.fields
  for (const part of parts) {
    if (value && typeof value === 'object' && part in value) {
      value = value[part]
    } else {
      return null
    }
  }

  return value !== undefined && value !== null ? String(value) : null
}

const getEventSeverityStyles = (severity: string | null) => {
  if (!severity) return 'bg-muted text-muted-foreground'

  switch (severity.toString().toLowerCase()) {
    case 'critical':
    case '1':
      return 'bg-red-500/10 text-red-500 border border-red-500/20'
    case 'high':
    case '2':
      return 'bg-orange-500/10 text-orange-500 border border-orange-500/20'
    case 'medium':
    case '3':
      return 'bg-amber-500/10 text-amber-500 border border-amber-500/20'
    case 'low':
    case '4':
      return 'bg-blue-500/10 text-blue-500 border border-blue-500/20'
    default:
      return 'bg-muted text-muted-foreground border border-border'
  }
}

const formatFieldValue = (value: any): string => {
  if (value === null || value === undefined) return '-'
  if (typeof value === 'object') {
    return JSON.stringify(value)
  }
  return String(value)
}

const removeRelatedEvent = async (eventId: string) => {
  if (!confirm('Remove this event from the case?')) return

  try {
    const response = await fetch(`/api/case/events/${eventId}`, {
      method: 'DELETE'
    })

    if (!response.ok) {
      throw new Error('Failed to remove event')
    }

    // Refresh events list
    await loadAssociation('events')

    // Also refresh history to show the removal
    await loadAssociation('history')
  } catch (err: any) {
    console.error('Error removing event:', err)
    alert('Failed to remove event: ' + (err.message || 'Unknown error'))
  }
}

// Highlighted events count
const highlightedEventsCount = computed(() => {
  return associations.value.events.filter((e: any) => e.isHighlighted).length
})

// Sorted events based on highlighted first toggle
const sortedEvents = computed(() => {
  const events = [...associations.value.events]
  if (sortHighlightedFirst.value) {
    events.sort((a: any, b: any) => {
      if (a.isHighlighted && !b.isHighlighted) return -1
      if (!a.isHighlighted && b.isHighlighted) return 1
      return 0
    })
  }
  return events
})

// Start editing a note
const startEditingNote = (event: any) => {
  editingNoteEventId.value = event.id
  editingNoteText.value = event.note || ''
}

// Cancel editing
const cancelEditingNote = () => {
  editingNoteEventId.value = null
  editingNoteText.value = ''
}

// Save note
const saveNote = async (eventId: string) => {
  savingNote.value = true
  try {
    const response = await fetch('/api/case/events', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        id: eventId,
        note: editingNoteText.value
      })
    })

    if (!response.ok) {
      throw new Error('Failed to save note')
    }

    // Update local state
    const eventIndex = associations.value.events.findIndex((e: any) => e.id === eventId)
    if (eventIndex >= 0) {
      associations.value.events[eventIndex].note = editingNoteText.value
    }

    editingNoteEventId.value = null
    editingNoteText.value = ''
  } catch (err: any) {
    console.error('Error saving note:', err)
    alert('Failed to save note: ' + (err.message || 'Unknown error'))
  } finally {
    savingNote.value = false
  }
}

// Toggle highlight status
const toggleHighlight = async (event: any) => {
  try {
    const response = await fetch('/api/case/events', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        id: event.id,
        isHighlighted: !event.isHighlighted
      })
    })

    if (!response.ok) {
      throw new Error('Failed to update highlight status')
    }

    // Update local state
    const eventIndex = associations.value.events.findIndex((e: any) => e.id === event.id)
    if (eventIndex >= 0) {
      associations.value.events[eventIndex].isHighlighted = !event.isHighlighted
    }
  } catch (err: any) {
    console.error('Error toggling highlight:', err)
    alert('Failed to update highlight status: ' + (err.message || 'Unknown error'))
  }
}

// AI Analysis function
const analyzeWithAI = async () => {
  // Ensure we have the latest data
  if (associations.value.events.length === 0) {
    await loadAssociation('events')
  }
  if (associations.value.evidence.length === 0) {
    await loadAssociation('evidence')
  }
  if (associations.value.attachments.length === 0) {
    await loadAssociation('attachments')
  }

  // Build the prompt with case context
  let prompt = `Please analyze this security case and provide your assessment:\n\n`

  // Case details
  prompt += `## Case Information\n`
  prompt += `- **Title:** ${caseObj.value?.title || 'Unknown'}\n`
  prompt += `- **Severity:** ${caseObj.value?.severity || 'Unknown'}\n`
  prompt += `- **Status:** ${caseObj.value?.status || 'Unknown'}\n`
  prompt += `- **TLP:** ${caseObj.value?.tlp || 'Unknown'}\n`
  if (caseObj.value?.description) {
    prompt += `- **Description:** ${caseObj.value.description}\n`
  }
  prompt += `\n`

  // Attachments (files)
  if (associations.value.attachments.length > 0) {
    prompt += `## Attachments (${associations.value.attachments.length} files)\n`
    for (const attachment of associations.value.attachments.slice(0, 10)) {
      prompt += `- ${attachment.name || attachment.value || 'Unknown file'}`
      if (attachment.mimeType) prompt += ` (${attachment.mimeType})`
      if (attachment.md5) prompt += ` [MD5: ${attachment.md5}]`
      if (attachment.sha256) prompt += ` [SHA256: ${attachment.sha256}]`
      prompt += `\n`
    }
    if (associations.value.attachments.length > 10) {
      prompt += `- ... and ${associations.value.attachments.length - 10} more files\n`
    }
    prompt += `\n`
  }

  // Observables (evidence/IOCs)
  if (associations.value.evidence.length > 0) {
    prompt += `## Observables (${associations.value.evidence.length} items)\n`
    for (const observable of associations.value.evidence.slice(0, 20)) {
      prompt += `- **${observable.artifactType || 'Unknown type'}:** ${observable.value || 'N/A'}`
      if (observable.description) {
        prompt += ` (${observable.description})`
      }
      prompt += `\n`
    }
    if (associations.value.evidence.length > 20) {
      prompt += `- ... and ${associations.value.evidence.length - 20} more items\n`
    }
    prompt += `\n`
  }

  // Related Events
  if (associations.value.events.length > 0) {
    prompt += `## Related Events (${associations.value.events.length} events)\n`
    for (const event of associations.value.events.slice(0, 10)) {
      const ruleName = getEventField(event, 'rule.name') || getEventField(event, 'event.module') || 'Event'
      const sourceIp = getEventField(event, 'source.ip') || getEventField(event, 'client.ip') || 'N/A'
      const destIp = getEventField(event, 'destination.ip') || getEventField(event, 'server.ip') || 'N/A'
      const timestamp = getEventField(event, '@timestamp') || getEventField(event, 'soc_timestamp') || 'N/A'
      const severity = getEventField(event, 'event.severity_label') || getEventField(event, 'event.severity') || ''

      prompt += `- **${ruleName}**`
      if (severity) prompt += ` [${severity}]`
      prompt += `: ${sourceIp} → ${destIp}`
      if (timestamp !== 'N/A') prompt += ` at ${timestamp}`
      prompt += `\n`

      // Add key fields from the event
      const keyFields = ['rule.category', 'event.dataset', 'network.protocol', 'destination.port', 'user.name', 'process.name']
      const fieldValues: string[] = []
      for (const field of keyFields) {
        const value = getEventField(event, field)
        if (value) {
          fieldValues.push(`${field.split('.').pop()}: ${value}`)
        }
      }
      if (fieldValues.length > 0) {
        prompt += `  - ${fieldValues.join(', ')}\n`
      }
    }
    if (associations.value.events.length > 10) {
      prompt += `- ... and ${associations.value.events.length - 10} more events\n`
    }
    prompt += `\n`
  }

  prompt += `## Questions\n`
  prompt += `1. What is your assessment of this case based on the evidence and events?\n`
  prompt += `2. Are there any indicators of compromise (IOCs) that stand out?\n`
  prompt += `3. What additional investigation steps would you recommend?\n`
  prompt += `4. What is the likely threat type or attack pattern?\n`

  // Open chat with the prompt
  openNewChatWithPrompt(prompt)
}
</script>

<template>
  <div class="space-y-6 animate-in slide-in-from-right duration-500">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div class="flex items-center gap-4">
        <button
          @click="goBack"
          class="p-2 hover:bg-muted rounded-full transition-colors text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft class="h-5 w-5" />
        </button>
        <div v-if="caseObj">
          <div class="flex items-center gap-2 mb-1">
            <span class="text-xs font-mono text-muted-foreground">{{ caseObj.id }}</span>
            <span :class="cn('px-1.5 py-0.5 rounded text-[10px] font-bold uppercase', getSeverityStyles(caseObj.severity))">
              {{ caseObj.severity }}
            </span>
          </div>
          <h2 class="text-2xl font-bold tracking-tight">{{ caseObj.title }}</h2>
        </div>
        <div v-else-if="loading" class="space-y-2">
          <div class="h-4 w-24 bg-muted animate-pulse rounded"></div>
          <div class="h-8 w-64 bg-muted animate-pulse rounded"></div>
        </div>
      </div>
      <div v-if="caseObj" class="flex items-center gap-3">
        <div :class="cn('px-3 py-1 rounded text-xs font-bold', getTLPStyles(caseObj.tlp))">
          TLP:{{ caseObj.tlp }}
        </div>
        <button
          @click="analyzeWithAI"
          class="inline-flex items-center gap-2 px-4 py-2 bg-violet-600 text-white rounded-md hover:bg-violet-700 transition-colors text-sm font-medium"
        >
          <Sparkles class="h-4 w-4" />
          Analyze with AI
        </button>
        <button class="px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 transition-colors text-sm font-medium">
          Update Case
        </button>
      </div>
    </div>

    <div v-if="error" class="p-4 rounded-lg bg-red-500/10 border border-red-500/20 text-red-500 flex items-center gap-3">
      <AlertTriangle class="h-5 w-5" />
      {{ error }}
    </div>

    <div v-else-if="caseObj" class="grid grid-cols-1 lg:grid-cols-4 gap-8">
      <!-- Sidebar Navigation -->
      <div class="lg:col-span-1 space-y-1">
        <button
          v-for="tab in tabs"
          :key="tab.id"
          @click="handleTabChange(tab.id)"
          :class="cn(
            'w-full flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm font-medium transition-all group',
            activeTab === tab.id
              ? 'bg-primary text-primary-foreground shadow-sm'
              : 'text-muted-foreground hover:bg-muted hover:text-foreground'
          )"
        >
          <component :is="tab.icon" class="h-4 w-4" />
          {{ tab.name }}
          <!-- Show highlighted event count on Events tab -->
          <span
            v-if="tab.id === 'events' && highlightedEventsCount > 0"
            :class="cn(
              'ml-auto px-1.5 py-0.5 rounded-full text-[10px] font-semibold flex items-center gap-0.5',
              activeTab === 'events'
                ? 'bg-amber-500/30 text-amber-200'
                : 'bg-amber-500/20 text-amber-500'
            )"
          >
            <Star class="h-2.5 w-2.5 fill-current" />
            {{ highlightedEventsCount }}
          </span>
          <ChevronRight v-if="activeTab === tab.id" class="h-4 w-4 ml-auto" />
        </button>

        <div class="mt-8 p-4 rounded-xl border border-border bg-card/50 space-y-4">
          <h4 class="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Quick Details</h4>
          <div class="space-y-3">
            <div class="flex items-center justify-between text-xs">
              <span class="text-muted-foreground flex items-center gap-1.5"><User class="h-3 w-3" /> Owner</span>
              <span class="font-medium truncate ml-2">{{ getUserName(caseObj.userId) || 'System' }}</span>
            </div>
            <div class="flex items-center justify-between text-xs">
              <span class="text-muted-foreground flex items-center gap-1.5"><Briefcase class="h-3 w-3" /> Assignee</span>
              <span class="font-medium truncate ml-2 text-primary">{{ getUserName(caseObj.assigneeId) || 'Unassigned' }}</span>
            </div>
            <div class="flex items-center justify-between text-xs">
              <span class="text-muted-foreground flex items-center gap-1.5"><Clock class="h-3 w-3" /> Created</span>
              <span class="font-medium ml-2">{{ formatDateOnly(caseObj.createTime) }}</span>
            </div>
          </div>
          <div class="pt-2">
            <div class="flex flex-wrap gap-1.5">
              <span v-for="tag in caseObj.tags" :key="tag" class="px-2 py-0.5 rounded-full bg-muted text-[10px] font-medium text-muted-foreground border border-border">
                #{{ tag }}
              </span>
            </div>
          </div>
        </div>
      </div>

      <!-- Content Area -->
      <div class="lg:col-span-3">
        <div class="bg-card border border-border rounded-xl shadow-sm overflow-hidden min-h-[600px] flex flex-col">
          
          <!-- Summary Tab -->
          <div v-if="activeTab === 'summary'" class="p-6 space-y-8 animate-in fade-in duration-300">
            <div>
              <h3 class="text-lg font-semibold mb-3 flex items-center gap-2">
                <FileText class="h-5 w-5 text-primary" />
                Description
              </h3>
              <div class="prose prose-sm prose-invert max-w-none bg-muted/30 p-4 rounded-lg border border-border/50 text-muted-foreground whitespace-pre-wrap">
                {{ caseObj.description }}
              </div>
            </div>

            <div class="grid grid-cols-2 gap-8">
              <div class="space-y-4">
                <h3 class="text-sm font-semibold uppercase tracking-wider text-muted-foreground">General Info</h3>
                <div class="space-y-3">
                  <div class="flex flex-col gap-1">
                    <span class="text-xs text-muted-foreground">Status</span>
                    <span class="text-sm font-medium uppercase text-green-500">{{ caseObj.status }}</span>
                  </div>
                  <div class="flex flex-col gap-1">
                    <span class="text-xs text-muted-foreground">Severity</span>
                    <span class="text-sm font-medium uppercase">{{ caseObj.severity }}</span>
                  </div>
                </div>
              </div>
              <div class="space-y-4">
                <h3 class="text-sm font-semibold uppercase tracking-wider text-muted-foreground">Classification</h3>
                <div class="space-y-3">
                  <div class="flex flex-col gap-1">
                    <span class="text-xs text-muted-foreground">TLP Level</span>
                    <span class="text-sm font-medium">{{ caseObj.tlp }}</span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <!-- Comments Tab -->
          <div v-else-if="activeTab === 'comments'" class="flex flex-col h-full animate-in fade-in duration-300">
            <!-- Comments List -->
            <div class="flex-1 p-6 space-y-6 overflow-y-auto max-h-[500px]">
              <div v-if="associations.comments.length === 0" class="text-center py-8 text-muted-foreground">
                <MessageSquare class="h-12 w-12 mx-auto mb-3 opacity-50" />
                <p>No comments yet. Be the first to add one!</p>
              </div>
              <div v-for="comment in associations.comments" :key="comment.id" class="flex gap-4">
                <div class="h-8 w-8 rounded-full bg-primary/20 flex items-center justify-center font-bold text-xs text-primary shrink-0">
                  {{ getUserName(comment.userId)?.charAt(0)?.toUpperCase() || '?' }}
                </div>
                <div class="space-y-1 flex-1">
                  <div class="flex items-center justify-between">
                    <span class="text-sm font-semibold">{{ getUserName(comment.userId) || 'Unknown' }}</span>
                    <span class="text-xs text-muted-foreground">{{ formatDate(comment.createTime) }}</span>
                  </div>
                  <div
                    class="prose prose-sm prose-invert max-w-none bg-muted/30 p-3 rounded-lg border border-border/50 text-sm [&>*:first-child]:mt-0 [&>*:last-child]:mb-0"
                    v-html="renderMarkdown(comment.description)"
                  ></div>
                  <div v-if="comment.hours" class="flex items-center gap-1 text-[10px] text-muted-foreground pt-1">
                    <Clock class="h-3 w-3" />
                    Hours spent: {{ comment.hours }}
                  </div>
                </div>
              </div>
            </div>

            <!-- Add Comment Form -->
            <div class="p-6 border-t border-border bg-muted/30 mt-auto">
              <div class="space-y-4">
                <!-- Error Message -->
                <div v-if="commentError" class="p-3 rounded-lg bg-destructive/10 border border-destructive/20 text-destructive text-sm">
                  {{ commentError }}
                </div>

                <!-- Preview Toggle -->
                <div class="flex items-center gap-2 border-b border-border pb-2">
                  <button
                    @click="showPreview = false"
                    :class="cn(
                      'flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors',
                      !showPreview ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:text-foreground'
                    )"
                  >
                    <Edit3 class="h-3.5 w-3.5" />
                    Write
                  </button>
                  <button
                    @click="showPreview = true"
                    :class="cn(
                      'flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors',
                      showPreview ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:text-foreground'
                    )"
                  >
                    <Eye class="h-3.5 w-3.5" />
                    Preview
                  </button>
                </div>

                <!-- Write Mode -->
                <textarea
                  v-if="!showPreview"
                  v-model="newCommentText"
                  placeholder="Add a comment... (Markdown supported: **bold**, *italic*, `code`, lists, etc.)"
                  class="w-full bg-background border border-border rounded-lg p-3 text-sm min-h-[120px] focus:outline-none focus:ring-2 focus:ring-primary/50 font-mono"
                  :disabled="addingComment"
                ></textarea>

                <!-- Preview Mode -->
                <div
                  v-else
                  class="w-full bg-background border border-border rounded-lg p-3 min-h-[120px] prose prose-sm prose-invert max-w-none [&>*:first-child]:mt-0 [&>*:last-child]:mb-0"
                >
                  <div v-if="newCommentText.trim()" v-html="renderMarkdown(newCommentText)"></div>
                  <p v-else class="text-muted-foreground italic">Nothing to preview</p>
                </div>

                <div class="flex items-center justify-between">
                  <div class="flex items-center gap-2">
                    <input
                      v-model.number="newCommentHours"
                      type="number"
                      step="0.5"
                      min="0"
                      class="w-20 bg-background border border-border rounded px-2 py-1.5 text-xs focus:outline-none focus:ring-2 focus:ring-primary/50"
                      placeholder="Hours"
                      :disabled="addingComment"
                    />
                    <span class="text-xs text-muted-foreground">hours spent (optional)</span>
                  </div>
                  <button
                    @click="addComment"
                    :disabled="addingComment || !newCommentText.trim()"
                    class="inline-flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    <Loader2 v-if="addingComment" class="h-4 w-4 animate-spin" />
                    <Send v-else class="h-4 w-4" />
                    {{ addingComment ? 'Adding...' : 'Add Comment' }}
                  </button>
                </div>
              </div>
            </div>
          </div>

          <!-- Observables Tab -->
          <div v-else-if="activeTab === 'observables'" class="flex flex-col h-full animate-in fade-in duration-300">
            <div class="flex-1 p-6 overflow-y-auto">
              <EvidencePanel
                :case-id="caseId"
                :evidence="associations.evidence"
                @refresh="refreshEvidence"
              />
            </div>
          </div>

          <!-- Attachments Tab -->
          <div v-else-if="activeTab === 'attachments'" class="flex flex-col h-full animate-in fade-in duration-300">
            <div class="flex-1 p-6 overflow-y-auto">
              <AttachmentsPanel
                :case-id="caseId"
                :attachments="associations.attachments"
                @refresh="refreshAttachments"
                @add-evidence="addHashAsObservable"
              />
            </div>
          </div>

          <!-- Events Tab -->
          <div v-else-if="activeTab === 'events'" class="flex flex-col h-full animate-in fade-in duration-300">
            <div class="flex-1 p-6 overflow-y-auto max-h-[600px]">
              <div v-if="associations.events.length === 0" class="text-center py-8 text-muted-foreground">
                <Activity class="h-12 w-12 mx-auto mb-3 opacity-50" />
                <p>No related events attached to this case.</p>
                <p class="text-xs mt-2">Events can be attached from the Hunt or Alerts pages.</p>
              </div>

              <!-- Events List -->
              <div v-else class="space-y-3">
                <div class="flex items-center justify-between mb-4">
                  <div class="flex items-center gap-3">
                    <h3 class="text-sm font-semibold text-muted-foreground">
                      {{ associations.events.length }} Related Event{{ associations.events.length !== 1 ? 's' : '' }}
                    </h3>
                    <span v-if="highlightedEventsCount > 0" class="text-xs text-amber-500 font-medium flex items-center gap-1">
                      <Star class="h-3.5 w-3.5 fill-amber-500" />
                      {{ highlightedEventsCount }} highlighted
                    </span>
                  </div>
                  <button
                    v-if="highlightedEventsCount > 0"
                    @click="sortHighlightedFirst = !sortHighlightedFirst"
                    :class="cn(
                      'text-xs font-medium flex items-center gap-1.5 px-2 py-1 rounded transition-colors',
                      sortHighlightedFirst
                        ? 'bg-amber-500/10 text-amber-500'
                        : 'text-muted-foreground hover:text-foreground hover:bg-muted'
                    )"
                  >
                    <ArrowUpDown class="h-3.5 w-3.5" />
                    {{ sortHighlightedFirst ? 'Highlighted First' : 'Default Order' }}
                  </button>
                </div>

                <div
                  v-for="(event, index) in sortedEvents"
                  :key="event.id || index"
                  :class="cn(
                    'rounded-lg overflow-hidden transition-colors',
                    event.isHighlighted
                      ? 'bg-amber-500/10 border-2 border-amber-500/30 hover:border-amber-500/50'
                      : 'bg-muted/30 border border-border/50 hover:border-border'
                  )"
                >
                  <!-- Event Header -->
                  <div
                    class="flex items-center justify-between p-4 cursor-pointer"
                    @click="toggleEventExpanded(event.id)"
                  >
                    <div class="flex items-center gap-3 flex-1 min-w-0">
                      <div :class="cn(
                        'p-2 rounded-lg',
                        event.isHighlighted ? 'bg-amber-500/20' : 'bg-primary/10'
                      )">
                        <Star v-if="event.isHighlighted" class="h-4 w-4 text-amber-500 fill-amber-500" />
                        <Activity v-else class="h-4 w-4 text-primary" />
                      </div>
                      <div class="flex-1 min-w-0">
                        <div class="flex items-center gap-2 flex-wrap">
                          <span class="font-medium text-sm truncate">
                            {{ getEventField(event, 'rule.name') || getEventField(event, 'event.module') || 'Event' }}
                          </span>
                          <span v-if="getEventField(event, 'event.severity_label') || getEventField(event, 'event.severity')"
                            :class="cn(
                              'px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase',
                              getEventSeverityStyles(getEventField(event, 'event.severity_label') || getEventField(event, 'event.severity'))
                            )"
                          >
                            {{ getEventField(event, 'event.severity_label') || getEventField(event, 'event.severity') }}
                          </span>
                          <span v-if="event.note" class="text-amber-500">
                            <StickyNote class="h-3.5 w-3.5" />
                          </span>
                        </div>
                        <div class="flex items-center gap-4 mt-1 text-xs text-muted-foreground">
                          <span v-if="getEventField(event, 'source.ip') || getEventField(event, 'client.ip')">
                            {{ getEventField(event, 'source.ip') || getEventField(event, 'client.ip') }}
                          </span>
                          <span v-if="getEventField(event, 'source.ip') || getEventField(event, 'client.ip')">→</span>
                          <span v-if="getEventField(event, 'destination.ip') || getEventField(event, 'server.ip')">
                            {{ getEventField(event, 'destination.ip') || getEventField(event, 'server.ip') }}
                          </span>
                          <span v-if="event.sourceQuestion" class="text-muted-foreground/70 truncate max-w-[200px]" :title="event.sourceQuestion">
                            from: {{ event.sourceQuestion }}
                          </span>
                        </div>
                      </div>
                    </div>
                    <div class="flex items-center gap-3">
                      <span class="text-xs text-muted-foreground whitespace-nowrap">
                        {{ formatDate(getEventField(event, '@timestamp') || getEventField(event, 'soc_timestamp') || event.createTime) }}
                      </span>
                      <ChevronRight
                        :class="cn(
                          'h-4 w-4 text-muted-foreground transition-transform',
                          expandedEvents.has(event.id) && 'rotate-90'
                        )"
                      />
                    </div>
                  </div>

                  <!-- Note Preview (when collapsed, if note exists) -->
                  <div v-if="event.note && !expandedEvents.has(event.id)" class="px-4 pb-3 -mt-2">
                    <div class="text-xs text-amber-600 bg-amber-500/5 rounded px-2 py-1 flex items-start gap-1.5 border border-amber-500/20">
                      <StickyNote class="h-3 w-3 flex-shrink-0 mt-0.5" />
                      <span class="line-clamp-1">{{ event.note }}</span>
                    </div>
                  </div>

                  <!-- Expanded Fields -->
                  <div v-if="expandedEvents.has(event.id)" class="border-t border-border/50 bg-background/50">
                    <div class="p-4 space-y-4">
                      <!-- Note Section -->
                      <div class="space-y-2">
                        <div class="flex items-center justify-between">
                          <span class="text-xs font-semibold text-muted-foreground uppercase tracking-wider flex items-center gap-1.5">
                            <StickyNote class="h-3.5 w-3.5" />
                            Analyst Note
                          </span>
                          <div class="flex items-center gap-2">
                            <button
                              v-if="editingNoteEventId !== event.id"
                              @click.stop="startEditingNote(event)"
                              class="text-xs text-primary hover:text-primary/80 font-medium"
                            >
                              {{ event.note ? 'Edit Note' : 'Add Note' }}
                            </button>
                            <template v-else>
                              <button
                                @click.stop="saveNote(event.id)"
                                :disabled="savingNote"
                                class="text-xs text-green-500 hover:text-green-600 font-medium flex items-center gap-1"
                              >
                                <Loader2 v-if="savingNote" class="h-3 w-3 animate-spin" />
                                <Save v-else class="h-3 w-3" />
                                Save
                              </button>
                              <button
                                @click.stop="cancelEditingNote"
                                class="text-xs text-muted-foreground hover:text-foreground font-medium flex items-center gap-1"
                              >
                                <X class="h-3 w-3" />
                                Cancel
                              </button>
                            </template>
                          </div>
                        </div>
                        <div v-if="editingNoteEventId === event.id" @click.stop>
                          <textarea
                            v-model="editingNoteText"
                            placeholder="Add analyst notes about this event..."
                            class="w-full text-xs bg-background border border-border rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-primary/50 resize-none min-h-[80px]"
                            rows="3"
                          ></textarea>
                        </div>
                        <div v-else-if="event.note" class="text-xs bg-amber-500/5 rounded px-3 py-2 border border-amber-500/20 text-amber-700 dark:text-amber-400 whitespace-pre-wrap">
                          {{ event.note }}
                        </div>
                        <div v-else class="text-xs text-muted-foreground italic">
                          No note added
                        </div>
                      </div>

                      <!-- Actions Row -->
                      <div class="flex items-center justify-between pt-2 border-t border-border/50">
                        <div class="flex items-center gap-2">
                          <button
                            @click.stop="toggleHighlight(event)"
                            :class="cn(
                              'text-xs font-medium flex items-center gap-1.5 px-2 py-1 rounded transition-colors',
                              event.isHighlighted
                                ? 'bg-amber-500/10 text-amber-500 hover:bg-amber-500/20'
                                : 'text-muted-foreground hover:text-amber-500 hover:bg-amber-500/10'
                            )"
                          >
                            <Star :class="cn('h-3.5 w-3.5', event.isHighlighted && 'fill-amber-500')" />
                            {{ event.isHighlighted ? 'Highlighted' : 'Highlight' }}
                          </button>
                        </div>
                        <button
                          @click.stop="removeRelatedEvent(event.id)"
                          class="text-xs text-destructive hover:text-destructive/80 font-medium"
                        >
                          Remove from Case
                        </button>
                      </div>

                      <!-- Event Fields -->
                      <div class="space-y-2">
                        <span class="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Event Fields</span>
                        <div class="grid grid-cols-2 gap-2 text-xs">
                          <div
                            v-for="(value, key) in event.fields"
                            :key="key"
                            class="flex flex-col gap-0.5 p-2 rounded bg-muted/50"
                          >
                            <span class="text-muted-foreground font-mono">{{ key }}</span>
                            <span class="font-medium break-all">{{ formatFieldValue(value) }}</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <!-- History Tab -->
          <div v-else-if="activeTab === 'history'" class="flex flex-col h-full animate-in fade-in duration-300">
            <div class="flex-1 p-6 overflow-y-auto max-h-[600px]">
              <div v-if="associations.history.length === 0" class="text-center py-8 text-muted-foreground">
                <History class="h-12 w-12 mx-auto mb-3 opacity-50" />
                <p>No history available for this case.</p>
              </div>

              <!-- Timeline -->
              <div v-else class="relative">
                <!-- Timeline line -->
                <div class="absolute left-4 top-0 bottom-0 w-px bg-border"></div>

                <!-- History items -->
                <div class="space-y-6">
                  <div
                    v-for="(item, index) in associations.history"
                    :key="item.id || index"
                    class="relative pl-10"
                  >
                    <!-- Timeline dot -->
                    <div
                      :class="cn(
                        'absolute left-2 w-5 h-5 rounded-full border-2 border-background flex items-center justify-center',
                        getHistoryDotColor(item.operation)
                      )"
                    >
                      <component :is="getHistoryIcon(item.kind)" class="h-2.5 w-2.5" />
                    </div>

                    <!-- Content card -->
                    <div class="bg-muted/30 border border-border/50 rounded-lg p-4 hover:bg-muted/50 transition-colors">
                      <div class="flex items-start justify-between gap-4">
                        <div class="flex-1 min-w-0">
                          <div class="flex items-center gap-2 flex-wrap">
                            <span class="font-medium text-sm">{{ getUserName(item.userId) || 'System' }}</span>
                            <span :class="cn(
                              'px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase',
                              getOperationStyles(item.operation)
                            )">
                              {{ item.operation }}
                            </span>
                            <span class="text-xs text-muted-foreground">
                              {{ getKindLabel(item.kind) }}
                            </span>
                          </div>

                          <!-- Details based on kind -->
                          <div class="mt-2 text-sm text-muted-foreground">
                            <template v-if="item.kind === 'case'">
                              <p v-if="item.operation === 'create'">Created this case</p>
                              <p v-else-if="item.title">Updated case: "{{ item.title }}"</p>
                              <p v-else>Updated case details</p>
                            </template>
                            <template v-else-if="item.kind === 'comment'">
                              <p class="line-clamp-2">{{ item.description || 'Added a comment' }}</p>
                            </template>
                            <template v-else-if="item.kind === 'artifact'">
                              <p>{{ item.artifactType || 'Artifact' }}: {{ item.value || item.description || 'Updated artifact' }}</p>
                            </template>
                            <template v-else-if="item.kind === 'relatedEvent'">
                              <p>Related event {{ item.operation === 'create' ? 'added' : 'updated' }}</p>
                            </template>
                            <template v-else>
                              <p>{{ item.description || `${item.operation} ${item.kind}` }}</p>
                            </template>
                          </div>
                        </div>

                        <div class="text-xs text-muted-foreground whitespace-nowrap">
                          {{ formatDate(item.createTime || item.updateTime) }}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <!-- Coming Soon (for tasks tab) -->
          <div v-else-if="activeTab === 'tasks'" class="flex-1 flex flex-col items-center justify-center p-12 text-center space-y-4 animate-in zoom-in duration-300">
            <div class="p-4 rounded-full bg-muted">
              <CheckSquare class="h-10 w-10 text-muted-foreground" />
            </div>
            <div>
              <h3 class="text-lg font-semibold">Tasks View</h3>
              <p class="text-sm text-muted-foreground max-w-xs mx-auto">
                Task management is coming soon to the modern interface.
              </p>
            </div>
            <button class="text-xs font-medium text-primary hover:underline" @click="activeTab = 'summary'">
              Go back to Summary
            </button>
          </div>

        </div>
      </div>
    </div>

    <!-- Loading State -->
    <div v-else-if="loading" class="flex items-center justify-center h-[600px]">
      <div class="flex flex-col items-center gap-4">
        <div class="h-10 w-10 border-4 border-primary/30 border-t-primary rounded-full animate-spin"></div>
        <p class="text-sm text-muted-foreground font-medium">Loading case details...</p>
      </div>
    </div>
  </div>
</template>
