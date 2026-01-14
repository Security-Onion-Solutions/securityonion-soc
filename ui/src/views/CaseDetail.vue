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
  Crosshair
} from 'lucide-vue-next'
import { marked } from 'marked'
import DOMPurify from 'dompurify'
import { cn } from '../lib/utils'
import { useUsers } from '../composables/useUsers'
import { useFormatters } from '../composables/useFormatters'
import { useApi } from '../composables/useApi'
import AttachmentsPanel from '../components/cases/AttachmentsPanel.vue'
import EvidencePanel from '../components/cases/EvidencePanel.vue'

const route = useRoute()
const router = useRouter()

const { getUserName } = useUsers()
const { formatDate, formatDateOnly } = useFormatters()
const { post } = useApi()

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
const artifactSubTab = ref<'attachments' | 'evidence'>('attachments')

// Evidence form state for pre-populating from attachment hashes
const pendingEvidence = ref<{ value: string; description: string } | null>(null)

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
  { id: 'artifacts', name: 'Artifacts', icon: Paperclip },
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
  if (tabId === 'artifacts') {
    loadAssociation('attachments')
    loadAssociation('evidence')
  }
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

// Add hash as evidence (from attachment panel)
const addHashAsEvidence = (hash: string, hashType: string) => {
  pendingEvidence.value = {
    value: hash,
    description: `${hashType.toUpperCase()} hash from attachment`
  }
  artifactSubTab.value = 'evidence'
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

          <!-- Artifacts Tab -->
          <div v-else-if="activeTab === 'artifacts'" class="flex flex-col h-full animate-in fade-in duration-300">
            <!-- Sub-tabs for Attachments and Evidence -->
            <div class="flex items-center gap-1 p-4 border-b border-border bg-muted/30">
              <button
                @click="artifactSubTab = 'attachments'"
                :class="cn(
                  'flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-colors',
                  artifactSubTab === 'attachments'
                    ? 'bg-primary text-primary-foreground'
                    : 'text-muted-foreground hover:bg-muted hover:text-foreground'
                )"
              >
                <File class="h-4 w-4" />
                Attachments
                <span v-if="associations.attachments.length" class="ml-1 px-1.5 py-0.5 rounded-full bg-primary-foreground/20 text-[10px]">
                  {{ associations.attachments.length }}
                </span>
              </button>
              <button
                @click="artifactSubTab = 'evidence'"
                :class="cn(
                  'flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-colors',
                  artifactSubTab === 'evidence'
                    ? 'bg-primary text-primary-foreground'
                    : 'text-muted-foreground hover:bg-muted hover:text-foreground'
                )"
              >
                <Crosshair class="h-4 w-4" />
                Evidence
                <span v-if="associations.evidence.length" class="ml-1 px-1.5 py-0.5 rounded-full bg-primary-foreground/20 text-[10px]">
                  {{ associations.evidence.length }}
                </span>
              </button>
            </div>

            <!-- Attachments Panel -->
            <div v-if="artifactSubTab === 'attachments'" class="flex-1 p-6 overflow-y-auto">
              <AttachmentsPanel
                :case-id="caseId"
                :attachments="associations.attachments"
                @refresh="refreshAttachments"
                @add-evidence="addHashAsEvidence"
              />
            </div>

            <!-- Evidence Panel -->
            <div v-if="artifactSubTab === 'evidence'" class="flex-1 p-6 overflow-y-auto">
              <EvidencePanel
                :case-id="caseId"
                :evidence="associations.evidence"
                @refresh="refreshEvidence"
              />
            </div>
          </div>

          <!-- Coming Soon (for other tabs) -->
          <div v-else class="flex-1 flex flex-col items-center justify-center p-12 text-center space-y-4 animate-in zoom-in duration-300">
            <div class="p-4 rounded-full bg-muted">
              <Activity v-if="activeTab === 'events'" class="h-10 w-10 text-muted-foreground" />
              <CheckSquare v-else-if="activeTab === 'tasks'" class="h-10 w-10 text-muted-foreground" />
              <History v-else-if="activeTab === 'history'" class="h-10 w-10 text-muted-foreground" />
            </div>
            <div>
              <h3 class="text-lg font-semibold capitalize">{{ activeTab }} View</h3>
              <p class="text-sm text-muted-foreground max-w-xs mx-auto">
                Detailed management for {{ activeTab }} is coming soon to the modern interface.
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
