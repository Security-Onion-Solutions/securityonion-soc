<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import {
  Plus,
  RefreshCw,
  ChevronRight,
  ChevronDown,
  Download,
  Copy,
  Trash2,
  Crosshair,
  Zap,
  Clock,
  Check,
  X,
  Edit3,
  Loader2,
  File,
  AlertCircle,
  AlertTriangle,
  CheckCircle,
  Info,
  HelpCircle,
  ChevronUp
} from 'lucide-vue-next'
import { cn } from '../../lib/utils'
import { useArtifacts, type Artifact, type AnalyzeJob, type AnalyzerResult } from '../../composables/useArtifacts'
import { useFormatters } from '../../composables/useFormatters'
import { useUsers } from '../../composables/useUsers'

const props = defineProps<{
  caseId: string
  evidence: Artifact[]
}>()

const emit = defineEmits<{
  (e: 'refresh'): void
}>()

const router = useRouter()

const {
  detectArtifactType,
  createArtifact,
  createFileArtifact,
  updateArtifact,
  deleteArtifact,
  getDownloadUrl,
  analyzeArtifact,
  getAnalyzeJobs,
  buildHuntQuery,
  copyToClipboard,
  formatFileSize,
  getAnalyzerDecoration,
  loading
} = useArtifacts()

const { formatDate } = useFormatters()
const { getUserName } = useUsers()

// Artifact type options
const artifactTypes = ['ip', 'domain', 'fqdn', 'url', 'filename', 'uri_path', 'hash', 'file']

// TLP options
const tlpOptions = ['RED', 'AMBER', 'GREEN', 'WHITE']

// UI State
const showAddForm = ref(false)
const expandedIds = ref<Set<string>>(new Set())
const editingField = ref<{ id: string; field: string } | null>(null)
const editValue = ref<any>(null)
const deleteConfirmId = ref<string | null>(null)
const analyzingIds = ref<Set<string>>(new Set())
const analyzeJobs = ref<Record<string, AnalyzeJob[]>>({})
const expandedJobs = ref<Set<string>>(new Set())
const expandedResults = ref<Set<string>>(new Set())

// Form state
const formData = ref({
  artifactType: 'ip',
  value: '',
  description: '',
  tlp: 'AMBER',
  tags: [] as string[],
  ioc: false,
  bulk: false,
})
const selectedFile = ref<File | null>(null)
const submitting = ref(false)
const formError = ref<string | null>(null)

// Auto-detect artifact type from value
watch(() => formData.value.value, (newValue) => {
  if (newValue && formData.value.artifactType !== 'file') {
    const detected = detectArtifactType(newValue.split('\n')[0])
    if (detected) {
      formData.value.artifactType = detected
    }
  }
})

// Toggle row expansion
function toggleExpand(id: string) {
  if (expandedIds.value.has(id)) {
    expandedIds.value.delete(id)
  } else {
    expandedIds.value.add(id)
    // Load analyze jobs when expanding
    loadAnalyzeJobs(id)
  }
  expandedIds.value = new Set(expandedIds.value)
}

// Toggle job expansion
function toggleJob(jobId: string) {
  if (expandedJobs.value.has(jobId)) {
    expandedJobs.value.delete(jobId)
  } else {
    expandedJobs.value.add(jobId)
  }
  expandedJobs.value = new Set(expandedJobs.value)
}

// Toggle result expansion
function toggleResult(resultId: string) {
  if (expandedResults.value.has(resultId)) {
    expandedResults.value.delete(resultId)
  } else {
    expandedResults.value.add(resultId)
  }
  expandedResults.value = new Set(expandedResults.value)
}

// Load analyze jobs for an artifact
async function loadAnalyzeJobs(artifactId: string) {
  if (!analyzeJobs.value[artifactId]) {
    const jobs = await getAnalyzeJobs(artifactId)
    analyzeJobs.value[artifactId] = jobs
  }
}

// File handling
function handleFileSelect(event: Event) {
  const input = event.target as HTMLInputElement
  if (input.files && input.files.length > 0) {
    selectedFile.value = input.files[0]
  }
}

// Submit new evidence
async function submitEvidence() {
  if (formData.value.artifactType === 'file') {
    if (!selectedFile.value) {
      formError.value = 'Please select a file'
      return
    }
  } else if (!formData.value.value.trim()) {
    formError.value = 'Please enter a value'
    return
  }

  submitting.value = true
  formError.value = null

  try {
    if (formData.value.artifactType === 'file') {
      await createFileArtifact(
        {
          caseId: props.caseId,
          groupType: 'evidence',
          artifactType: 'file',
          value: selectedFile.value!.name,
          description: formData.value.description,
          tlp: formData.value.tlp,
          tags: formData.value.tags,
          ioc: formData.value.ioc,
        },
        selectedFile.value!
      )
    } else if (formData.value.bulk && formData.value.value.includes('\n')) {
      // Bulk add
      const values = formData.value.value.split('\n').filter(v => v.trim())
      for (const value of values) {
        await createArtifact({
          caseId: props.caseId,
          groupType: 'evidence',
          artifactType: formData.value.artifactType,
          value: value.trim(),
          description: formData.value.description,
          tlp: formData.value.tlp,
          tags: formData.value.tags,
          ioc: formData.value.ioc,
        })
      }
    } else {
      await createArtifact({
        caseId: props.caseId,
        groupType: 'evidence',
        artifactType: formData.value.artifactType,
        value: formData.value.value.trim(),
        description: formData.value.description,
        tlp: formData.value.tlp,
        tags: formData.value.tags,
        ioc: formData.value.ioc,
      })
    }

    // Reset form
    cancelAdd()
    emit('refresh')
  } catch (e: any) {
    formError.value = e.message || 'Failed to add evidence'
  } finally {
    submitting.value = false
  }
}

// Cancel add form
function cancelAdd() {
  showAddForm.value = false
  selectedFile.value = null
  formData.value = {
    artifactType: 'ip',
    value: '',
    description: '',
    tlp: 'AMBER',
    tags: [],
    ioc: false,
    bulk: false,
  }
  formError.value = null
}

// Edit field
function startEdit(evidence: Artifact, field: string) {
  editingField.value = { id: evidence.id, field }
  editValue.value = (evidence as any)[field]
}

async function saveEdit(evidence: Artifact) {
  if (!editingField.value) return

  try {
    await updateArtifact({
      ...evidence,
      [editingField.value.field]: editValue.value,
    })
    emit('refresh')
  } catch (e) {
    console.error('Failed to update:', e)
  } finally {
    editingField.value = null
    editValue.value = null
  }
}

function cancelEdit() {
  editingField.value = null
  editValue.value = null
}

// Delete evidence
async function confirmDelete(id: string) {
  try {
    await deleteArtifact(id)
    deleteConfirmId.value = null
    emit('refresh')
  } catch (e) {
    console.error('Failed to delete:', e)
  }
}

// Hunt action
function huntForEvidence(evidence: Artifact) {
  const query = buildHuntQuery(evidence.value)
  router.push({ name: 'hunt', query: { q: query } })
}

// Analyze action
async function analyzeEvidence(evidence: Artifact) {
  analyzingIds.value.add(evidence.id)
  try {
    await analyzeArtifact(evidence)
    // Reload jobs after a brief delay
    setTimeout(async () => {
      analyzeJobs.value[evidence.id] = await getAnalyzeJobs(evidence.id)
    }, 1000)
  } catch (e) {
    console.error('Failed to analyze:', e)
  } finally {
    analyzingIds.value.delete(evidence.id)
    analyzingIds.value = new Set(analyzingIds.value)
  }
}

// Get TLP color
function getTlpColor(tlp: string | undefined): string {
  switch (tlp?.toUpperCase()) {
    case 'RED': return 'bg-red-600 text-white'
    case 'AMBER': return 'bg-amber-500 text-black'
    case 'GREEN': return 'bg-green-600 text-white'
    case 'WHITE': return 'bg-white text-black border border-border'
    default: return 'bg-slate-500 text-white'
  }
}

// Check if editing a specific field
function isEditing(id: string, field: string): boolean {
  return editingField.value?.id === id && editingField.value?.field === field
}

// Get job status icon
function getJobStatusIcon(job: AnalyzeJob) {
  if (job.status === 'pending') return Clock
  if (job.status === 'completed') {
    if (!job.results?.length) return AlertCircle
    const maxSeverity = Math.max(...job.results.map(r => getAnalyzerDecoration(r).severity))
    if (maxSeverity >= 100) return AlertCircle
    if (maxSeverity >= 80) return AlertTriangle
    if (maxSeverity >= 10) return Info
    return CheckCircle
  }
  return AlertCircle
}

// Get job status color
function getJobStatusColor(job: AnalyzeJob): string {
  if (job.status === 'pending') return 'text-blue-500'
  if (job.status === 'completed') {
    if (!job.results?.length) return 'text-muted-foreground'
    const maxSeverity = Math.max(...job.results.map(r => getAnalyzerDecoration(r).severity))
    if (maxSeverity >= 100) return 'text-red-500'
    if (maxSeverity >= 80) return 'text-amber-500'
    if (maxSeverity >= 10) return 'text-blue-500'
    return 'text-green-500'
  }
  return 'text-red-500'
}

// Get result icon
function getResultIcon(result: AnalyzerResult) {
  const deco = getAnalyzerDecoration(result)
  switch (deco.icon) {
    case 'check-circle': return CheckCircle
    case 'alert-triangle': return AlertTriangle
    case 'alert-circle': return AlertCircle
    case 'info': return Info
    default: return HelpCircle
  }
}
</script>

<template>
  <div class="space-y-4">
    <!-- Toolbar -->
    <div class="flex items-center gap-2">
      <button
        @click="showAddForm = true"
        :disabled="showAddForm"
        class="flex items-center gap-2 px-3 py-1.5 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90 transition-colors disabled:opacity-50"
      >
        <Plus class="h-4 w-4" />
        Add Evidence
      </button>
      <button
        @click="emit('refresh')"
        class="flex items-center gap-2 px-3 py-1.5 bg-muted text-muted-foreground rounded-md text-sm font-medium hover:bg-muted/80 transition-colors"
      >
        <RefreshCw class="h-4 w-4" />
        Refresh
      </button>
    </div>

    <!-- Add Form -->
    <div
      v-if="showAddForm"
      class="p-4 rounded-lg border border-border bg-muted/30 space-y-4 animate-in slide-in-from-top-2 duration-200"
    >
      <div class="flex items-center gap-2 text-sm font-semibold text-primary">
        <Plus class="h-4 w-4" />
        Add Evidence
      </div>

      <!-- Error Message -->
      <div v-if="formError" class="p-3 rounded-lg bg-destructive/10 border border-destructive/20 text-destructive text-sm">
        {{ formError }}
      </div>

      <!-- Form Fields -->
      <div class="grid gap-4">
        <!-- Artifact Type -->
        <div>
          <label class="text-xs font-medium text-muted-foreground mb-1 block">Type</label>
          <select
            v-model="formData.artifactType"
            class="w-full bg-background border border-border rounded-md p-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary/50"
          >
            <option v-for="type in artifactTypes" :key="type" :value="type">{{ type }}</option>
          </select>
        </div>

        <!-- File Input (for file type) -->
        <div v-if="formData.artifactType === 'file'">
          <label class="text-xs font-medium text-muted-foreground mb-1 block">File</label>
          <input
            type="file"
            @change="handleFileSelect"
            class="w-full bg-background border border-border rounded-md p-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary/50"
          />
        </div>

        <!-- Value Input (for non-file types) -->
        <div v-else>
          <label class="text-xs font-medium text-muted-foreground mb-1 block">Value</label>
          <textarea
            v-model="formData.value"
            :rows="formData.bulk ? 4 : 2"
            class="w-full bg-background border border-border rounded-md p-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-primary/50"
            :placeholder="formData.bulk ? 'Enter values, one per line...' : 'Enter value...'"
          ></textarea>
          <div class="mt-2 flex items-center gap-2">
            <input
              type="checkbox"
              id="bulk"
              v-model="formData.bulk"
              class="rounded border-border"
            />
            <label for="bulk" class="text-xs text-muted-foreground">
              Bulk add (one value per line)
            </label>
          </div>
        </div>

        <!-- Description -->
        <div>
          <label class="text-xs font-medium text-muted-foreground mb-1 block">Description</label>
          <textarea
            v-model="formData.description"
            rows="2"
            class="w-full bg-background border border-border rounded-md p-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary/50"
            placeholder="Describe this evidence..."
          ></textarea>
        </div>

        <div class="grid grid-cols-2 gap-4">
          <!-- TLP -->
          <div>
            <label class="text-xs font-medium text-muted-foreground mb-1 block">TLP Level</label>
            <select
              v-model="formData.tlp"
              class="w-full bg-background border border-border rounded-md p-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary/50"
            >
              <option v-for="opt in tlpOptions" :key="opt" :value="opt">{{ opt }}</option>
            </select>
          </div>

          <!-- IoC -->
          <div class="flex items-center gap-2 pt-5">
            <input
              type="checkbox"
              id="ioc"
              v-model="formData.ioc"
              class="rounded border-border"
            />
            <label for="ioc" class="text-sm">
              Indicator of Compromise (IoC)
            </label>
          </div>
        </div>
      </div>

      <!-- Form Actions -->
      <div class="flex justify-end gap-2">
        <button
          @click="cancelAdd"
          class="px-3 py-1.5 text-sm text-muted-foreground hover:text-foreground"
        >
          Cancel
        </button>
        <button
          @click="submitEvidence"
          :disabled="submitting"
          class="flex items-center gap-2 px-4 py-1.5 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90 disabled:opacity-50"
        >
          <Loader2 v-if="submitting" class="h-4 w-4 animate-spin" />
          {{ submitting ? 'Adding...' : 'Add' }}
        </button>
      </div>
    </div>

    <!-- Evidence List -->
    <div v-if="evidence.length === 0 && !showAddForm" class="text-center py-8 text-muted-foreground">
      <Crosshair class="h-12 w-12 mx-auto mb-3 opacity-50" />
      <p>No evidence yet. Click "Add Evidence" to add observables or indicators.</p>
    </div>

    <div v-else class="rounded-md border border-border bg-card overflow-hidden">
      <table class="w-full text-sm">
        <thead>
          <tr class="border-b border-border bg-muted/50">
            <th class="w-10 px-4"></th>
            <th class="h-10 px-4 text-left align-middle font-medium text-muted-foreground w-32">Actions</th>
            <th class="h-10 px-4 text-left align-middle font-medium text-muted-foreground">Created</th>
            <th class="h-10 px-4 text-left align-middle font-medium text-muted-foreground">Type</th>
            <th class="h-10 px-4 text-left align-middle font-medium text-muted-foreground">Value</th>
          </tr>
        </thead>
        <tbody>
          <template v-for="item in evidence" :key="item.id">
            <tr
              :class="cn(
                'border-b border-border transition-colors hover:bg-muted/50',
                expandedIds.has(item.id) && 'bg-muted/30'
              )"
            >
              <td class="p-4 align-middle text-center cursor-pointer" @click="toggleExpand(item.id)">
                <ChevronDown v-if="expandedIds.has(item.id)" class="h-4 w-4 text-muted-foreground" />
                <ChevronRight v-else class="h-4 w-4 text-muted-foreground" />
              </td>
              <td class="p-4 align-middle">
                <div class="flex items-center gap-1">
                  <button
                    @click="huntForEvidence(item)"
                    class="p-1.5 text-muted-foreground hover:text-primary transition-colors rounded hover:bg-muted"
                    title="Hunt for this value"
                  >
                    <Crosshair class="h-4 w-4" />
                  </button>
                  <button
                    @click="analyzeEvidence(item)"
                    :disabled="analyzingIds.has(item.id)"
                    class="p-1.5 text-muted-foreground hover:text-amber-500 transition-colors rounded hover:bg-muted disabled:opacity-50"
                    title="Analyze with threat intel"
                  >
                    <Clock v-if="analyzingIds.has(item.id)" class="h-4 w-4 animate-pulse" />
                    <Zap v-else class="h-4 w-4" />
                  </button>
                  <button
                    @click="deleteConfirmId = item.id"
                    class="p-1.5 text-muted-foreground hover:text-destructive transition-colors rounded hover:bg-muted"
                    title="Delete"
                  >
                    <Trash2 class="h-4 w-4" />
                  </button>
                </div>
              </td>
              <td class="p-4 align-middle text-muted-foreground cursor-pointer" @click="toggleExpand(item.id)">
                {{ formatDate(item.createTime) }}
              </td>
              <td class="p-4 align-middle cursor-pointer" @click="toggleExpand(item.id)">
                <span class="inline-flex items-center rounded-full border border-border px-2 py-0.5 text-xs font-medium">
                  {{ item.artifactType }}
                </span>
                <span v-if="item.ioc" class="ml-1 text-[10px] text-amber-500 font-bold">IoC</span>
              </td>
              <td class="p-4 align-middle font-mono text-sm cursor-pointer" @click="toggleExpand(item.id)">
                <span class="break-all">{{ item.value }}</span>
              </td>
            </tr>

            <!-- Expanded Row -->
            <tr v-if="expandedIds.has(item.id)" class="border-b border-border bg-muted/10">
              <td colspan="5" class="p-6">
                <div class="space-y-4 animate-in fade-in slide-in-from-top-2 duration-200">
                  <!-- File download (if file type) -->
                  <div v-if="item.artifactType === 'file'">
                    <a
                      :href="getDownloadUrl(item.id)"
                      target="_blank"
                      class="inline-flex items-center gap-2 text-primary hover:underline"
                    >
                      <Download class="h-4 w-4" />
                      {{ item.value }}
                      <span class="text-muted-foreground text-xs">
                        ({{ formatFileSize(item.streamLength || item.streamLen) }})
                      </span>
                    </a>

                    <!-- Hashes for file -->
                    <div class="grid gap-2 mt-3">
                      <div v-if="item.sha256" class="flex items-start gap-2">
                        <span class="text-xs font-semibold text-muted-foreground w-16">SHA256:</span>
                        <code class="text-xs font-mono break-all">{{ item.sha256 }}</code>
                      </div>
                      <div v-if="item.sha1" class="flex items-start gap-2">
                        <span class="text-xs font-semibold text-muted-foreground w-16">SHA1:</span>
                        <code class="text-xs font-mono break-all">{{ item.sha1 }}</code>
                      </div>
                      <div v-if="item.md5" class="flex items-start gap-2">
                        <span class="text-xs font-semibold text-muted-foreground w-16">MD5:</span>
                        <code class="text-xs font-mono break-all">{{ item.md5 }}</code>
                      </div>
                    </div>
                  </div>

                  <!-- Value (for non-file) -->
                  <div v-else class="space-y-1">
                    <span class="text-xs font-semibold text-muted-foreground">Value</span>
                    <div class="text-sm p-2 bg-muted/30 rounded font-mono break-all">
                      {{ item.value }}
                    </div>
                  </div>

                  <!-- Description -->
                  <div class="space-y-1">
                    <div class="flex items-center justify-between">
                      <span class="text-xs font-semibold text-muted-foreground">Description</span>
                      <button
                        v-if="!isEditing(item.id, 'description')"
                        @click="startEdit(item, 'description')"
                        class="p-1 text-muted-foreground hover:text-foreground transition-colors"
                      >
                        <Edit3 class="h-3 w-3" />
                      </button>
                    </div>
                    <div v-if="!isEditing(item.id, 'description')" class="text-sm p-2 bg-muted/30 rounded min-h-[2rem]">
                      {{ item.description || 'No description' }}
                    </div>
                    <div v-else class="flex gap-2">
                      <textarea
                        v-model="editValue"
                        rows="2"
                        class="flex-1 bg-background border border-border rounded-md p-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary/50"
                      ></textarea>
                      <div class="flex flex-col gap-1">
                        <button @click="saveEdit(item)" class="p-1 text-green-500 hover:text-green-400">
                          <Check class="h-4 w-4" />
                        </button>
                        <button @click="cancelEdit" class="p-1 text-muted-foreground hover:text-foreground">
                          <X class="h-4 w-4" />
                        </button>
                      </div>
                    </div>
                  </div>

                  <div class="grid grid-cols-3 gap-4">
                    <!-- IoC -->
                    <div class="space-y-1">
                      <div class="flex items-center justify-between">
                        <span class="text-xs font-semibold text-muted-foreground">IoC</span>
                        <button
                          v-if="!isEditing(item.id, 'ioc')"
                          @click="startEdit(item, 'ioc')"
                          class="p-1 text-muted-foreground hover:text-foreground transition-colors"
                        >
                          <Edit3 class="h-3 w-3" />
                        </button>
                      </div>
                      <div v-if="!isEditing(item.id, 'ioc')" class="text-sm">
                        <span :class="item.ioc ? 'text-amber-500 font-semibold' : 'text-muted-foreground'">
                          {{ item.ioc ? 'Yes' : 'No' }}
                        </span>
                      </div>
                      <div v-else class="flex gap-2 items-center">
                        <input
                          type="checkbox"
                          v-model="editValue"
                          class="rounded border-border"
                        />
                        <button @click="saveEdit(item)" class="p-1 text-green-500 hover:text-green-400">
                          <Check class="h-4 w-4" />
                        </button>
                        <button @click="cancelEdit" class="p-1 text-muted-foreground hover:text-foreground">
                          <X class="h-4 w-4" />
                        </button>
                      </div>
                    </div>

                    <!-- TLP -->
                    <div class="space-y-1">
                      <div class="flex items-center justify-between">
                        <span class="text-xs font-semibold text-muted-foreground">TLP Level</span>
                        <button
                          v-if="!isEditing(item.id, 'tlp')"
                          @click="startEdit(item, 'tlp')"
                          class="p-1 text-muted-foreground hover:text-foreground transition-colors"
                        >
                          <Edit3 class="h-3 w-3" />
                        </button>
                      </div>
                      <div v-if="!isEditing(item.id, 'tlp')">
                        <span :class="cn('px-2 py-0.5 rounded text-xs font-bold', getTlpColor(item.tlp))">
                          {{ item.tlp || 'Unknown' }}
                        </span>
                      </div>
                      <div v-else class="flex gap-2 items-center">
                        <select
                          v-model="editValue"
                          class="bg-background border border-border rounded-md p-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-primary/50"
                        >
                          <option v-for="opt in tlpOptions" :key="opt" :value="opt">{{ opt }}</option>
                        </select>
                        <button @click="saveEdit(item)" class="p-1 text-green-500 hover:text-green-400">
                          <Check class="h-4 w-4" />
                        </button>
                        <button @click="cancelEdit" class="p-1 text-muted-foreground hover:text-foreground">
                          <X class="h-4 w-4" />
                        </button>
                      </div>
                    </div>

                    <!-- Tags -->
                    <div class="space-y-1">
                      <span class="text-xs font-semibold text-muted-foreground">Tags</span>
                      <div class="flex flex-wrap gap-1">
                        <span
                          v-for="tag in (item.tags || [])"
                          :key="tag"
                          class="px-2 py-0.5 rounded-full bg-primary/10 text-primary text-xs"
                        >
                          {{ tag }}
                        </span>
                        <span v-if="!item.tags?.length" class="text-muted-foreground text-xs">No tags</span>
                      </div>
                    </div>
                  </div>

                  <!-- Analyze Jobs -->
                  <div v-if="analyzeJobs[item.id]?.length" class="space-y-2 pt-4 border-t border-border">
                    <span class="text-xs font-semibold text-muted-foreground">Analyzer Jobs</span>
                    <div class="space-y-2">
                      <div
                        v-for="job in analyzeJobs[item.id]"
                        :key="job.id"
                        class="rounded-lg border border-border bg-card overflow-hidden"
                      >
                        <!-- Job Header -->
                        <div
                          @click="toggleJob(job.id)"
                          class="flex items-center justify-between p-3 cursor-pointer hover:bg-muted/30 transition-colors"
                        >
                          <div class="flex items-center gap-3">
                            <component
                              :is="getJobStatusIcon(job)"
                              :class="cn('h-4 w-4', getJobStatusColor(job))"
                            />
                            <span class="text-sm font-medium">Job {{ job.id.slice(0, 8) }}</span>
                            <span class="text-xs text-muted-foreground">{{ formatDate(job.createTime) }}</span>
                          </div>
                          <div class="flex items-center gap-2">
                            <span class="text-xs text-muted-foreground">
                              {{ job.results?.length || 0 }} analyzers
                            </span>
                            <ChevronDown v-if="expandedJobs.has(job.id)" class="h-4 w-4 text-muted-foreground" />
                            <ChevronRight v-else class="h-4 w-4 text-muted-foreground" />
                          </div>
                        </div>

                        <!-- Job Results -->
                        <div v-if="expandedJobs.has(job.id)" class="border-t border-border">
                          <div v-if="job.status === 'pending'" class="p-4 text-center text-muted-foreground text-sm">
                            <Loader2 class="h-5 w-5 animate-spin mx-auto mb-2" />
                            Analysis in progress...
                          </div>
                          <div v-else-if="!job.results?.length" class="p-4 text-center text-muted-foreground text-sm">
                            No analyzer results available
                          </div>
                          <div v-else class="divide-y divide-border">
                            <div
                              v-for="result in job.results"
                              :key="result.id"
                              class="p-3"
                            >
                              <div
                                @click="toggleResult(`${job.id}-${result.id}`)"
                                class="flex items-center justify-between cursor-pointer"
                              >
                                <div class="flex items-center gap-2">
                                  <component
                                    :is="getResultIcon(result)"
                                    :class="cn('h-4 w-4', getAnalyzerDecoration(result).color)"
                                  />
                                  <span class="text-sm font-medium">{{ result.id }}</span>
                                  <span class="text-xs text-muted-foreground">{{ result.summary }}</span>
                                </div>
                                <ChevronDown
                                  v-if="expandedResults.has(`${job.id}-${result.id}`)"
                                  class="h-4 w-4 text-muted-foreground"
                                />
                                <ChevronRight v-else class="h-4 w-4 text-muted-foreground" />
                              </div>
                              <div
                                v-if="expandedResults.has(`${job.id}-${result.id}`)"
                                class="mt-2 p-2 bg-muted/30 rounded text-xs font-mono overflow-auto max-h-48"
                              >
                                <pre>{{ JSON.stringify(result.data, null, 2) }}</pre>
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>

                  <!-- Metadata -->
                  <div class="flex items-center gap-4 text-xs text-muted-foreground pt-2 border-t border-border">
                    <span>Created by {{ getUserName(item.userId) || 'Unknown' }}</span>
                    <span>{{ formatDate(item.createTime) }}</span>
                  </div>
                </div>
              </td>
            </tr>
          </template>
        </tbody>
      </table>
    </div>

    <!-- Delete Confirmation Dialog -->
    <div
      v-if="deleteConfirmId"
      class="fixed inset-0 bg-black/50 flex items-center justify-center z-50"
      @click="deleteConfirmId = null"
    >
      <div
        class="bg-card border border-border rounded-lg p-6 max-w-sm w-full mx-4 shadow-lg"
        @click.stop
      >
        <h3 class="text-lg font-semibold mb-2">Delete Evidence</h3>
        <p class="text-muted-foreground text-sm mb-4">
          Are you sure you want to delete this evidence? This action cannot be undone.
        </p>
        <div class="flex justify-end gap-2">
          <button
            @click="deleteConfirmId = null"
            class="px-3 py-1.5 text-sm text-muted-foreground hover:text-foreground"
          >
            Cancel
          </button>
          <button
            @click="confirmDelete(deleteConfirmId!)"
            class="px-3 py-1.5 bg-destructive text-destructive-foreground rounded-md text-sm font-medium hover:bg-destructive/90"
          >
            Delete
          </button>
        </div>
      </div>
    </div>
  </div>
</template>
