<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import {
  Plus,
  RefreshCw,
  ChevronRight,
  ChevronDown,
  Download,
  Copy,
  Eye,
  Trash2,
  Upload,
  File,
  Shield,
  X,
  Check,
  Edit3,
  Loader2
} from 'lucide-vue-next'
import { cn } from '../../lib/utils'
import { useArtifacts, type Artifact } from '../../composables/useArtifacts'
import { useFormatters } from '../../composables/useFormatters'
import { useUsers } from '../../composables/useUsers'

const props = defineProps<{
  caseId: string
  attachments: Artifact[]
}>()

const emit = defineEmits<{
  (e: 'refresh'): void
  (e: 'addEvidence', hash: string, hashType: string): void
}>()

const {
  createFileArtifact,
  updateArtifact,
  deleteArtifact,
  getDownloadUrl,
  copyToClipboard,
  formatFileSize,
  loading
} = useArtifacts()

const { formatDate } = useFormatters()
const { getUserName } = useUsers()

// UI State
const showAddForm = ref(false)
const expandedIds = ref<Set<string>>(new Set())
const editingField = ref<{ id: string; field: string } | null>(null)
const editValue = ref<any>(null)
const deleteConfirmId = ref<string | null>(null)
const copiedHash = ref<string | null>(null)

// Form state
const formData = ref({
  description: '',
  tlp: 'AMBER',
  tags: [] as string[],
  protected: false,
})
const selectedFile = ref<File | null>(null)
const dragOver = ref(false)
const submitting = ref(false)
const formError = ref<string | null>(null)

// TLP options
const tlpOptions = ['RED', 'AMBER', 'GREEN', 'WHITE']

// Toggle row expansion
function toggleExpand(id: string) {
  if (expandedIds.value.has(id)) {
    expandedIds.value.delete(id)
  } else {
    expandedIds.value.add(id)
  }
  expandedIds.value = new Set(expandedIds.value)
}

// File handling
function handleFileSelect(event: Event) {
  const input = event.target as HTMLInputElement
  if (input.files && input.files.length > 0) {
    selectedFile.value = input.files[0]
  }
}

function handleDrop(event: DragEvent) {
  dragOver.value = false
  if (event.dataTransfer?.files && event.dataTransfer.files.length > 0) {
    selectedFile.value = event.dataTransfer.files[0]
  }
}

function handleDragOver(event: DragEvent) {
  event.preventDefault()
  dragOver.value = true
}

function handleDragLeave() {
  dragOver.value = false
}

function clearFile() {
  selectedFile.value = null
}

// Submit new attachment
async function submitAttachment() {
  if (!selectedFile.value) {
    formError.value = 'Please select a file'
    return
  }

  submitting.value = true
  formError.value = null

  try {
    await createFileArtifact(
      {
        caseId: props.caseId,
        groupType: 'attachments',
        artifactType: 'file',
        value: selectedFile.value.name,
        description: formData.value.description,
        tlp: formData.value.tlp,
        tags: formData.value.tags,
        protected: formData.value.protected,
      },
      selectedFile.value
    )

    // Reset form
    showAddForm.value = false
    selectedFile.value = null
    formData.value = {
      description: '',
      tlp: 'AMBER',
      tags: [],
      protected: false,
    }

    emit('refresh')
  } catch (e: any) {
    formError.value = e.message || 'Failed to upload file'
  } finally {
    submitting.value = false
  }
}

// Cancel add form
function cancelAdd() {
  showAddForm.value = false
  selectedFile.value = null
  formData.value = {
    description: '',
    tlp: 'AMBER',
    tags: [],
    protected: false,
  }
  formError.value = null
}

// Edit field
function startEdit(attachment: Artifact, field: string) {
  editingField.value = { id: attachment.id, field }
  editValue.value = (attachment as any)[field]
}

async function saveEdit(attachment: Artifact) {
  if (!editingField.value) return

  try {
    await updateArtifact({
      ...attachment,
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

// Delete attachment
async function confirmDelete(id: string) {
  try {
    await deleteArtifact(id)
    deleteConfirmId.value = null
    emit('refresh')
  } catch (e) {
    console.error('Failed to delete:', e)
  }
}

// Copy hash to clipboard
async function handleCopyHash(hash: string) {
  const success = await copyToClipboard(hash)
  if (success) {
    copiedHash.value = hash
    setTimeout(() => {
      copiedHash.value = null
    }, 2000)
  }
}

// Add hash as evidence
function addHashAsEvidence(hash: string, hashType: string) {
  emit('addEvidence', hash, hashType)
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
        Add Attachment
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
        <Upload class="h-4 w-4" />
        Upload Attachment
      </div>

      <!-- Error Message -->
      <div v-if="formError" class="p-3 rounded-lg bg-destructive/10 border border-destructive/20 text-destructive text-sm">
        {{ formError }}
      </div>

      <!-- File Drop Zone -->
      <div
        @drop.prevent="handleDrop"
        @dragover="handleDragOver"
        @dragleave="handleDragLeave"
        :class="cn(
          'border-2 border-dashed rounded-lg p-6 text-center transition-colors',
          dragOver ? 'border-primary bg-primary/5' : 'border-border',
          selectedFile ? 'bg-muted/50' : ''
        )"
      >
        <div v-if="!selectedFile" class="space-y-2">
          <File class="h-10 w-10 mx-auto text-muted-foreground" />
          <p class="text-sm text-muted-foreground">
            Drag and drop a file here, or
            <label class="text-primary cursor-pointer hover:underline">
              browse
              <input type="file" class="hidden" @change="handleFileSelect" />
            </label>
          </p>
        </div>
        <div v-else class="flex items-center justify-center gap-3">
          <File class="h-6 w-6 text-primary" />
          <span class="text-sm font-medium">{{ selectedFile.name }}</span>
          <span class="text-xs text-muted-foreground">({{ formatFileSize(selectedFile.size) }})</span>
          <button @click="clearFile" class="text-muted-foreground hover:text-foreground">
            <X class="h-4 w-4" />
          </button>
        </div>
      </div>

      <!-- Form Fields -->
      <div class="grid gap-4">
        <!-- Description -->
        <div>
          <label class="text-xs font-medium text-muted-foreground mb-1 block">Description</label>
          <textarea
            v-model="formData.description"
            rows="2"
            class="w-full bg-background border border-border rounded-md p-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary/50"
            placeholder="Describe this attachment..."
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

          <!-- Protected -->
          <div class="flex items-center gap-2 pt-5">
            <input
              type="checkbox"
              id="protected"
              v-model="formData.protected"
              class="rounded border-border"
            />
            <label for="protected" class="text-sm flex items-center gap-1">
              <Shield class="h-4 w-4" />
              Protected (auto-zip on download)
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
          @click="submitAttachment"
          :disabled="!selectedFile || submitting"
          class="flex items-center gap-2 px-4 py-1.5 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90 disabled:opacity-50"
        >
          <Loader2 v-if="submitting" class="h-4 w-4 animate-spin" />
          {{ submitting ? 'Uploading...' : 'Upload' }}
        </button>
      </div>
    </div>

    <!-- Attachments List -->
    <div v-if="attachments.length === 0 && !showAddForm" class="text-center py-8 text-muted-foreground">
      <File class="h-12 w-12 mx-auto mb-3 opacity-50" />
      <p>No attachments yet. Click "Add Attachment" to upload a file.</p>
    </div>

    <div v-else class="rounded-md border border-border bg-card overflow-hidden">
      <table class="w-full text-sm">
        <thead>
          <tr class="border-b border-border bg-muted/50">
            <th class="w-10 px-4"></th>
            <th class="h-10 px-4 text-left align-middle font-medium text-muted-foreground">Created</th>
            <th class="h-10 px-4 text-left align-middle font-medium text-muted-foreground">Modified</th>
            <th class="h-10 px-4 text-left align-middle font-medium text-muted-foreground">Filename</th>
            <th class="h-10 px-4 text-left align-middle font-medium text-muted-foreground w-20">Actions</th>
          </tr>
        </thead>
        <tbody>
          <template v-for="attachment in attachments" :key="attachment.id">
            <tr
              @click="toggleExpand(attachment.id)"
              :class="cn(
                'border-b border-border transition-colors hover:bg-muted/50 cursor-pointer',
                expandedIds.has(attachment.id) && 'bg-muted/30'
              )"
            >
              <td class="p-4 align-middle text-center">
                <ChevronDown v-if="expandedIds.has(attachment.id)" class="h-4 w-4 text-muted-foreground" />
                <ChevronRight v-else class="h-4 w-4 text-muted-foreground" />
              </td>
              <td class="p-4 align-middle text-muted-foreground">{{ formatDate(attachment.createTime) }}</td>
              <td class="p-4 align-middle text-muted-foreground">{{ formatDate(attachment.updateTime) }}</td>
              <td class="p-4 align-middle font-medium">
                <div class="flex items-center gap-2">
                  <File class="h-4 w-4 text-muted-foreground" />
                  {{ attachment.value }}
                  <Shield v-if="attachment.protected" class="h-3 w-3 text-amber-500" title="Protected" />
                </div>
              </td>
              <td class="p-4 align-middle" @click.stop>
                <button
                  @click="deleteConfirmId = attachment.id"
                  class="p-1 text-muted-foreground hover:text-destructive transition-colors"
                  title="Delete"
                >
                  <Trash2 class="h-4 w-4" />
                </button>
              </td>
            </tr>

            <!-- Expanded Row -->
            <tr v-if="expandedIds.has(attachment.id)" class="border-b border-border bg-muted/10">
              <td colspan="5" class="p-6">
                <div class="space-y-4 animate-in fade-in slide-in-from-top-2 duration-200">
                  <!-- Download Link -->
                  <div v-if="attachment.artifactType !== 'assistant_chat'">
                    <a
                      :href="getDownloadUrl(attachment.id)"
                      target="_blank"
                      class="inline-flex items-center gap-2 text-primary hover:underline"
                    >
                      <Download class="h-4 w-4" />
                      {{ attachment.value }}
                      <span class="text-muted-foreground text-xs">
                        ({{ formatFileSize(attachment.streamLength || attachment.streamLen) }})
                      </span>
                    </a>
                  </div>

                  <!-- Hashes -->
                  <div class="grid gap-3">
                    <div v-if="attachment.sha256" class="flex items-start gap-2">
                      <span class="text-xs font-semibold text-muted-foreground w-16">SHA256:</span>
                      <code class="text-xs font-mono break-all flex-1">{{ attachment.sha256 }}</code>
                      <div class="flex gap-1">
                        <button
                          @click="handleCopyHash(attachment.sha256!)"
                          class="p-1 text-muted-foreground hover:text-foreground transition-colors"
                          title="Copy to clipboard"
                        >
                          <Check v-if="copiedHash === attachment.sha256" class="h-3.5 w-3.5 text-green-500" />
                          <Copy v-else class="h-3.5 w-3.5" />
                        </button>
                        <button
                          @click="addHashAsEvidence(attachment.sha256!, 'sha256')"
                          class="p-1 text-muted-foreground hover:text-primary transition-colors"
                          title="Add as evidence"
                        >
                          <Eye class="h-3.5 w-3.5" />
                        </button>
                      </div>
                    </div>
                    <div v-if="attachment.sha1" class="flex items-start gap-2">
                      <span class="text-xs font-semibold text-muted-foreground w-16">SHA1:</span>
                      <code class="text-xs font-mono break-all flex-1">{{ attachment.sha1 }}</code>
                      <div class="flex gap-1">
                        <button
                          @click="handleCopyHash(attachment.sha1!)"
                          class="p-1 text-muted-foreground hover:text-foreground transition-colors"
                          title="Copy to clipboard"
                        >
                          <Check v-if="copiedHash === attachment.sha1" class="h-3.5 w-3.5 text-green-500" />
                          <Copy v-else class="h-3.5 w-3.5" />
                        </button>
                        <button
                          @click="addHashAsEvidence(attachment.sha1!, 'sha1')"
                          class="p-1 text-muted-foreground hover:text-primary transition-colors"
                          title="Add as evidence"
                        >
                          <Eye class="h-3.5 w-3.5" />
                        </button>
                      </div>
                    </div>
                    <div v-if="attachment.md5" class="flex items-start gap-2">
                      <span class="text-xs font-semibold text-muted-foreground w-16">MD5:</span>
                      <code class="text-xs font-mono break-all flex-1">{{ attachment.md5 }}</code>
                      <div class="flex gap-1">
                        <button
                          @click="handleCopyHash(attachment.md5!)"
                          class="p-1 text-muted-foreground hover:text-foreground transition-colors"
                          title="Copy to clipboard"
                        >
                          <Check v-if="copiedHash === attachment.md5" class="h-3.5 w-3.5 text-green-500" />
                          <Copy v-else class="h-3.5 w-3.5" />
                        </button>
                        <button
                          @click="addHashAsEvidence(attachment.md5!, 'md5')"
                          class="p-1 text-muted-foreground hover:text-primary transition-colors"
                          title="Add as evidence"
                        >
                          <Eye class="h-3.5 w-3.5" />
                        </button>
                      </div>
                    </div>
                  </div>

                  <!-- Description -->
                  <div class="space-y-1">
                    <div class="flex items-center justify-between">
                      <span class="text-xs font-semibold text-muted-foreground">Description</span>
                      <button
                        v-if="!isEditing(attachment.id, 'description')"
                        @click="startEdit(attachment, 'description')"
                        class="p-1 text-muted-foreground hover:text-foreground transition-colors"
                      >
                        <Edit3 class="h-3 w-3" />
                      </button>
                    </div>
                    <div v-if="!isEditing(attachment.id, 'description')" class="text-sm p-2 bg-muted/30 rounded min-h-[2rem]">
                      {{ attachment.description || 'No description' }}
                    </div>
                    <div v-else class="flex gap-2">
                      <textarea
                        v-model="editValue"
                        rows="2"
                        class="flex-1 bg-background border border-border rounded-md p-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary/50"
                      ></textarea>
                      <div class="flex flex-col gap-1">
                        <button @click="saveEdit(attachment)" class="p-1 text-green-500 hover:text-green-400">
                          <Check class="h-4 w-4" />
                        </button>
                        <button @click="cancelEdit" class="p-1 text-muted-foreground hover:text-foreground">
                          <X class="h-4 w-4" />
                        </button>
                      </div>
                    </div>
                  </div>

                  <!-- TLP -->
                  <div class="space-y-1">
                    <div class="flex items-center justify-between">
                      <span class="text-xs font-semibold text-muted-foreground">TLP Level</span>
                      <button
                        v-if="!isEditing(attachment.id, 'tlp')"
                        @click="startEdit(attachment, 'tlp')"
                        class="p-1 text-muted-foreground hover:text-foreground transition-colors"
                      >
                        <Edit3 class="h-3 w-3" />
                      </button>
                    </div>
                    <div v-if="!isEditing(attachment.id, 'tlp')">
                      <span :class="cn('px-2 py-0.5 rounded text-xs font-bold', getTlpColor(attachment.tlp))">
                        {{ attachment.tlp || 'Unknown' }}
                      </span>
                    </div>
                    <div v-else class="flex gap-2 items-center">
                      <select
                        v-model="editValue"
                        class="bg-background border border-border rounded-md p-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-primary/50"
                      >
                        <option v-for="opt in tlpOptions" :key="opt" :value="opt">{{ opt }}</option>
                      </select>
                      <button @click="saveEdit(attachment)" class="p-1 text-green-500 hover:text-green-400">
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
                        v-for="tag in (attachment.tags || [])"
                        :key="tag"
                        class="px-2 py-0.5 rounded-full bg-primary/10 text-primary text-xs"
                      >
                        {{ tag }}
                      </span>
                      <span v-if="!attachment.tags?.length" class="text-muted-foreground text-xs">No tags</span>
                    </div>
                  </div>

                  <!-- Metadata -->
                  <div class="flex items-center gap-4 text-xs text-muted-foreground pt-2 border-t border-border">
                    <span>Created by {{ getUserName(attachment.userId) || 'Unknown' }}</span>
                    <span>{{ formatDate(attachment.createTime) }}</span>
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
        <h3 class="text-lg font-semibold mb-2">Delete Attachment</h3>
        <p class="text-muted-foreground text-sm mb-4">
          Are you sure you want to delete this attachment? This action cannot be undone.
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
