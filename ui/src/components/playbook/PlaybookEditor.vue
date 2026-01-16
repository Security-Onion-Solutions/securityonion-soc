<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import { X, Save, Plus, FileText, Target, Users, HelpCircle, RefreshCw, Globe } from 'lucide-vue-next'
import { cn } from '../../lib/utils'
import QuestionEditor from './QuestionEditor.vue'

interface PlaybookQuestion {
  question: string
  context: string
  range?: string
  query: string
  answer_sources?: string[]
}

interface Playbook {
  id?: string
  name: string
  description: string
  detection_id?: string
  detection_category?: string
  detection_type?: string
  is_global?: boolean
  contributors?: string[]
  questions: PlaybookQuestion[]
  isCommunity?: boolean
}

const props = defineProps<{
  playbook?: Playbook | null
  detectionId?: string
  detectionCategory?: string
  detectionType?: string
}>()

const emit = defineEmits<{
  save: [playbook: Playbook]
  cancel: []
}>()

const isEditing = computed(() => !!props.playbook?.id)

// Form state
const formData = ref<Playbook>({
  name: '',
  description: '',
  detection_id: '',
  detection_category: '',
  detection_type: '',
  is_global: false,
  contributors: [],
  questions: []
})

const contributorsText = computed({
  get: () => (formData.value.contributors || []).join('\n'),
  set: (value: string) => {
    formData.value.contributors = value.split('\n').map(s => s.trim()).filter(s => s)
  }
})

const saving = ref(false)
const error = ref<string | null>(null)

// Initialize form data
watch(() => props.playbook, (pb) => {
  if (pb) {
    formData.value = {
      id: pb.id,
      name: pb.name || '',
      description: pb.description || '',
      detection_id: pb.detection_id || '',
      detection_category: pb.detection_category || '',
      detection_type: pb.detection_type || '',
      is_global: pb.is_global || false,
      contributors: pb.contributors ? [...pb.contributors] : [],
      questions: pb.questions ? pb.questions.map(q => ({ ...q })) : []
    }
  } else {
    // New playbook - pre-fill detection info if provided
    formData.value = {
      name: '',
      description: '',
      detection_id: props.detectionId || '',
      detection_category: props.detectionCategory || '',
      detection_type: props.detectionType || '',
      is_global: false,
      contributors: [],
      questions: []
    }
  }
}, { immediate: true })

const addQuestion = () => {
  formData.value.questions.push({
    question: '',
    context: '',
    range: undefined,
    query: '',
    answer_sources: []
  })
}

const removeQuestion = (index: number) => {
  formData.value.questions.splice(index, 1)
}

const handleSave = async () => {
  error.value = null

  // Basic validation
  if (!formData.value.name.trim()) {
    error.value = 'Playbook name is required'
    return
  }

  saving.value = true
  try {
    emit('save', { ...formData.value })
  } catch (e: any) {
    error.value = e.message || 'Failed to save playbook'
  } finally {
    saving.value = false
  }
}
</script>

<template>
  <div class="fixed inset-0 z-50 bg-black/50 flex items-center justify-center p-4 overflow-y-auto">
    <div class="bg-card border border-border rounded-xl shadow-xl w-full max-w-3xl max-h-[90vh] overflow-hidden flex flex-col">
      <!-- Header -->
      <div class="flex items-center justify-between px-6 py-4 border-b border-border bg-muted/30">
        <h2 class="text-lg font-semibold text-foreground">
          {{ isEditing ? 'Edit Playbook' : 'Create Playbook' }}
        </h2>
        <button
          @click="emit('cancel')"
          class="p-2 text-muted-foreground hover:text-foreground hover:bg-muted rounded-lg transition-colors"
        >
          <X class="h-5 w-5" />
        </button>
      </div>

      <!-- Content -->
      <div class="flex-1 overflow-y-auto p-6 space-y-6">
        <!-- Error Message -->
        <div v-if="error" class="p-3 bg-red-500/10 border border-red-500/20 rounded-lg text-red-500 text-sm">
          {{ error }}
        </div>

        <!-- Basic Info Section -->
        <section class="space-y-4">
          <h3 class="flex items-center gap-2 text-sm font-semibold text-foreground uppercase tracking-wider">
            <FileText class="h-4 w-4 text-primary" />
            Basic Information
          </h3>

          <div class="space-y-4">
            <div class="space-y-1.5">
              <label class="text-sm font-medium text-foreground">Name <span class="text-red-500">*</span></label>
              <input
                v-model="formData.name"
                type="text"
                placeholder="My Investigation Playbook"
                class="w-full px-3 py-2 bg-background border border-border rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-primary/50 transition-all"
              />
            </div>

            <div class="space-y-1.5">
              <label class="text-sm font-medium text-foreground">Description</label>
              <textarea
                v-model="formData.description"
                rows="3"
                placeholder="A brief description of what this playbook helps investigate..."
                class="w-full px-3 py-2 bg-background border border-border rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-primary/50 transition-all resize-none"
              />
            </div>
          </div>
        </section>

        <!-- Detection Association Section -->
        <section class="space-y-4">
          <h3 class="flex items-center gap-2 text-sm font-semibold text-foreground uppercase tracking-wider">
            <Target class="h-4 w-4 text-primary" />
            Detection Association
          </h3>

          <!-- Global Playbook Toggle -->
          <div class="flex items-center gap-3 p-3 bg-muted/30 rounded-lg">
            <input
              type="checkbox"
              id="isGlobal"
              v-model="formData.is_global"
              class="h-4 w-4 rounded border-border text-primary focus:ring-primary/50"
            />
            <label for="isGlobal" class="flex items-center gap-2 text-sm font-medium text-foreground cursor-pointer">
              <Globe class="h-4 w-4 text-green-500" />
              Global Playbook
            </label>
            <span class="text-xs text-muted-foreground">
              This playbook will be included in guided analysis for all alerts
            </span>
          </div>

          <div v-if="!formData.is_global" class="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div class="space-y-1.5">
              <label class="text-sm font-medium text-foreground">Detection ID</label>
              <input
                v-model="formData.detection_id"
                type="text"
                placeholder="UUID or Public ID"
                class="w-full px-3 py-2 bg-background border border-border rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-primary/50 transition-all"
              />
            </div>

            <div class="space-y-1.5">
              <label class="text-sm font-medium text-foreground">Category</label>
              <input
                v-model="formData.detection_category"
                type="text"
                placeholder="e.g., process_creation"
                class="w-full px-3 py-2 bg-background border border-border rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-primary/50 transition-all"
              />
            </div>

            <div class="space-y-1.5">
              <label class="text-sm font-medium text-foreground">Type</label>
              <select
                v-model="formData.detection_type"
                class="w-full px-3 py-2 bg-background border border-border rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-primary/50 transition-all"
              >
                <option value="">Select type...</option>
                <option value="sigma">Sigma (ElastAlert)</option>
                <option value="nids">NIDS (Suricata)</option>
                <option value="yara">YARA (Strelka)</option>
              </select>
            </div>
          </div>
          <p v-if="!formData.is_global" class="text-xs text-muted-foreground">
            Link this playbook to specific detections by ID, category, or type. Leave blank to apply broadly.
          </p>
        </section>

        <!-- Contributors Section -->
        <section class="space-y-4">
          <h3 class="flex items-center gap-2 text-sm font-semibold text-foreground uppercase tracking-wider">
            <Users class="h-4 w-4 text-primary" />
            Contributors
          </h3>

          <div class="space-y-1.5">
            <label class="text-sm font-medium text-foreground">Authors <span class="text-xs text-muted-foreground font-normal">(one per line)</span></label>
            <textarea
              v-model="contributorsText"
              rows="2"
              placeholder="John Doe
Jane Smith"
              class="w-full px-3 py-2 bg-background border border-border rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-primary/50 transition-all resize-none"
            />
          </div>
        </section>

        <!-- Questions Section -->
        <section class="space-y-4">
          <div class="flex items-center justify-between">
            <h3 class="flex items-center gap-2 text-sm font-semibold text-foreground uppercase tracking-wider">
              <HelpCircle class="h-4 w-4 text-primary" />
              Investigation Questions
            </h3>
            <button
              @click="addQuestion"
              class="flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium text-primary bg-primary/10 hover:bg-primary/20 rounded-lg transition-colors"
            >
              <Plus class="h-4 w-4" />
              Add Question
            </button>
          </div>

          <div v-if="formData.questions.length === 0" class="p-8 border-2 border-dashed border-border rounded-lg text-center">
            <HelpCircle class="h-8 w-8 text-muted-foreground/50 mx-auto mb-2" />
            <p class="text-sm text-muted-foreground">No questions yet. Add questions to guide investigations.</p>
          </div>

          <div v-else class="space-y-4">
            <QuestionEditor
              v-for="(q, i) in formData.questions"
              :key="i"
              :model-value="q"
              :index="i"
              @update:model-value="formData.questions[i] = $event"
              @remove="removeQuestion(i)"
            />
          </div>
        </section>
      </div>

      <!-- Footer -->
      <div class="flex items-center justify-end gap-3 px-6 py-4 border-t border-border bg-muted/30">
        <button
          @click="emit('cancel')"
          :disabled="saving"
          class="px-4 py-2 text-sm font-medium text-muted-foreground hover:text-foreground hover:bg-muted rounded-lg transition-colors disabled:opacity-50"
        >
          Cancel
        </button>
        <button
          @click="handleSave"
          :disabled="saving"
          :class="cn(
            'flex items-center gap-2 px-4 py-2 text-sm font-medium text-primary-foreground bg-primary rounded-lg transition-colors',
            'hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed'
          )"
        >
          <RefreshCw v-if="saving" class="h-4 w-4 animate-spin" />
          <Save v-else class="h-4 w-4" />
          {{ saving ? 'Saving...' : (isEditing ? 'Update Playbook' : 'Create Playbook') }}
        </button>
      </div>
    </div>
  </div>
</template>
