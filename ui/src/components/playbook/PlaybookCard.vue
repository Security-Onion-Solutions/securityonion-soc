<script setup lang="ts">
import { ref, computed } from 'vue'
import { ChevronDown, ChevronRight, Edit, Trash2, Users, HelpCircle, Shield, Copy } from 'lucide-vue-next'
import { cn } from '../../lib/utils'
import { useFormatters } from '../../composables/useFormatters'

const { formatDate } = useFormatters()

interface PlaybookQuestion {
  question: string
  context: string
  range?: string
  query: string
}

interface Playbook {
  id: string
  name: string
  description: string
  detection_id?: string
  detection_category?: string
  detection_type?: string
  is_global?: boolean
  contributors?: string[]
  questions: PlaybookQuestion[]
  isCommunity: boolean
  createTime?: string
  updateTime?: string
}

const props = defineProps<{
  playbook: Playbook
  currentDetectionId?: string
}>()

// Determine why this playbook matched
const matchLevel = computed(() => {
  const pb = props.playbook
  // Check for global playbook first
  if (pb.is_global || (!pb.detection_id && !pb.detection_category && !pb.detection_type)) {
    return { label: 'Global', color: 'bg-green-500/10 text-green-500', tooltip: 'Applies to all alerts' }
  }
  // If playbook's detection_id matches the current detection, it's detection-specific
  if (pb.detection_id && props.currentDetectionId &&
      pb.detection_id.toLowerCase() === props.currentDetectionId.toLowerCase()) {
    return { label: 'Detection', color: 'bg-emerald-500/10 text-emerald-500', tooltip: 'Matches this specific detection' }
  }
  // If it has a detection_id but doesn't match current, it matched via category/engine
  if (pb.detection_id && props.currentDetectionId &&
      pb.detection_id.toLowerCase() !== props.currentDetectionId.toLowerCase()) {
    // This shouldn't normally happen, but handle it
    return { label: 'Other Detection', color: 'bg-gray-500/10 text-gray-500', tooltip: 'From another detection' }
  }
  // If it has a detection_id (but no currentDetectionId to compare), it's detection-level
  if (pb.detection_id) {
    return { label: 'Detection', color: 'bg-emerald-500/10 text-emerald-500', tooltip: `For detection: ${pb.detection_id}` }
  }
  // If it has detection_category, it's category-level
  if (pb.detection_category) {
    return { label: 'Category', color: 'bg-amber-500/10 text-amber-500', tooltip: `Matches category: ${pb.detection_category}` }
  }
  // If it only has detection_type, it's engine-level
  if (pb.detection_type) {
    return { label: 'Engine', color: 'bg-purple-500/10 text-purple-500', tooltip: `Matches engine: ${pb.detection_type}` }
  }
  // Generic/universal playbook
  return { label: 'General', color: 'bg-gray-500/10 text-gray-500', tooltip: 'General playbook' }
})

const emit = defineEmits<{
  edit: []
  delete: []
  duplicate: []
}>()

const expanded = ref(false)
</script>

<template>
  <div class="border border-border rounded-xl bg-card overflow-hidden transition-all hover:border-primary/30">
    <!-- Header -->
    <div class="p-4">
      <div class="flex items-start justify-between gap-4">
        <div class="flex-1 min-w-0">
          <div class="flex items-center gap-2 flex-wrap">
            <h3 class="font-semibold text-foreground truncate">{{ playbook.name }}</h3>
            <span
              :class="cn('px-2 py-0.5 text-xs font-medium rounded', matchLevel.color)"
              :title="matchLevel.tooltip"
            >
              {{ matchLevel.label }}
            </span>
            <span
              v-if="playbook.isCommunity"
              class="px-2 py-0.5 text-xs font-medium bg-blue-500/10 text-blue-500 rounded"
            >
              Community
            </span>
            <span
              v-else
              class="px-2 py-0.5 text-xs font-medium bg-cyan-500/10 text-cyan-500 rounded"
            >
              Custom
            </span>
          </div>
          <p v-if="playbook.description" class="text-sm text-muted-foreground mt-1 line-clamp-2">
            {{ playbook.description }}
          </p>

          <!-- Metadata -->
          <div class="flex items-center gap-4 mt-2 text-xs text-muted-foreground flex-wrap">
            <span v-if="playbook.detection_type" class="flex items-center gap-1">
              <Shield class="h-3 w-3" />
              {{ playbook.detection_type }}
            </span>
            <span v-if="playbook.detection_category" class="flex items-center gap-1">
              {{ playbook.detection_category }}
            </span>
            <span v-if="playbook.contributors?.length" class="flex items-center gap-1">
              <Users class="h-3 w-3" />
              {{ playbook.contributors.join(', ') }}
            </span>
            <span class="flex items-center gap-1">
              <HelpCircle class="h-3 w-3" />
              {{ playbook.questions?.length || 0 }} question{{ (playbook.questions?.length || 0) !== 1 ? 's' : '' }}
            </span>
          </div>
        </div>

        <!-- Actions -->
        <div class="flex items-center gap-1">
          <button
            v-if="!playbook.isCommunity"
            @click.stop="emit('edit')"
            class="p-2 text-muted-foreground hover:text-primary hover:bg-primary/10 rounded-lg transition-colors"
            title="Edit playbook"
          >
            <Edit class="h-4 w-4" />
          </button>
          <button
            @click.stop="emit('duplicate')"
            class="p-2 text-muted-foreground hover:text-blue-500 hover:bg-blue-500/10 rounded-lg transition-colors"
            :title="playbook.isCommunity ? 'Create editable copy' : 'Duplicate playbook'"
          >
            <Copy class="h-4 w-4" />
          </button>
          <button
            v-if="!playbook.isCommunity"
            @click.stop="emit('delete')"
            class="p-2 text-muted-foreground hover:text-red-500 hover:bg-red-500/10 rounded-lg transition-colors"
            title="Delete playbook"
          >
            <Trash2 class="h-4 w-4" />
          </button>
          <button
            @click="expanded = !expanded"
            class="p-2 text-muted-foreground hover:text-foreground hover:bg-muted rounded-lg transition-colors"
            :title="expanded ? 'Collapse' : 'Expand'"
          >
            <ChevronDown v-if="expanded" class="h-4 w-4" />
            <ChevronRight v-else class="h-4 w-4" />
          </button>
        </div>
      </div>
    </div>

    <!-- Expandable Questions Preview -->
    <div
      v-if="expanded && playbook.questions?.length"
      class="border-t border-border bg-muted/20"
    >
      <div class="p-4 space-y-3">
        <h4 class="text-sm font-medium text-muted-foreground">Investigation Questions</h4>
        <div
          v-for="(q, i) in playbook.questions"
          :key="i"
          class="p-3 bg-background border border-border rounded-lg"
        >
          <div class="flex items-start gap-2">
            <span class="flex-shrink-0 w-5 h-5 flex items-center justify-center bg-primary/10 text-primary text-xs font-bold rounded">
              {{ i + 1 }}
            </span>
            <div class="flex-1 min-w-0">
              <p class="text-sm font-medium text-foreground">{{ q.question }}</p>
              <p v-if="q.context" class="text-xs text-muted-foreground mt-1">{{ q.context }}</p>
              <div v-if="q.range" class="mt-1">
                <span class="text-xs bg-primary/10 text-primary px-1.5 py-0.5 rounded">
                  Range: {{ q.range }}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Empty state for no questions -->
    <div
      v-else-if="expanded && !playbook.questions?.length"
      class="border-t border-border bg-muted/20 p-4"
    >
      <p class="text-sm text-muted-foreground text-center">No questions defined</p>
    </div>
  </div>
</template>
