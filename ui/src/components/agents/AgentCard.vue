<script setup lang="ts">
import { computed } from 'vue'
import {
  Play,
  Pause,
  Edit,
  Trash2,
  Clock,
  Zap,
  Calendar,
  MousePointer,
  Wrench
} from 'lucide-vue-next'
import { cn } from '../../lib/utils'
import { useFormatters } from '../../composables/useFormatters'
import type { AIAgent } from '../../composables/useAgents'

const { formatRelativeTime } = useFormatters()

const props = defineProps<{
  agent: AIAgent
}>()

const emit = defineEmits<{
  edit: []
  delete: []
  toggleStatus: []
}>()

// Status styling
const statusStyles = computed(() => {
  if (props.agent.status === 'active') {
    return {
      bg: 'bg-green-500/10',
      text: 'text-green-500',
      label: 'Active'
    }
  }
  return {
    bg: 'bg-amber-500/10',
    text: 'text-amber-500',
    label: 'Paused'
  }
})

// Trigger type styling
const triggerStyles = computed(() => {
  switch (props.agent.triggerType) {
    case 'event-driven':
      return {
        icon: Zap,
        bg: 'bg-purple-500/10',
        text: 'text-purple-500',
        label: 'Event-Driven'
      }
    case 'scheduled':
      return {
        icon: Calendar,
        bg: 'bg-blue-500/10',
        text: 'text-blue-500',
        label: 'Scheduled'
      }
    case 'manual':
    default:
      return {
        icon: MousePointer,
        bg: 'bg-gray-500/10',
        text: 'text-gray-400',
        label: 'Manual'
      }
  }
})

// Enabled tools count
const enabledToolsCount = computed(() => {
  return props.agent.tools.filter(t => t.enabled).length
})
</script>

<template>
  <div class="border border-border rounded-xl bg-card overflow-hidden transition-all hover:border-primary/30">
    <div class="p-4">
      <div class="flex items-start justify-between gap-4">
        <div class="flex-1 min-w-0">
          <!-- Name and badges -->
          <div class="flex items-center gap-2 flex-wrap">
            <h3 class="font-semibold text-foreground truncate">{{ agent.name }}</h3>
            <span
              :class="cn('px-2 py-0.5 text-xs font-medium rounded', statusStyles.bg, statusStyles.text)"
            >
              {{ statusStyles.label }}
            </span>
            <span
              :class="cn('inline-flex items-center gap-1 px-2 py-0.5 text-xs font-medium rounded', triggerStyles.bg, triggerStyles.text)"
            >
              <component :is="triggerStyles.icon" class="h-3 w-3" />
              {{ triggerStyles.label }}
            </span>
          </div>

          <!-- Description -->
          <p class="text-sm text-muted-foreground mt-1 line-clamp-2">
            {{ agent.description }}
          </p>

          <!-- Metadata -->
          <div class="flex items-center gap-4 mt-2 text-xs text-muted-foreground flex-wrap">
            <span v-if="agent.lastRun" class="flex items-center gap-1">
              <Clock class="h-3 w-3" />
              Last run: {{ formatRelativeTime(agent.lastRun) }}
            </span>
            <span v-else class="flex items-center gap-1">
              <Clock class="h-3 w-3" />
              Never run
            </span>
            <span class="flex items-center gap-1">
              <Wrench class="h-3 w-3" />
              {{ enabledToolsCount }} tool{{ enabledToolsCount !== 1 ? 's' : '' }} enabled
            </span>
          </div>
        </div>

        <!-- Actions -->
        <div class="flex items-center gap-1">
          <button
            @click.stop="emit('toggleStatus')"
            :class="cn(
              'p-2 rounded-lg transition-colors',
              agent.status === 'active'
                ? 'text-amber-500 hover:text-amber-400 hover:bg-amber-500/10'
                : 'text-green-500 hover:text-green-400 hover:bg-green-500/10'
            )"
            :title="agent.status === 'active' ? 'Pause agent' : 'Activate agent'"
          >
            <Pause v-if="agent.status === 'active'" class="h-4 w-4" />
            <Play v-else class="h-4 w-4" />
          </button>
          <button
            @click.stop="emit('edit')"
            class="p-2 text-muted-foreground hover:text-primary hover:bg-primary/10 rounded-lg transition-colors"
            title="Edit agent"
          >
            <Edit class="h-4 w-4" />
          </button>
          <button
            @click.stop="emit('delete')"
            class="p-2 text-muted-foreground hover:text-red-500 hover:bg-red-500/10 rounded-lg transition-colors"
            title="Delete agent"
          >
            <Trash2 class="h-4 w-4" />
          </button>
        </div>
      </div>
    </div>
  </div>
</template>
