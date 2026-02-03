<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import {
  X,
  Save,
  FileText,
  Zap,
  MessageSquare,
  Wrench,
  RefreshCw
} from 'lucide-vue-next'
import { cn } from '../../lib/utils'
import { useAgents, type AIAgent, type AgentTool } from '../../composables/useAgents'

const { getAvailableTools } = useAgents()

const props = defineProps<{
  agent?: AIAgent | null
}>()

const emit = defineEmits<{
  save: [agent: Omit<AIAgent, 'id' | 'createTime' | 'updateTime'> & { id?: string }]
  cancel: []
}>()

const isEditing = computed(() => !!props.agent?.id)

// Form state
const formData = ref<{
  id?: string
  name: string
  description: string
  status: 'active' | 'paused'
  triggerType: 'manual' | 'scheduled' | 'event-driven'
  systemPrompt: string
  tools: AgentTool[]
  lastRun?: string
}>({
  name: '',
  description: '',
  status: 'paused',
  triggerType: 'manual',
  systemPrompt: '',
  tools: []
})

const saving = ref(false)
const error = ref<string | null>(null)

// Initialize form data
watch(() => props.agent, (agent) => {
  if (agent) {
    formData.value = {
      id: agent.id,
      name: agent.name || '',
      description: agent.description || '',
      status: agent.status || 'paused',
      triggerType: agent.triggerType || 'manual',
      systemPrompt: agent.systemPrompt || '',
      tools: agent.tools ? agent.tools.map(t => ({ ...t })) : getAvailableTools(),
      lastRun: agent.lastRun
    }
  } else {
    // New agent
    formData.value = {
      name: '',
      description: '',
      status: 'paused',
      triggerType: 'manual',
      systemPrompt: '',
      tools: getAvailableTools()
    }
  }
}, { immediate: true })

// Toggle tool enabled state
function toggleTool(toolId: string) {
  const tool = formData.value.tools.find(t => t.id === toolId)
  if (tool) {
    tool.enabled = !tool.enabled
  }
}

// Save handler
const handleSave = async () => {
  error.value = null

  // Basic validation
  if (!formData.value.name.trim()) {
    error.value = 'Agent name is required'
    return
  }

  if (!formData.value.systemPrompt.trim()) {
    error.value = 'System prompt is required'
    return
  }

  saving.value = true
  try {
    emit('save', {
      id: formData.value.id,
      name: formData.value.name.trim(),
      description: formData.value.description.trim(),
      status: formData.value.status,
      triggerType: formData.value.triggerType,
      systemPrompt: formData.value.systemPrompt.trim(),
      tools: formData.value.tools,
      lastRun: formData.value.lastRun
    })
  } catch (e: any) {
    error.value = e.message || 'Failed to save agent'
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
          {{ isEditing ? 'Edit AI Agent' : 'Create AI Agent' }}
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
                placeholder="My AI Agent"
                class="w-full px-3 py-2 bg-background border border-border rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-primary/50 transition-all"
              />
            </div>

            <div class="space-y-1.5">
              <label class="text-sm font-medium text-foreground">Description</label>
              <textarea
                v-model="formData.description"
                rows="2"
                placeholder="A brief description of what this agent does..."
                class="w-full px-3 py-2 bg-background border border-border rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-primary/50 transition-all resize-none"
              />
            </div>
          </div>
        </section>

        <!-- Trigger Section -->
        <section class="space-y-4">
          <h3 class="flex items-center gap-2 text-sm font-semibold text-foreground uppercase tracking-wider">
            <Zap class="h-4 w-4 text-primary" />
            Trigger Configuration
          </h3>

          <div class="space-y-1.5">
            <label class="text-sm font-medium text-foreground">Trigger Type</label>
            <select
              v-model="formData.triggerType"
              class="w-full px-3 py-2 bg-background border border-border rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-primary/50 transition-all"
            >
              <option value="manual">Manual - Run on demand</option>
              <option value="scheduled">Scheduled - Run on a schedule</option>
              <option value="event-driven">Event-Driven - Run when events occur</option>
            </select>
            <p class="text-xs text-muted-foreground mt-1">
              <template v-if="formData.triggerType === 'manual'">
                This agent will only run when manually triggered by a user.
              </template>
              <template v-else-if="formData.triggerType === 'scheduled'">
                This agent will run automatically on a configured schedule.
              </template>
              <template v-else>
                This agent will run automatically when specific events occur (e.g., new alert, new case).
              </template>
            </p>
          </div>
        </section>

        <!-- System Prompt Section -->
        <section class="space-y-4">
          <h3 class="flex items-center gap-2 text-sm font-semibold text-foreground uppercase tracking-wider">
            <MessageSquare class="h-4 w-4 text-primary" />
            System Prompt
          </h3>

          <div class="space-y-1.5">
            <label class="text-sm font-medium text-foreground">Instructions <span class="text-red-500">*</span></label>
            <textarea
              v-model="formData.systemPrompt"
              rows="8"
              placeholder="You are a security analyst AI agent. Your job is to..."
              class="w-full px-3 py-2 bg-background border border-border rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-primary/50 transition-all resize-none font-mono"
            />
            <p class="text-xs text-muted-foreground">
              Define the agent's role, capabilities, and behavior. Be specific about what actions it should take.
            </p>
          </div>
        </section>

        <!-- Tools Section -->
        <section class="space-y-4">
          <h3 class="flex items-center gap-2 text-sm font-semibold text-foreground uppercase tracking-wider">
            <Wrench class="h-4 w-4 text-primary" />
            Available Tools
          </h3>
          <p class="text-xs text-muted-foreground -mt-2">
            Select the tools this agent can use to perform its tasks.
          </p>

          <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
            <button
              v-for="tool in formData.tools"
              :key="tool.id"
              @click="toggleTool(tool.id)"
              :class="cn(
                'flex items-start gap-3 p-3 rounded-lg border text-left transition-all',
                tool.enabled
                  ? 'border-primary bg-primary/5 ring-1 ring-primary/20'
                  : 'border-border hover:border-muted-foreground/30'
              )"
            >
              <div
                :class="cn(
                  'flex-shrink-0 w-5 h-5 rounded border flex items-center justify-center mt-0.5',
                  tool.enabled
                    ? 'bg-primary border-primary'
                    : 'border-muted-foreground/30'
                )"
              >
                <svg
                  v-if="tool.enabled"
                  class="w-3 h-3 text-primary-foreground"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M5 13l4 4L19 7" />
                </svg>
              </div>
              <div class="flex-1 min-w-0">
                <div class="font-medium text-sm text-foreground">{{ tool.name }}</div>
                <div class="text-xs text-muted-foreground mt-0.5">{{ tool.description }}</div>
              </div>
            </button>
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
          {{ saving ? 'Saving...' : (isEditing ? 'Update Agent' : 'Create Agent') }}
        </button>
      </div>
    </div>
  </div>
</template>
