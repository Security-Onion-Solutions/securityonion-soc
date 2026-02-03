<script setup lang="ts">
import { computed } from 'vue'
import {
  X,
  CheckCircle,
  XCircle,
  Activity,
  Clock,
  Cpu,
  Zap,
  Calendar,
  MousePointer,
  Bell,
  Briefcase,
  Search,
  Shield,
  AlertTriangle,
  FileText,
  ChevronRight
} from 'lucide-vue-next'
import { cn } from '../../lib/utils'
import { useFormatters } from '../../composables/useFormatters'
import type { AgentExecution } from '../../composables/useAgents'

const props = defineProps<{
  execution: AgentExecution
}>()

const emit = defineEmits<{
  close: []
}>()

const { formatRelativeTime, formatDate } = useFormatters()

// Format duration
function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`
  return `${(ms / 60000).toFixed(1)}m`
}

// Format tokens
function formatTokens(tokens: number): string {
  if (tokens >= 1000000) return `${(tokens / 1000000).toFixed(1)}M`
  if (tokens >= 1000) return `${(tokens / 1000).toFixed(1)}K`
  return String(tokens)
}

// Get status styles
const statusStyle = computed(() => {
  switch (props.execution.status) {
    case 'completed':
      return { bg: 'bg-green-500/10', text: 'text-green-500', border: 'border-green-500/20', icon: CheckCircle, label: 'Completed' }
    case 'failed':
      return { bg: 'bg-red-500/10', text: 'text-red-500', border: 'border-red-500/20', icon: XCircle, label: 'Failed' }
    case 'running':
      return { bg: 'bg-blue-500/10', text: 'text-blue-500', border: 'border-blue-500/20', icon: Activity, label: 'Running' }
    default:
      return { bg: 'bg-gray-500/10', text: 'text-gray-500', border: 'border-gray-500/20', icon: Clock, label: 'Unknown' }
  }
})

// Get trigger styles
const triggerStyle = computed(() => {
  switch (props.execution.trigger) {
    case 'event':
      return { icon: Zap, bg: 'bg-purple-500/10', text: 'text-purple-500', label: 'Event-Driven' }
    case 'scheduled':
      return { icon: Calendar, bg: 'bg-blue-500/10', text: 'text-blue-500', label: 'Scheduled' }
    case 'manual':
    default:
      return { icon: MousePointer, bg: 'bg-gray-500/10', text: 'text-gray-400', label: 'Manual' }
  }
})

// Get tool icon
function getToolIcon(tool: string) {
  switch (tool) {
    case 'hunt': return Search
    case 'alerts': return Bell
    case 'cases': return Briefcase
    case 'analyzers': return Zap
    case 'detections': return Shield
    case 'playbooks': return FileText
    default: return Activity
  }
}

// Calculate action stats
const actionStats = computed(() => {
  const actions = props.execution.actions
  const successful = actions.filter(a => a.status === 'success').length
  const failed = actions.filter(a => a.status === 'failed').length
  const byTool = new Map<string, number>()

  for (const action of actions) {
    byTool.set(action.tool, (byTool.get(action.tool) || 0) + 1)
  }

  return { successful, failed, byTool: Array.from(byTool.entries()) }
})
</script>

<template>
  <div class="fixed inset-0 z-50 bg-black/50 flex items-center justify-center p-4 overflow-y-auto">
    <div class="bg-card border border-border rounded-xl shadow-xl w-full max-w-4xl max-h-[90vh] overflow-hidden flex flex-col">
      <!-- Header -->
      <div class="flex items-center justify-between px-6 py-4 border-b border-border bg-muted/30">
        <div class="flex items-center gap-3">
          <div :class="cn('p-2 rounded-lg', statusStyle.bg)">
            <component :is="statusStyle.icon" :class="cn('h-5 w-5', statusStyle.text)" />
          </div>
          <div>
            <h2 class="text-lg font-semibold text-foreground">{{ execution.agentName }}</h2>
            <p class="text-sm text-muted-foreground">Execution {{ execution.id }}</p>
          </div>
        </div>
        <button
          @click="emit('close')"
          class="p-2 text-muted-foreground hover:text-foreground hover:bg-muted rounded-lg transition-colors"
        >
          <X class="h-5 w-5" />
        </button>
      </div>

      <!-- Content -->
      <div class="flex-1 overflow-y-auto p-6 space-y-6">
        <!-- Status & Metadata -->
        <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div class="p-4 rounded-lg border border-border bg-card">
            <div class="text-xs text-muted-foreground mb-1">Status</div>
            <div class="flex items-center gap-2">
              <span :class="cn('px-2 py-1 text-sm font-medium rounded', statusStyle.bg, statusStyle.text)">
                {{ statusStyle.label }}
              </span>
            </div>
          </div>

          <div class="p-4 rounded-lg border border-border bg-card">
            <div class="text-xs text-muted-foreground mb-1">Trigger</div>
            <div class="flex items-center gap-2">
              <component :is="triggerStyle.icon" :class="cn('h-4 w-4', triggerStyle.text)" />
              <span class="text-sm font-medium text-foreground">{{ triggerStyle.label }}</span>
            </div>
          </div>

          <div class="p-4 rounded-lg border border-border bg-card">
            <div class="text-xs text-muted-foreground mb-1">Duration</div>
            <div class="flex items-center gap-2">
              <Clock class="h-4 w-4 text-muted-foreground" />
              <span class="text-sm font-medium text-foreground">
                {{ execution.duration ? formatDuration(execution.duration) : 'N/A' }}
              </span>
            </div>
          </div>

          <div class="p-4 rounded-lg border border-border bg-card">
            <div class="text-xs text-muted-foreground mb-1">Tokens Used</div>
            <div class="flex items-center gap-2">
              <Cpu class="h-4 w-4 text-cyan-500" />
              <span class="text-sm font-medium text-foreground">
                {{ execution.tokensUsed ? formatTokens(execution.tokensUsed) : 'N/A' }}
              </span>
            </div>
          </div>
        </div>

        <!-- Time Info -->
        <div class="p-4 rounded-lg border border-border bg-muted/30">
          <div class="grid grid-cols-2 gap-4 text-sm">
            <div>
              <span class="text-muted-foreground">Started:</span>
              <span class="ml-2 text-foreground">{{ formatDate(execution.startTime) }}</span>
              <span class="ml-2 text-muted-foreground">({{ formatRelativeTime(execution.startTime) }})</span>
            </div>
            <div v-if="execution.endTime">
              <span class="text-muted-foreground">Ended:</span>
              <span class="ml-2 text-foreground">{{ formatDate(execution.endTime) }}</span>
            </div>
          </div>
        </div>

        <!-- Trigger Data -->
        <div v-if="execution.triggerEvent || execution.triggerData" class="space-y-2">
          <h3 class="text-sm font-semibold text-foreground">Trigger Details</h3>
          <div class="p-4 rounded-lg border border-border bg-card">
            <div v-if="execution.triggerEvent" class="flex items-center gap-2 mb-2">
              <span class="text-sm text-muted-foreground">Event:</span>
              <code class="px-2 py-0.5 bg-muted rounded text-sm text-foreground">{{ execution.triggerEvent }}</code>
            </div>
            <div v-if="execution.triggerData" class="space-y-1">
              <div v-for="(value, key) in execution.triggerData" :key="key" class="flex items-start gap-2 text-sm">
                <span class="text-muted-foreground min-w-[100px]">{{ key }}:</span>
                <span class="text-foreground">{{ value }}</span>
              </div>
            </div>
          </div>
        </div>

        <!-- Summary / Error -->
        <div v-if="execution.summary || execution.error" class="space-y-2">
          <h3 class="text-sm font-semibold text-foreground">
            {{ execution.error ? 'Error' : 'Summary' }}
          </h3>
          <div
            :class="cn(
              'p-4 rounded-lg border',
              execution.error
                ? 'bg-red-500/5 border-red-500/20'
                : 'bg-green-500/5 border-green-500/20'
            )"
          >
            <div class="flex items-start gap-3">
              <AlertTriangle v-if="execution.error" class="h-5 w-5 text-red-500 flex-shrink-0 mt-0.5" />
              <CheckCircle v-else class="h-5 w-5 text-green-500 flex-shrink-0 mt-0.5" />
              <p :class="cn('text-sm', execution.error ? 'text-red-500' : 'text-foreground')">
                {{ execution.error || execution.summary }}
              </p>
            </div>
          </div>
        </div>

        <!-- Action Stats -->
        <div class="space-y-2">
          <h3 class="text-sm font-semibold text-foreground">Action Summary</h3>
          <div class="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div class="p-3 rounded-lg border border-border bg-card text-center">
              <div class="text-2xl font-bold text-foreground">{{ execution.actions.length }}</div>
              <div class="text-xs text-muted-foreground">Total Actions</div>
            </div>
            <div class="p-3 rounded-lg border border-border bg-card text-center">
              <div class="text-2xl font-bold text-green-500">{{ actionStats.successful }}</div>
              <div class="text-xs text-muted-foreground">Successful</div>
            </div>
            <div class="p-3 rounded-lg border border-border bg-card text-center">
              <div class="text-2xl font-bold text-red-500">{{ actionStats.failed }}</div>
              <div class="text-xs text-muted-foreground">Failed</div>
            </div>
            <div class="p-3 rounded-lg border border-border bg-card">
              <div class="text-xs text-muted-foreground mb-1">Tools Used</div>
              <div class="flex flex-wrap gap-1">
                <span
                  v-for="[tool, count] in actionStats.byTool"
                  :key="tool"
                  class="inline-flex items-center gap-1 px-2 py-0.5 bg-muted rounded text-xs"
                >
                  <component :is="getToolIcon(tool)" class="h-3 w-3" />
                  {{ tool }} ({{ count }})
                </span>
              </div>
            </div>
          </div>
        </div>

        <!-- Action Timeline -->
        <div class="space-y-2">
          <h3 class="text-sm font-semibold text-foreground">Action Timeline</h3>
          <div class="border border-border rounded-lg overflow-hidden">
            <div class="divide-y divide-border">
              <div
                v-for="(action, index) in execution.actions"
                :key="action.id"
                class="p-4 hover:bg-muted/30 transition-colors"
              >
                <div class="flex items-start gap-4">
                  <!-- Step number -->
                  <div
                    :class="cn(
                      'flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold',
                      action.status === 'success'
                        ? 'bg-green-500/10 text-green-500'
                        : 'bg-red-500/10 text-red-500'
                    )"
                  >
                    {{ index + 1 }}
                  </div>

                  <!-- Action details -->
                  <div class="flex-1 min-w-0">
                    <div class="flex items-center gap-2 flex-wrap">
                      <component
                        :is="getToolIcon(action.tool)"
                        class="h-4 w-4 text-muted-foreground"
                      />
                      <code class="px-2 py-0.5 bg-muted rounded text-sm font-medium">
                        {{ action.tool }}.{{ action.action }}
                      </code>
                      <span
                        :class="cn(
                          'px-2 py-0.5 text-xs font-medium rounded',
                          action.status === 'success'
                            ? 'bg-green-500/10 text-green-500'
                            : 'bg-red-500/10 text-red-500'
                        )"
                      >
                        {{ action.status }}
                      </span>
                    </div>

                    <p class="text-sm text-foreground mt-1">{{ action.description }}</p>

                    <!-- Action details/results -->
                    <div v-if="action.details" class="mt-2 p-3 bg-muted/50 rounded-lg">
                      <div class="grid grid-cols-2 md:grid-cols-3 gap-2 text-sm">
                        <div v-for="(value, key) in action.details" :key="key">
                          <span class="text-muted-foreground">{{ key }}:</span>
                          <span
                            :class="cn(
                              'ml-1 font-medium',
                              key === 'malicious' && value === true ? 'text-red-500' :
                              key === 'isBaseline' && value === true ? 'text-green-500' :
                              'text-foreground'
                            )"
                          >
                            {{ value }}
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>

                  <!-- Timestamp -->
                  <div class="flex-shrink-0 text-xs text-muted-foreground">
                    {{ new Date(action.timestamp).toLocaleTimeString() }}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Footer -->
      <div class="flex items-center justify-end gap-3 px-6 py-4 border-t border-border bg-muted/30">
        <button
          @click="emit('close')"
          class="px-4 py-2 text-sm font-medium text-foreground bg-muted hover:bg-muted/80 rounded-lg transition-colors"
        >
          Close
        </button>
      </div>
    </div>
  </div>
</template>
