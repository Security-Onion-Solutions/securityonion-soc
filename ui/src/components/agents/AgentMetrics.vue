<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import {
  Activity,
  CheckCircle,
  XCircle,
  Zap,
  Clock,
  Bell,
  Briefcase,
  Search,
  Shield,
  ChevronRight,
  AlertTriangle,
  Cpu
} from 'lucide-vue-next'
import { cn } from '../../lib/utils'
import { useFormatters } from '../../composables/useFormatters'
import {
  useAgents,
  type AgentExecution,
  type AgentMetricsSummary
} from '../../composables/useAgents'
import ExecutionDetail from './ExecutionDetail.vue'

const props = defineProps<{
  agentId?: string
}>()

const emit = defineEmits<{
  viewExecution: [execution: AgentExecution]
  close: []
}>()

const { formatRelativeTime } = useFormatters()
const {
  getExecutions,
  getMetricsSummary,
  getExecutionsByDay,
  getActionBreakdown
} = useAgents()

// State
const loading = ref(true)
const metrics = ref<AgentMetricsSummary | null>(null)
const executions = ref<AgentExecution[]>([])
const executionsByDay = ref<{ date: string; completed: number; failed: number }[]>([])
const actionBreakdown = ref<{ tool: string; action: string; count: number }[]>([])
const showExecutionDetail = ref(false)
const selectedExecution = ref<AgentExecution | null>(null)

// Open execution detail
function openExecutionDetail(execution: AgentExecution) {
  selectedExecution.value = execution
  showExecutionDetail.value = true
}

// Close execution detail
function closeExecutionDetail() {
  showExecutionDetail.value = false
  selectedExecution.value = null
}

// Load data
onMounted(async () => {
  loading.value = true
  try {
    const [metricsData, executionsData, dailyData, actionsData] = await Promise.all([
      getMetricsSummary(props.agentId),
      getExecutions(props.agentId, 20),
      getExecutionsByDay(7, props.agentId),
      getActionBreakdown(props.agentId)
    ])
    metrics.value = metricsData
    executions.value = executionsData
    executionsByDay.value = dailyData
    actionBreakdown.value = actionsData
  } finally {
    loading.value = false
  }
})

// Format duration
function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`
  return `${(ms / 60000).toFixed(1)}m`
}

// Format token count
function formatTokens(tokens: number): string {
  if (tokens >= 1000000) return `${(tokens / 1000000).toFixed(1)}M`
  if (tokens >= 1000) return `${(tokens / 1000).toFixed(1)}K`
  return String(tokens)
}

// Get tokens by agent for breakdown
const tokensByAgent = computed(() => {
  const byAgent = new Map<string, { name: string; tokens: number; executions: number }>()

  for (const exec of executions.value) {
    const current = byAgent.get(exec.agentId) || { name: exec.agentName, tokens: 0, executions: 0 }
    current.tokens += exec.tokensUsed || 0
    current.executions += 1
    byAgent.set(exec.agentId, current)
  }

  return Array.from(byAgent.values()).sort((a, b) => b.tokens - a.tokens)
})

const maxAgentTokens = computed(() => {
  return Math.max(...tokensByAgent.value.map(a => a.tokens), 1)
})

// Get status styles
function getStatusStyle(status: string) {
  switch (status) {
    case 'completed':
      return { bg: 'bg-green-500/10', text: 'text-green-500', icon: CheckCircle }
    case 'failed':
      return { bg: 'bg-red-500/10', text: 'text-red-500', icon: XCircle }
    case 'running':
      return { bg: 'bg-blue-500/10', text: 'text-blue-500', icon: Activity }
    default:
      return { bg: 'bg-gray-500/10', text: 'text-gray-500', icon: Clock }
  }
}

// Get tool icon
function getToolIcon(tool: string) {
  switch (tool) {
    case 'hunt': return Search
    case 'alerts': return Bell
    case 'cases': return Briefcase
    case 'analyzers': return Zap
    case 'detections': return Shield
    default: return Activity
  }
}

// Chart max value for scaling
const chartMax = computed(() => {
  const max = Math.max(...executionsByDay.value.map(d => d.completed + d.failed))
  return Math.max(max, 1)
})

// Success rate
const successRate = computed(() => {
  if (!metrics.value || metrics.value.totalExecutions === 0) return 0
  return Math.round((metrics.value.successfulExecutions / metrics.value.totalExecutions) * 100)
})
</script>

<template>
  <div class="space-y-6">
    <!-- Loading State -->
    <div v-if="loading" class="space-y-4">
      <div class="grid gap-4 md:grid-cols-4">
        <div v-for="i in 4" :key="i" class="p-6 rounded-xl border border-border bg-card animate-pulse">
          <div class="h-4 w-24 bg-muted rounded mb-2"></div>
          <div class="h-8 w-16 bg-muted rounded"></div>
        </div>
      </div>
    </div>

    <template v-else-if="metrics">
      <!-- Summary Stats -->
      <div class="grid gap-4 md:grid-cols-5">
        <div class="p-6 rounded-xl border border-border bg-card">
          <div class="flex items-center gap-2 text-sm font-medium text-muted-foreground mb-2">
            <Activity class="h-4 w-4" />
            Total Executions
          </div>
          <div class="text-2xl font-bold">{{ metrics.totalExecutions }}</div>
          <div class="text-xs text-muted-foreground mt-1">
            {{ successRate }}% success rate
          </div>
        </div>

        <div class="p-6 rounded-xl border border-border bg-card">
          <div class="flex items-center gap-2 text-sm font-medium text-muted-foreground mb-2">
            <Bell class="h-4 w-4 text-amber-500" />
            Alerts Acknowledged
          </div>
          <div class="text-2xl font-bold">{{ metrics.alertsAcknowledged }}</div>
          <div class="text-xs text-muted-foreground mt-1">
            Automatic triage
          </div>
        </div>

        <div class="p-6 rounded-xl border border-border bg-card">
          <div class="flex items-center gap-2 text-sm font-medium text-muted-foreground mb-2">
            <Briefcase class="h-4 w-4 text-blue-500" />
            Cases Enriched
          </div>
          <div class="text-2xl font-bold">{{ metrics.casesCreated + metrics.casesUpdated }}</div>
          <div class="text-xs text-muted-foreground mt-1">
            {{ metrics.casesCreated }} created, {{ metrics.casesUpdated }} updated
          </div>
        </div>

        <div class="p-6 rounded-xl border border-border bg-card">
          <div class="flex items-center gap-2 text-sm font-medium text-muted-foreground mb-2">
            <Zap class="h-4 w-4 text-purple-500" />
            Analyzers Run
          </div>
          <div class="text-2xl font-bold">{{ metrics.analyzersRun }}</div>
          <div class="text-xs text-muted-foreground mt-1">
            Avg {{ formatDuration(metrics.averageDuration) }} per execution
          </div>
        </div>

        <div class="p-6 rounded-xl border border-border bg-card">
          <div class="flex items-center gap-2 text-sm font-medium text-muted-foreground mb-2">
            <Cpu class="h-4 w-4 text-cyan-500" />
            Tokens Used
          </div>
          <div class="text-2xl font-bold">{{ formatTokens(metrics.tokensUsed) }}</div>
          <div class="text-xs text-muted-foreground mt-1">
            ~{{ formatTokens(Math.round(metrics.tokensUsed / metrics.totalExecutions)) }} per execution
          </div>
        </div>
      </div>

      <!-- Execution Chart, Token Usage & Action Breakdown -->
      <div class="grid gap-6 md:grid-cols-3">
        <!-- Executions by Day Chart -->
        <div class="p-6 rounded-xl border border-border bg-card">
          <h3 class="text-sm font-semibold text-foreground mb-4">Executions (Last 7 Days)</h3>
          <div class="flex items-end gap-2 h-32">
            <div
              v-for="day in executionsByDay"
              :key="day.date"
              class="flex-1 flex flex-col items-center gap-1"
            >
              <div class="w-full flex flex-col-reverse gap-0.5" style="height: 100px;">
                <div
                  v-if="day.completed > 0"
                  class="w-full bg-green-500 rounded-t transition-all"
                  :style="{ height: `${(day.completed / chartMax) * 100}%` }"
                  :title="`${day.completed} completed`"
                ></div>
                <div
                  v-if="day.failed > 0"
                  class="w-full bg-red-500 rounded-t transition-all"
                  :style="{ height: `${(day.failed / chartMax) * 100}%` }"
                  :title="`${day.failed} failed`"
                ></div>
              </div>
              <span class="text-[10px] text-muted-foreground">
                {{ new Date(day.date).toLocaleDateString('en-US', { weekday: 'short' }) }}
              </span>
            </div>
          </div>
          <div class="flex items-center justify-center gap-4 mt-4 text-xs">
            <div class="flex items-center gap-1">
              <div class="w-3 h-3 bg-green-500 rounded"></div>
              <span class="text-muted-foreground">Completed</span>
            </div>
            <div class="flex items-center gap-1">
              <div class="w-3 h-3 bg-red-500 rounded"></div>
              <span class="text-muted-foreground">Failed</span>
            </div>
          </div>
        </div>

        <!-- Token Usage by Agent -->
        <div class="p-6 rounded-xl border border-border bg-card">
          <h3 class="text-sm font-semibold text-foreground mb-4">Token Usage by Agent</h3>
          <div class="space-y-3">
            <div
              v-for="agent in tokensByAgent"
              :key="agent.name"
              class="flex items-center gap-3"
            >
              <Cpu class="h-4 w-4 text-cyan-500 flex-shrink-0" />
              <div class="flex-1 min-w-0">
                <div class="flex items-center justify-between">
                  <span class="text-sm text-foreground truncate">
                    {{ agent.name }}
                  </span>
                  <span class="text-sm font-medium text-foreground ml-2">
                    {{ formatTokens(agent.tokens) }}
                  </span>
                </div>
                <div class="w-full bg-muted rounded-full h-1.5 mt-1">
                  <div
                    class="bg-cyan-500 rounded-full h-1.5 transition-all"
                    :style="{ width: `${(agent.tokens / maxAgentTokens) * 100}%` }"
                  ></div>
                </div>
                <div class="text-xs text-muted-foreground mt-0.5">
                  {{ agent.executions }} execution{{ agent.executions !== 1 ? 's' : '' }} · avg {{ formatTokens(Math.round(agent.tokens / agent.executions)) }}/exec
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- Action Breakdown -->
        <div class="p-6 rounded-xl border border-border bg-card">
          <h3 class="text-sm font-semibold text-foreground mb-4">Top Actions</h3>
          <div class="space-y-3">
            <div
              v-for="action in actionBreakdown.slice(0, 5)"
              :key="`${action.tool}:${action.action}`"
              class="flex items-center gap-3"
            >
              <component
                :is="getToolIcon(action.tool)"
                class="h-4 w-4 text-muted-foreground flex-shrink-0"
              />
              <div class="flex-1 min-w-0">
                <div class="flex items-center justify-between">
                  <span class="text-sm text-foreground truncate">
                    {{ action.tool }}.{{ action.action }}
                  </span>
                  <span class="text-sm font-medium text-foreground ml-2">
                    {{ action.count }}
                  </span>
                </div>
                <div class="w-full bg-muted rounded-full h-1.5 mt-1">
                  <div
                    class="bg-primary rounded-full h-1.5 transition-all"
                    :style="{ width: `${(action.count / actionBreakdown[0].count) * 100}%` }"
                  ></div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Recent Executions -->
      <div class="rounded-xl border border-border bg-card overflow-hidden">
        <div class="px-6 py-4 border-b border-border">
          <h3 class="text-sm font-semibold text-foreground">Recent Executions</h3>
        </div>
        <div class="divide-y divide-border">
          <div
            v-for="execution in executions"
            :key="execution.id"
            class="px-6 py-4 hover:bg-muted/50 transition-colors cursor-pointer"
            @click="openExecutionDetail(execution)"
          >
            <div class="flex items-start justify-between gap-4">
              <div class="flex items-start gap-3 flex-1 min-w-0">
                <div
                  :class="cn(
                    'flex-shrink-0 p-2 rounded-lg',
                    getStatusStyle(execution.status).bg
                  )"
                >
                  <component
                    :is="getStatusStyle(execution.status).icon"
                    :class="cn('h-4 w-4', getStatusStyle(execution.status).text)"
                  />
                </div>
                <div class="flex-1 min-w-0">
                  <div class="flex items-center gap-2 flex-wrap">
                    <span class="font-medium text-foreground">{{ execution.agentName }}</span>
                    <span
                      :class="cn(
                        'px-2 py-0.5 text-xs font-medium rounded capitalize',
                        execution.trigger === 'event' ? 'bg-purple-500/10 text-purple-500' :
                        execution.trigger === 'scheduled' ? 'bg-blue-500/10 text-blue-500' :
                        'bg-gray-500/10 text-gray-400'
                      )"
                    >
                      {{ execution.trigger }}
                    </span>
                    <span
                      v-if="execution.triggerEvent"
                      class="text-xs text-muted-foreground"
                    >
                      {{ execution.triggerEvent }}
                    </span>
                  </div>
                  <p v-if="execution.summary" class="text-sm text-muted-foreground mt-1 line-clamp-1">
                    {{ execution.summary }}
                  </p>
                  <p v-else-if="execution.error" class="text-sm text-red-500 mt-1 line-clamp-1">
                    {{ execution.error }}
                  </p>
                </div>
              </div>
              <div class="flex items-center gap-4 text-sm text-muted-foreground flex-shrink-0">
                <span>{{ execution.actions.length }} actions</span>
                <span v-if="execution.tokensUsed" class="flex items-center gap-1">
                  <Cpu class="h-3 w-3" />
                  {{ formatTokens(execution.tokensUsed) }}
                </span>
                <span v-if="execution.duration">{{ formatDuration(execution.duration) }}</span>
                <span>{{ formatRelativeTime(execution.startTime) }}</span>
                <ChevronRight class="h-4 w-4" />
              </div>
            </div>
          </div>

          <div v-if="executions.length === 0" class="px-6 py-12 text-center">
            <Cpu class="h-8 w-8 text-muted-foreground/50 mx-auto mb-2" />
            <p class="text-sm text-muted-foreground">No executions yet</p>
          </div>
        </div>
      </div>

      <!-- Execution Detail Dialog -->
      <ExecutionDetail
        v-if="showExecutionDetail && selectedExecution"
        :execution="selectedExecution"
        @close="closeExecutionDetail"
      />

    </template>
  </div>
</template>
