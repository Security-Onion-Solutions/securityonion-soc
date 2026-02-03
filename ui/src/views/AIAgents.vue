<script setup lang="ts">
import { ref, onMounted, watch, computed } from 'vue'
import { useDebounceFn } from '@vueuse/core'
import {
  Cpu,
  Search,
  Plus,
  RefreshCw,
  Play,
  Pause,
  Zap,
  Activity,
  List
} from 'lucide-vue-next'
import { cn } from '../lib/utils'
import { useAgents, type AIAgent, type AgentSearchCriteria } from '../composables/useAgents'
import AgentCard from '../components/agents/AgentCard.vue'
import AgentEditor from '../components/agents/AgentEditor.vue'
import AgentMetrics from '../components/agents/AgentMetrics.vue'

const {
  getAgents,
  createAgent,
  updateAgent,
  deleteAgent,
  toggleAgentStatus,
  stats,
  loading
} = useAgents()

// Tab state
const activeTab = ref<'agents' | 'metrics'>('agents')

// State
const agents = ref<AIAgent[]>([])
const error = ref<string | null>(null)
const searchQuery = ref('')
const statusFilter = ref<'all' | 'active' | 'paused'>('all')
const triggerFilter = ref<'all' | 'manual' | 'scheduled' | 'event-driven'>('all')

// Editor state
const showEditor = ref(false)
const editingAgent = ref<AIAgent | null>(null)

// Fetch agents with current filters
const fetchAgents = async () => {
  error.value = null

  try {
    const criteria: AgentSearchCriteria = {
      search: searchQuery.value || undefined,
      status: statusFilter.value !== 'all' ? statusFilter.value : undefined,
      triggerType: triggerFilter.value !== 'all' ? triggerFilter.value : undefined
    }
    agents.value = await getAgents(criteria)
  } catch (e: any) {
    console.error('[AIAgents] Fetch error:', e)
    error.value = e.message || 'Failed to fetch agents'
  }
}

// Debounced search
const debouncedFetch = useDebounceFn(() => {
  fetchAgents()
}, 300)

// Watch for filter changes
watch([statusFilter, triggerFilter], () => {
  fetchAgents()
})

// Watch for search changes (debounced)
watch(searchQuery, () => {
  debouncedFetch()
})

// Create new agent
const handleCreate = () => {
  editingAgent.value = null
  showEditor.value = true
}

// Edit agent
const handleEdit = (agent: AIAgent) => {
  editingAgent.value = agent
  showEditor.value = true
}

// Save agent (create or update)
const handleSave = async (agentData: Omit<AIAgent, 'id' | 'createTime' | 'updateTime'> & { id?: string }) => {
  try {
    if (agentData.id) {
      // Update existing
      const existing = agents.value.find(a => a.id === agentData.id)
      if (existing) {
        await updateAgent({
          ...existing,
          ...agentData,
          id: agentData.id
        } as AIAgent)
      }
    } else {
      // Create new
      await createAgent(agentData)
    }
    showEditor.value = false
    editingAgent.value = null
    await fetchAgents()
  } catch (e: any) {
    console.error('[AIAgents] Save error:', e)
    error.value = e.message || 'Failed to save agent'
  }
}

// Delete agent
const handleDelete = async (agent: AIAgent) => {
  if (!confirm(`Are you sure you want to delete "${agent.name}"?`)) return

  try {
    await deleteAgent(agent.id)
    await fetchAgents()
  } catch (e: any) {
    console.error('[AIAgents] Delete error:', e)
    error.value = e.message || 'Failed to delete agent'
  }
}

// Toggle agent status
const handleToggleStatus = async (agent: AIAgent) => {
  try {
    await toggleAgentStatus(agent.id)
    await fetchAgents()
  } catch (e: any) {
    console.error('[AIAgents] Toggle status error:', e)
    error.value = e.message || 'Failed to toggle agent status'
  }
}

// Filter counts for badges
const statusCounts = computed(() => ({
  all: stats.value.total,
  active: stats.value.active,
  paused: stats.value.paused
}))

onMounted(() => {
  fetchAgents()
})
</script>

<template>
  <div class="space-y-6 animate-in fade-in duration-500">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h2 class="text-3xl font-bold tracking-tight">AI Agents</h2>
        <p class="text-muted-foreground">Create and manage AI agents for automated security tasks.</p>
      </div>
      <div class="flex items-center gap-4">
        <!-- Tab Switcher -->
        <div class="flex items-center bg-muted rounded-lg p-1">
          <button
            @click="activeTab = 'agents'"
            :class="cn(
              'flex items-center gap-2 px-3 py-1.5 rounded-md text-sm font-medium transition-all',
              activeTab === 'agents'
                ? 'bg-background text-foreground shadow-sm'
                : 'text-muted-foreground hover:text-foreground'
            )"
          >
            <List class="h-4 w-4" />
            Agents
          </button>
          <button
            @click="activeTab = 'metrics'"
            :class="cn(
              'flex items-center gap-2 px-3 py-1.5 rounded-md text-sm font-medium transition-all',
              activeTab === 'metrics'
                ? 'bg-background text-foreground shadow-sm'
                : 'text-muted-foreground hover:text-foreground'
            )"
          >
            <Activity class="h-4 w-4" />
            Metrics
          </button>
        </div>

        <template v-if="activeTab === 'agents'">
          <!-- Status Filter -->
          <div class="flex items-center bg-muted rounded-lg p-1">
            <button
              v-for="status in (['all', 'active', 'paused'] as const)"
              :key="status"
              @click="statusFilter = status"
              :class="cn(
                'px-3 py-1.5 rounded-md text-xs font-medium capitalize transition-all',
                statusFilter === status
                  ? 'bg-background text-foreground shadow-sm'
                  : 'text-muted-foreground hover:text-foreground'
              )"
            >
              {{ status }}
            </button>
          </div>

          <!-- Trigger Filter -->
          <div class="flex items-center bg-muted rounded-lg p-1">
            <button
              v-for="trigger in (['all', 'manual', 'scheduled', 'event-driven'] as const)"
              :key="trigger"
              @click="triggerFilter = trigger"
              :class="cn(
                'px-3 py-1.5 rounded-md text-xs font-medium capitalize transition-all',
                triggerFilter === trigger
                  ? 'bg-background text-foreground shadow-sm'
                  : 'text-muted-foreground hover:text-foreground'
              )"
            >
              {{ trigger === 'event-driven' ? 'Event' : trigger }}
            </button>
          </div>

          <!-- Search -->
          <div class="relative w-64">
            <Search class="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
            <input
              v-model="searchQuery"
              type="search"
              placeholder="Search agents..."
              class="w-full bg-background border border-border rounded-md pl-9 pr-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary/50"
            />
          </div>

          <!-- Refresh -->
          <button
            @click="fetchAgents()"
            :disabled="loading"
            class="p-2 text-muted-foreground hover:text-foreground hover:bg-muted rounded-md transition-colors"
            title="Refresh"
          >
            <RefreshCw :class="cn('h-4 w-4', loading && 'animate-spin')" />
          </button>

          <!-- Create -->
          <button
            @click="handleCreate"
            class="inline-flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 transition-colors font-medium"
          >
            <Plus class="h-4 w-4" />
            Create Agent
          </button>
        </template>
      </div>
    </div>

    <!-- Agents Tab -->
    <template v-if="activeTab === 'agents'">
      <!-- Stats Cards -->
      <div class="grid gap-4 md:grid-cols-4">
        <div class="p-6 rounded-xl border border-border bg-card shadow-sm">
          <div class="flex items-center gap-2 text-sm font-medium text-muted-foreground mb-2">
            <Cpu class="h-4 w-4" />
            Total Agents
          </div>
          <div class="text-2xl font-bold">{{ stats.total }}</div>
        </div>
        <div class="p-6 rounded-xl border border-border bg-card shadow-sm">
          <div class="flex items-center gap-2 text-sm font-medium text-muted-foreground mb-2">
            <Play class="h-4 w-4 text-green-500" />
            Active
          </div>
          <div class="text-2xl font-bold">{{ stats.active }}</div>
        </div>
        <div class="p-6 rounded-xl border border-border bg-card shadow-sm">
          <div class="flex items-center gap-2 text-sm font-medium text-muted-foreground mb-2">
            <Pause class="h-4 w-4 text-amber-500" />
            Paused
          </div>
          <div class="text-2xl font-bold">{{ stats.paused }}</div>
        </div>
        <div class="p-6 rounded-xl border border-border bg-card shadow-sm">
          <div class="flex items-center gap-2 text-sm font-medium text-muted-foreground mb-2">
            <Zap class="h-4 w-4 text-purple-500" />
            Event-Driven
          </div>
          <div class="text-2xl font-bold">
            {{ agents.filter(a => a.triggerType === 'event-driven').length }}
          </div>
        </div>
      </div>

      <!-- Error Message -->
      <div v-if="error" class="p-4 rounded-lg bg-red-500/10 border border-red-500/20 text-red-500">
        {{ error }}
      </div>

      <!-- Loading State -->
      <div v-if="loading" class="space-y-4">
        <div v-for="i in 3" :key="i" class="border border-border rounded-xl bg-card p-4 animate-pulse">
          <div class="flex items-start justify-between gap-4">
            <div class="flex-1">
              <div class="h-5 w-48 bg-muted rounded mb-2"></div>
              <div class="h-4 w-96 bg-muted rounded mb-3"></div>
              <div class="flex gap-4">
                <div class="h-3 w-16 bg-muted rounded"></div>
                <div class="h-3 w-24 bg-muted rounded"></div>
                <div class="h-3 w-20 bg-muted rounded"></div>
              </div>
            </div>
            <div class="flex gap-2">
              <div class="h-8 w-8 bg-muted rounded"></div>
              <div class="h-8 w-8 bg-muted rounded"></div>
              <div class="h-8 w-8 bg-muted rounded"></div>
            </div>
          </div>
        </div>
      </div>

      <!-- Agents List -->
      <div v-else-if="agents.length > 0" class="space-y-4">
        <p class="text-sm text-muted-foreground">
          Showing {{ agents.length }} agent{{ agents.length !== 1 ? 's' : '' }}
        </p>
        <AgentCard
          v-for="agent in agents"
          :key="agent.id"
          :agent="agent"
          @edit="handleEdit(agent)"
          @delete="handleDelete(agent)"
          @toggle-status="handleToggleStatus(agent)"
        />
      </div>

      <!-- Empty State -->
      <div v-else class="text-center py-16">
        <Cpu class="h-12 w-12 text-muted-foreground/50 mx-auto mb-4" />
        <h3 class="text-lg font-medium text-foreground mb-1">No agents found</h3>
        <p class="text-sm text-muted-foreground mb-4">
          {{ searchQuery || statusFilter !== 'all' || triggerFilter !== 'all'
            ? 'Try adjusting your filters or search query.'
            : 'Create an AI agent to automate security tasks.' }}
        </p>
        <button
          v-if="!searchQuery && statusFilter === 'all' && triggerFilter === 'all'"
          @click="handleCreate"
          class="inline-flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 transition-colors font-medium"
        >
          <Plus class="h-4 w-4" />
          Create Agent
        </button>
      </div>
    </template>

    <!-- Metrics Tab -->
    <template v-else-if="activeTab === 'metrics'">
      <AgentMetrics />
    </template>

    <!-- Editor Dialog -->
    <AgentEditor
      v-if="showEditor"
      :agent="editingAgent"
      @save="handleSave"
      @cancel="showEditor = false"
    />
  </div>
</template>
