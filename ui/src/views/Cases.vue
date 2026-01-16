<script setup lang="ts">
import { ref, onMounted, computed, watch } from 'vue'
import { useRouter } from 'vue-router'
import { Briefcase, Search, Plus, Eye, Activity, Clock, AlertTriangle, ChevronUp, ChevronDown, Filter } from 'lucide-vue-next'
import { cn } from '../lib/utils'
import { useUsers } from '../composables/useUsers'
import { useFormatters } from '../composables/useFormatters'
import { useStatusStyles } from '../composables/useStatusStyles'
import { useTimeRange } from '../composables/useTimeRange'
import CreateCaseDialog from '../components/cases/CreateCaseDialog.vue'
import DateTimePicker from '../components/common/DateTimePicker.vue'

const router = useRouter()

const { getUserName, fetchUsers } = useUsers()
const { formatDateForApi, formatDate } = useFormatters()
const { getSeverityStyles, getStatusStyles } = useStatusStyles()

// Cases uses its own independent time range scope (doesn't affect Hunt/Alerts)
const { formattedRange, setRelativeTime, RELATIVE_TIME_UNITS, zone } = useTimeRange({ scope: 'cases' })

// Initialize with 1 year time range to match classic interface exactly
// 60 = RELATIVE_TIME_MONTHS from hunt.ts
setRelativeTime(12, 60)

const showCreateDialog = ref(false)

function handleCaseCreated(caseId: string) {
  showCreateDialog.value = false
  router.push({ name: 'case-detail', params: { id: caseId } })
}

interface Case {
  soc_id: string
  id: string
  title: string
  severity: string
  status: string
  owner: string
  assignee: string
  createdAt: string
  updatedAt: string
}

const cases = ref<Case[]>([])
const loading = ref(true)
const error = ref<string | null>(null)
const searchQuery = ref('')
const currentStatusFilter = ref('open')
const currentSeverityFilter = ref('all')

// Sorting state
type SortField = 'createdAt' | 'title' | 'severity' | 'status' | 'assignee'
type SortDirection = 'asc' | 'desc'
const sortField = ref<SortField>('createdAt')
const sortDirection = ref<SortDirection>('desc')

const severityOptions = ['all', 'critical', 'high', 'medium', 'low']

function toggleSort(field: SortField) {
  if (sortField.value === field) {
    sortDirection.value = sortDirection.value === 'asc' ? 'desc' : 'asc'
  } else {
    sortField.value = field
    sortDirection.value = field === 'createdAt' ? 'desc' : 'asc'
  }
}

function getSortIcon(field: SortField) {
  if (sortField.value !== field) return null
  return sortDirection.value === 'asc' ? ChevronUp : ChevronDown
}

const fetchCases = async () => {
  loading.value = true
  const statusFilter = currentStatusFilter.value
  try {
    // Construct search query for cases - use the exact same query as classic
    let query: string
    if (statusFilter === 'open') {
      query = '(NOT so_case.status:closed AND NOT so_case.category:template) AND _index:"*:so-case" AND so_kind:case'
    } else if (statusFilter === 'closed') {
      query = '(so_case.status:closed AND NOT so_case.category:template) AND _index:"*:so-case" AND so_kind:case'
    } else {
      // 'all' - show both open and closed, just exclude templates
      query = 'NOT so_case.category:template AND _index:"*:so-case" AND so_kind:case'
    }

    // Integrate search query if present
    if (searchQuery.value.trim()) {
      query = `(${query}) AND (${searchQuery.value.trim()})`
    }

    // Sort by createTime descending to show newest cases first
    const sortedQuery = `${query} | sortby so_case.createTime^`

    const params = new URLSearchParams({
      query: sortedQuery,
      range: formattedRange.value,
      format: '2006/01/02 3:04:05 PM',
      zone: zone.value,
      metricLimit: '100',
      eventLimit: '500'
    })

    const response = await fetch(`/api/events/?${params.toString()}`)
    if (!response.ok) throw new Error('Failed to fetch cases')

    const data = await response.json()

    if (data && data.events) {
      cases.value = data.events.map((event: any) => {
        const payload = event.payload || {}
        // Case fields are stored with so_case. prefix (e.g., so_case.title)
        // But also check for nested so_case object for backwards compatibility
        const nestedCase = payload['so_case'] || {}
        return {
          soc_id: event.id,
          id: payload['so_case.id'] || nestedCase.id || event.id,
          title: payload['so_case.title'] || nestedCase.title || 'No Title',
          severity: payload['so_case.severity'] || nestedCase.severity || 'unknown',
          status: payload['so_case.status'] || nestedCase.status || 'open',
          owner: payload['so_case.userId'] || nestedCase.userId || 'System',
          assignee: payload['so_case.assigneeId'] || nestedCase.assigneeId || 'Unassigned',
          createdAt: payload['so_case.createTime'] || nestedCase.createTime || event.timestamp || new Date().toISOString(),
          updatedAt: event.timestamp
        }
      })
    }

    loading.value = false
  } catch (err: any) {
    console.error('[Cases] Fetch error:', err)
    error.value = err.message || 'Failed to fetch cases'
    loading.value = false
  }
}

let debounceTimer: any = null
watch(searchQuery, () => {
  if (debounceTimer) clearTimeout(debounceTimer)
  debounceTimer = setTimeout(() => {
    fetchCases()
  }, 300)
})

watch(currentStatusFilter, () => {
  fetchCases()
})

onMounted(() => {
  fetchCases()
  fetchUsers()
})

const filteredCases = computed(() => {
  let result = cases.value

  // Apply severity filter
  if (currentSeverityFilter.value !== 'all') {
    result = result.filter(c => c.severity.toLowerCase() === currentSeverityFilter.value)
  }

  // Apply search filter
  if (searchQuery.value) {
    const query = searchQuery.value.toLowerCase()
    result = result.filter(c =>
      c.title.toLowerCase().includes(query) ||
      c.id.toLowerCase().includes(query) ||
      c.owner.toLowerCase().includes(query)
    )
  }

  // Apply sorting
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 }

  result = [...result].sort((a, b) => {
    let comparison = 0

    switch (sortField.value) {
      case 'createdAt':
        comparison = new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime()
        break
      case 'title':
        comparison = a.title.localeCompare(b.title)
        break
      case 'severity':
        comparison = (severityOrder[a.severity.toLowerCase() as keyof typeof severityOrder] ?? 4) -
                     (severityOrder[b.severity.toLowerCase() as keyof typeof severityOrder] ?? 4)
        break
      case 'status':
        comparison = a.status.localeCompare(b.status)
        break
      case 'assignee':
        comparison = (a.assignee || '').localeCompare(b.assignee || '')
        break
    }

    return sortDirection.value === 'asc' ? comparison : -comparison
  })

  return result
})

const viewDetail = (id: string) => {
  router.push({ name: 'case-detail', params: { id } })
}
</script>

<template>
  <div class="space-y-6 animate-in fade-in duration-500">
    <div class="flex items-center justify-between">
      <div>
        <h2 class="text-3xl font-bold tracking-tight">Cases</h2>
        <p class="text-muted-foreground">Manage and investigate security incidents.</p>
      </div>
      <div class="flex items-center gap-4">
        <!-- Status Filter -->
        <div class="flex items-center bg-muted rounded-lg p-1">
          <button
            v-for="status in ['open', 'closed', 'all']"
            :key="status"
            @click="currentStatusFilter = status"
            :class="cn(
              'px-3 py-1.5 rounded-md text-xs font-medium capitalize transition-all',
              currentStatusFilter === status
                ? 'bg-background text-foreground shadow-sm'
                : 'text-muted-foreground hover:text-foreground'
            )"
          >
            {{ status }}
          </button>
        </div>

        <!-- Severity Filter -->
        <div class="relative">
          <Filter class="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground pointer-events-none" />
          <select
            v-model="currentSeverityFilter"
            class="appearance-none bg-background border border-border rounded-md pl-9 pr-8 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary/50 cursor-pointer"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>

        <!-- Time Range -->
        <DateTimePicker scope="cases" @change="fetchCases" />

        <div class="relative w-64">
          <Search class="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
          <input
            v-model="searchQuery"
            type="search"
            placeholder="Search cases..."
            class="w-full bg-background border border-border rounded-md pl-9 pr-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary/50"
          />
        </div>
        <button
          @click="showCreateDialog = true"
          class="inline-flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 transition-colors font-medium"
        >
          <Plus class="h-4 w-4" />
          Create Case
        </button>
      </div>
    </div>

    <!-- Stats Cards -->
    <div class="grid gap-4 md:grid-cols-4">
      <div class="p-6 rounded-xl border border-border bg-card shadow-sm">
        <div class="flex items-center gap-2 text-sm font-medium text-muted-foreground mb-2">
          <Briefcase class="h-4 w-4" />
          Total Cases
        </div>
        <div class="text-2xl font-bold">{{ cases.length }}</div>
      </div>
      <div class="p-6 rounded-xl border border-border bg-card shadow-sm">
        <div class="flex items-center gap-2 text-sm font-medium text-muted-foreground mb-2">
          <Activity class="h-4 w-4 text-green-500" />
          Open Cases
        </div>
        <div class="text-2xl font-bold">{{ cases.filter(c => c.status === 'open').length }}</div>
      </div>
      <div class="p-6 rounded-xl border border-border bg-card shadow-sm">
        <div class="flex items-center gap-2 text-sm font-medium text-muted-foreground mb-2">
          <AlertTriangle class="h-4 w-4 text-red-500" />
          High Severity
        </div>
        <div class="text-2xl font-bold">{{ cases.filter(c => c.severity === 'high').length }}</div>
      </div>
      <div class="p-6 rounded-xl border border-border bg-card shadow-sm">
        <div class="flex items-center gap-2 text-sm font-medium text-muted-foreground mb-2">
          <Clock class="h-4 w-4 text-blue-500" />
          Recently Updated
        </div>
        <div class="text-2xl font-bold">2</div>
      </div>
    </div>

    <!-- Cases Table -->
    <div class="rounded-xl border border-border bg-card overflow-hidden shadow-sm">
      <div class="overflow-x-auto">
        <table class="w-full text-sm">
          <thead>
            <tr class="bg-muted/50 border-b border-border">
              <th
                @click="toggleSort('createdAt')"
                class="px-4 py-3 text-left font-medium text-muted-foreground cursor-pointer hover:text-foreground transition-colors select-none"
              >
                <div class="flex items-center gap-1">
                  Created
                  <component :is="getSortIcon('createdAt')" v-if="getSortIcon('createdAt')" class="h-4 w-4" />
                </div>
              </th>
              <th
                @click="toggleSort('title')"
                class="px-4 py-3 text-left font-medium text-muted-foreground cursor-pointer hover:text-foreground transition-colors select-none"
              >
                <div class="flex items-center gap-1">
                  Title
                  <component :is="getSortIcon('title')" v-if="getSortIcon('title')" class="h-4 w-4" />
                </div>
              </th>
              <th
                @click="toggleSort('severity')"
                class="px-4 py-3 text-left font-medium text-muted-foreground cursor-pointer hover:text-foreground transition-colors select-none"
              >
                <div class="flex items-center gap-1">
                  Severity
                  <component :is="getSortIcon('severity')" v-if="getSortIcon('severity')" class="h-4 w-4" />
                </div>
              </th>
              <th
                @click="toggleSort('status')"
                class="px-4 py-3 text-left font-medium text-muted-foreground cursor-pointer hover:text-foreground transition-colors select-none"
              >
                <div class="flex items-center gap-1">
                  Status
                  <component :is="getSortIcon('status')" v-if="getSortIcon('status')" class="h-4 w-4" />
                </div>
              </th>
              <th
                @click="toggleSort('assignee')"
                class="px-4 py-3 text-left font-medium text-muted-foreground cursor-pointer hover:text-foreground transition-colors select-none"
              >
                <div class="flex items-center gap-1">
                  Assignee
                  <component :is="getSortIcon('assignee')" v-if="getSortIcon('assignee')" class="h-4 w-4" />
                </div>
              </th>
              <th class="px-4 py-3 text-left font-medium text-muted-foreground text-right">Actions</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-border">
            <tr v-if="loading" v-for="i in 3" :key="i" class="animate-pulse">
              <td class="px-4 py-4"><div class="h-4 w-16 bg-muted rounded"></div></td>
              <td class="px-4 py-4"><div class="h-4 w-64 bg-muted rounded"></div></td>
              <td class="px-4 py-4"><div class="h-6 w-16 bg-muted rounded-full"></div></td>
              <td class="px-4 py-4"><div class="h-6 w-16 bg-muted rounded-full"></div></td>
              <td class="px-4 py-4"><div class="h-4 w-32 bg-muted rounded"></div></td>
              <td class="px-4 py-4 text-right"><div class="h-8 w-8 bg-muted rounded ml-auto"></div></td>
            </tr>
            <tr v-else-if="filteredCases.length === 0">
              <td colspan="6" class="px-4 py-8 text-center text-muted-foreground">
                No cases found matching your search.
              </td>
            </tr>
            <tr 
              v-for="item in filteredCases" 
              :key="item.soc_id"
              class="hover:bg-muted/30 transition-colors group cursor-pointer"
              @click="viewDetail(item.soc_id)"
            >
              <td class="px-4 py-4 text-xs text-muted-foreground">
                {{ formatDate(item.createdAt) }}
              </td>
              <td class="px-4 py-4">
                <div class="font-medium text-foreground line-clamp-1 group-hover:text-primary transition-colors">
                  {{ item.title }}
                </div>
              </td>
              <td class="px-4 py-4 text-xs font-semibold">
                <span :class="cn('px-2 py-0.5 rounded-full border', getSeverityStyles(item.severity))">
                  {{ item.severity }}
                </span>
              </td>
              <td class="px-4 py-4 text-xs font-semibold uppercase">
                <span :class="cn('px-2 py-0.5 rounded-full border', getStatusStyles(item.status))">
                  {{ item.status }}
                </span>
              </td>
              <td class="px-4 py-4">
                <div class="flex items-center gap-2">
                  <div class="h-6 w-6 rounded-full bg-muted flex items-center justify-center text-[10px] font-bold">
                    {{ item.assignee ? item.assignee.charAt(0).toUpperCase() : '?' }}
                  </div>
                  <span class="text-muted-foreground">{{ getUserName(item.assignee) || 'Unassigned' }}</span>
                </div>
              </td>
              <td class="px-4 py-4 text-right">
                <button 
                  class="p-2 hover:bg-card border border-transparent hover:border-border rounded-md transition-all text-muted-foreground hover:text-foreground"
                  @click.stop="viewDetail(item.soc_id)"
                >
                  <Eye class="h-4 w-4" />
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Create Case Dialog -->
    <CreateCaseDialog
      :open="showCreateDialog"
      @close="showCreateDialog = false"
      @created="handleCaseCreated"
    />
  </div>
</template>
