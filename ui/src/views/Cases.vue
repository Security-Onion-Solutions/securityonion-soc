<script setup lang="ts">
import { ref, onMounted, computed, watch } from 'vue'
import { Briefcase, Search, Plus, Eye, Activity, Clock, AlertTriangle } from 'lucide-vue-next'
import { cn } from '../lib/utils'
import { useUsers } from '../composables/useUsers'
import { useFormatters } from '../composables/useFormatters'
import { useStatusStyles } from '../composables/useStatusStyles'

const { getUserName, fetchUsers } = useUsers()
const { formatDateForApi } = useFormatters()
const { getSeverityStyles, getStatusStyles } = useStatusStyles()

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

const fetchCases = async () => {
  loading.value = true
  const statusFilter = currentStatusFilter.value
  try {
    // Construct search query for cases as per user feedback
    // We restrict to the so-case index to avoid matching non-case events
    let query = '_index:"*:so-case" AND NOT so_case.category:template'
    if (statusFilter === 'open') {
      query += ' AND NOT so_case.status:closed'
    } else if (statusFilter === 'closed') {
      query += ' AND so_case.status:closed'
    } else {
      // For 'all', we still want to make sure it's a case record
      query += ' AND so_case.status:*'
    }

    // Integrate search query if present
    if (searchQuery.value.trim()) {
      query = `(${query}) AND (${searchQuery.value.trim()})`
    }

    const now = new Date()
    // Broaden range to 1 year to ensure older open cases are found
    // Open cases in Security Onion are often kept regardless of their creation date
    const oneYearAgo = new Date(now.getTime() - 365 * 24 * 60 * 60 * 1000)

    const dateRange = `${formatDateForApi(oneYearAgo)} - ${formatDateForApi(now)}`

    const params = new URLSearchParams({
      query: `${query}`,
      range: dateRange,
      format: '2006/01/02 3:04:05 PM',
      zone: 'Local',
      metricLimit: '10',
      eventLimit: '1000'
    })

    const response = await fetch(`/api/events/?${params.toString()}`)
    if (!response.ok) throw new Error('Failed to fetch cases')
    
    const data = await response.json()
    
    if (data && data.events) {
      cases.value = data.events.map((event: any) => {
        const payload = event.payload || {}
        return {
          soc_id: event.id,
          id: payload['id'] || event.id,
          title: payload['so_case.title'] || 'No Title',
          severity: payload['so_case.severity'] || 'unknown',
          status: payload['so_case.status'] || 'open',
          owner: payload['so_case.userId'] || 'System',
          assignee: payload['so_case.assigneeId'] || 'Unassigned',
          createdAt: payload['so_case.createTime'] || event.timestamp || new Date().toISOString(),
          updatedAt: event.timestamp
        }
      })
    }
    
    loading.value = false
  } catch (err: any) {
    console.error('Fetch cases error:', err)
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
  if (!searchQuery.value) return cases.value
  const query = searchQuery.value.toLowerCase()
  return cases.value.filter(c => 
    c.title.toLowerCase().includes(query) || 
    c.id.toLowerCase().includes(query) ||
    c.owner.toLowerCase().includes(query)
  )
})

const emit = defineEmits(['view-detail'])

const viewDetail = (id: string) => {
  emit('view-detail', id)
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

        <div class="relative w-64">
          <Search class="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
          <input
            v-model="searchQuery"
            type="search"
            placeholder="Search cases..."
            class="w-full bg-background border border-border rounded-md pl-9 pr-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary/50"
          />
        </div>
        <button class="inline-flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 transition-colors font-medium">
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
              <th class="px-4 py-3 text-left font-medium text-muted-foreground">ID</th>
              <th class="px-4 py-3 text-left font-medium text-muted-foreground">Title</th>
              <th class="px-4 py-3 text-left font-medium text-muted-foreground">Severity</th>
              <th class="px-4 py-3 text-left font-medium text-muted-foreground">Status</th>
              <th class="px-4 py-3 text-left font-medium text-muted-foreground">Assignee</th>
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
              <td class="px-4 py-4 font-mono text-xs text-muted-foreground">
                {{ item.id }}
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
  </div>
</template>
