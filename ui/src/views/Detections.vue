<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import {
  ShieldAlert,
  Search,
  CheckCircle2,
  Circle,
  MoreVertical,
  Eye,
  RefreshCw,
  Plus
} from 'lucide-vue-next'
import { cn } from '../lib/utils'
import { useFormatters } from '../composables/useFormatters'
import { useStatusStyles } from '../composables/useStatusStyles'

const { formatDateForApi } = useFormatters()
const { getSeverityStyles } = useStatusStyles()

interface Detection {
  soc_id: string
  publicId: string
  title: string
  description: string
  severity: string
  engine: string
  author: string
  isEnabled: boolean
  isReporting: boolean
  isCommunity: boolean
  language: string
  ruleset: string
  license: string
  overrideCount: number
  createdAt?: string
  updatedAt?: string
}

const emit = defineEmits(['view-detail'])

const detections = ref<Detection[]>([])
const loading = ref(true)
const error = ref<string | null>(null)
const searchQuery = ref('')
const totalEvents = ref(0)

// Map event fields from the events API response to our Detection interface
// The events API returns: { id, score, type, timestamp, source, payload: { so_detection: {...}, ... } }
const mapEventToDetection = (event: Record<string, any>): Detection => {
  // The payload contains the actual document fields
  const payload = event.payload || event

  return {
    soc_id: event.id || payload['soc_id'] || '',
    publicId: payload['so_detection.publicId'] || '',
    title: payload['so_detection.title'] || '',
    description: payload['so_detection.description'] || '',
    severity: payload['so_detection.severity'] || 'unknown',
    engine: payload['so_detection.engine'] || '',
    author: payload['so_detection.author'] || '',
    isEnabled: payload['so_detection.isEnabled'] ?? false,
    isReporting: payload['so_detection.isReporting'] ?? false,
    isCommunity: payload['so_detection.isCommunity'] ?? false,
    language: payload['so_detection.language'] || '',
    ruleset: payload['so_detection.ruleset'] || '',
    license: payload['so_detection.license'] || '',
    overrideCount: payload['so_detection.overrides']?.length || 0,
    createdAt: payload['so_detection.createTime'] || event.timestamp || payload['@timestamp'],
    updatedAt: payload['so_detection.updateTime'] || event.timestamp || payload['@timestamp']
  }
}

const fetchDetections = async () => {
  loading.value = true
  error.value = null

  try {
    // Use epoch to now for full detection list (like old UI does)
    const now = new Date()
    const epoch = new Date(0)
    const dateRange = `${formatDateForApi(epoch)} - ${formatDateForApi(now)}`

    // Query the so-detection index with so_kind:detection filter
    // Use a high limit to get all detections - the old UI allows up to 5000
    const params = new URLSearchParams({
        query: '_index:"*:so-detection" AND so_kind:detection',
        range: dateRange,
        format: '2006/01/02 3:04:05 PM',
        zone: 'Local',
        metricLimit: '0',
        eventLimit: '10000'
    })

    const response = await fetch(`/api/events?${params.toString()}`)

    if (!response.ok) {
        throw new Error(`Failed to fetch detections: ${response.status}`)
    }

    const data = await response.json()
    totalEvents.value = data.totalEvents || 0

    // Map events to detection objects
    const events = data.events || []
    detections.value = events.map(mapEventToDetection)

  } catch (err: any) {
    console.error('Error fetching detections:', err)
    error.value = err.message
    detections.value = []
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  fetchDetections()
})

const filteredDetections = computed(() => {
  if (!searchQuery.value) return detections.value
  const query = searchQuery.value.toLowerCase()
  return detections.value.filter(d =>
    d.title?.toLowerCase().includes(query) ||
    d.description?.toLowerCase().includes(query) ||
    d.publicId?.toLowerCase().includes(query) ||
    d.engine?.toLowerCase().includes(query) ||
    d.author?.toLowerCase().includes(query)
  )
})

const toggleEnabled = async (detection: Detection) => {
  const previousState = detection.isEnabled
  detection.isEnabled = !detection.isEnabled

  try {
    const response = await fetch(`/api/detection/${detection.soc_id}`)
    if (!response.ok) throw new Error('Failed to fetch detection')

    const fullDetection = await response.json()
    fullDetection.isEnabled = detection.isEnabled

    const updateResponse = await fetch('/api/detection', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(fullDetection)
    })

    if (!updateResponse.ok) {
      throw new Error('Failed to update detection')
    }
  } catch (err) {
    console.error('Error toggling detection:', err)
    detection.isEnabled = previousState
  }
}

const viewDetail = (id: string) => {
  emit('view-detail', id)
}
</script>

<template>
  <div class="space-y-6 animate-in fade-in duration-500">
    <div class="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
      <div>
        <h2 class="text-3xl font-bold tracking-tight text-primary flex items-center gap-2">
          <ShieldAlert class="h-8 w-8" />
          Detections
        </h2>
        <p class="text-muted-foreground">Manage your threat detection rules and tuning.</p>
      </div>
      <div class="flex items-center gap-2">
         <div class="relative w-64">
          <Search class="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <input 
            v-model="searchQuery"
            type="text" 
            placeholder="Search rules..." 
            class="w-full pl-9 pr-4 py-2 bg-card border border-border rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-primary/50 transition-all"
          />
        </div>
        <button 
          @click="fetchDetections"
          class="p-2 hover:bg-muted rounded-md transition-colors text-muted-foreground"
          :class="{ 'animate-spin': loading }"
        >
          <RefreshCw class="h-5 w-5" />
        </button>
        <button class="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 transition-all shadow-lg active:scale-95">
          <Plus class="h-4 w-4" />
          Create Rule
        </button>
      </div>
    </div>

    <!-- Stats Cards -->
    <div class="grid gap-4 md:grid-cols-3">
        <div class="p-6 rounded-xl bg-card border border-border flex items-center justify-between shadow-sm hover:shadow-md transition-shadow group">
            <div>
                <p class="text-sm font-medium text-muted-foreground">Total Rules</p>
                <div class="flex items-end gap-2">
                    <h3 class="text-3xl font-bold">{{ detections.length }}</h3>
                    <span class="text-xs text-muted-foreground mb-1">Active</span>
                </div>
            </div>
            <div class="p-3 bg-primary/10 rounded-lg group-hover:scale-110 transition-transform">
                <ShieldAlert class="h-6 w-6 text-primary" />
            </div>
        </div>
        <div class="p-6 rounded-xl bg-card border border-border flex items-center justify-between shadow-sm hover:shadow-md transition-shadow group">
            <div>
                <p class="text-sm font-medium text-muted-foreground">Enabled</p>
                <div class="flex items-end gap-2">
                    <h3 class="text-3xl font-bold text-green-500">{{ detections.filter(d => d.isEnabled).length }}</h3>
                    <span class="text-xs text-muted-foreground mb-1">Live</span>
                </div>
            </div>
            <div class="p-3 bg-green-500/10 rounded-lg group-hover:scale-110 transition-transform">
                <CheckCircle2 class="h-6 w-6 text-green-500" />
            </div>
        </div>
        <div class="p-6 rounded-xl bg-card border border-border flex items-center justify-between shadow-sm hover:shadow-md transition-shadow group">
            <div>
                <p class="text-sm font-medium text-muted-foreground">Disabled</p>
                <div class="flex items-end gap-2">
                    <h3 class="text-3xl font-bold text-amber-500">{{ detections.filter(d => !d.isEnabled).length }}</h3>
                    <span class="text-xs text-muted-foreground mb-1">Paused</span>
                </div>
            </div>
            <div class="p-3 bg-amber-500/10 rounded-lg group-hover:scale-110 transition-transform">
                <Circle class="h-6 w-6 text-amber-500" />
            </div>
        </div>
    </div>

    <!-- Table Container -->
    <div class="rounded-xl border border-border bg-card overflow-hidden shadow-sm">
      <div class="overflow-x-auto">
        <table class="w-full text-sm">
          <thead>
            <tr class="border-b border-border bg-muted/30">
              <th class="h-12 px-6 text-left align-middle font-semibold text-muted-foreground">Enabled</th>
              <th class="h-12 px-6 text-left align-middle font-semibold text-muted-foreground">Severity</th>
              <th class="h-12 px-6 text-left align-middle font-semibold text-muted-foreground">Rule Title</th>
              <th class="h-12 px-6 text-left align-middle font-semibold text-muted-foreground">Engine</th>
              <th class="h-12 px-6 text-left align-middle font-semibold text-muted-foreground">Author</th>
              <th class="h-12 px-6 text-right align-middle font-semibold text-muted-foreground">Actions</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-border">
            <tr v-if="loading" class="animate-pulse">
                <td colspan="6" class="h-32 text-center text-muted-foreground">Loading detections...</td>
            </tr>
            <tr v-else-if="filteredDetections.length === 0" class="h-32 text-center text-muted-foreground">
                <td colspan="6">No detections match your search.</td>
            </tr>
            <tr 
              v-for="detection in filteredDetections" 
              :key="detection.soc_id"
              class="group transition-colors hover:bg-muted/30 cursor-pointer"
              @click="viewDetail(detection.soc_id)"
            >
              <td class="px-6 py-4 align-middle" @click.stop>
                 <button 
                   @click="toggleEnabled(detection)"
                   :class="cn(
                     'relative inline-flex h-5 w-9 shrink-0 cursor-pointer items-center rounded-full transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2',
                     detection.isEnabled ? 'bg-green-500' : 'bg-muted-foreground/30'
                   )"
                 >
                   <span 
                     :class="cn(
                       'pointer-events-none block h-4 w-4 rounded-full bg-white shadow-lg ring-0 transition-transform',
                       detection.isEnabled ? 'translate-x-4' : 'translate-x-1'
                     )"
                   />
                 </button>
              </td>
              <td class="px-6 py-4 align-middle">
                 <span :class="cn('px-2.5 py-0.5 rounded-full text-xs font-bold border', getSeverityStyles(detection.severity))">
                    {{ detection.severity }}
                 </span>
              </td>
              <td class="px-6 py-4 align-middle">
                <div class="font-semibold text-foreground group-hover:text-primary transition-colors">{{ detection.title }}</div>
                <div class="text-xs text-muted-foreground line-clamp-1 mt-0.5">{{ detection.description }}</div>
              </td>
              <td class="px-6 py-4 align-middle">
                <span class="inline-flex items-center gap-1.5 text-xs font-medium text-muted-foreground bg-muted px-2 py-1 rounded">
                    {{ detection.engine }}
                </span>
              </td>
              <td class="px-6 py-4 align-middle text-muted-foreground italic">{{ detection.author }}</td>
              <td class="px-6 py-4 align-middle text-right" @click.stop>
                <div class="flex items-center justify-end gap-1">
                    <button @click="viewDetail(detection.soc_id)" class="p-2 hover:bg-muted rounded text-muted-foreground hover:text-primary transition-all" title="View Details">
                        <Eye class="h-4 w-4" />
                    </button>
                    <button class="p-2 hover:bg-muted rounded text-muted-foreground hover:text-foreground transition-all">
                        <MoreVertical class="h-4 w-4" />
                    </button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>
