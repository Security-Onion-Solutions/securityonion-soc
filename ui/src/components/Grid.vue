<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import {
  CheckCircle,
  AlertTriangle,
  AlertCircle,
  Info,
  Server,
  Activity,
  Cpu,
  HardDrive,
  Network,
  ChevronDown,
  ChevronRight,
  ChevronUp,
  PlayCircle,
  Upload,
  RotateCcw,
  BarChart2,
  ArrowUpDown,
  Search
} from 'lucide-vue-next'
import { cn } from '../lib/utils'
import { useFormatters } from '../composables/useFormatters'
import { useStatusStyles } from '../composables/useStatusStyles'
import { useTableSort } from '../composables/useTableSort'
import { useAuth } from '../composables/useAuth'

const { formatDate, formatUptime, formatRelativeTime } = useFormatters()
const { getNodeStatusColor, getUsageColor, getProgressColor } = useStatusStyles()
const { isUserAdmin } = useAuth()

interface GridNode {
  id: string
  gridId: string
  role: string
  address: string
  version: string
  model: string
  consumptionEps: number
  memoryUsedPct: number
  memoryTotalGB?: number
  swapUsedPct?: number
  swapTotalGB?: number
  diskUsedRootPct: number
  diskTotalRootGB?: number
  diskUsedNsmPct?: number
  diskTotalNsmGB?: number
  cpuUsedPct: number
  ioWaitPct?: number
  trafficManInMbs?: number
  trafficManOutMbs?: number
  uptimeSeconds: number
  osUptimeSeconds?: number
  trafficMonInMbs?: number
  osNeedsRestart?: number
  highstateAgeSeconds?: number
  status: string
  containers?: any[]
  updateTime?: string
  onlineTime?: string
  epochTime?: string
  processStatus?: string
  connectionStatus?: string
  eventstoreStatus?: string
  raidStatus?: string
  load1m?: number
  load5m?: number
  load15m?: number
  description?: string
  keywords?: string
  metricsEnabled?: boolean
  processJson?: string
  statusCode?: number
}

const nodes = ref<GridNode[]>([])
const loading = ref(true)
const error = ref<string | null>(null)
const expandedNodeId = ref<string | null>(null)
const showMetrics = ref<Record<string, boolean>>({})
const metricsData = ref<Record<string, any>>({})
const loadingMetrics = ref<Record<string, boolean>>({})
const selectedDuration = ref<Record<string, string>>({}) // Duration per node, e.g., "1h"

// Table sorting and filtering
const {
    sortState,
    searchQuery,
    toggleSort,
    getSortDirection
} = useTableSort(nodes, { column: 'id', direction: 'asc' })

// Sortable columns configuration
const sortableColumns = [
    { key: 'id', label: 'Node' },
    { key: 'role', label: 'Role' },
    { key: 'address', label: 'Address' },
    { key: 'osUptimeSeconds', label: 'OS Uptime' },
    { key: 'version', label: 'Version' }
] as const

// Filtered and sorted nodes
const filteredNodes = computed(() => {
    let result = nodes.value

    // Filter by search query (searches in id/name)
    if (searchQuery.value.trim()) {
        const query = searchQuery.value.toLowerCase().trim()
        result = result.filter(node =>
            node.id.toLowerCase().includes(query) ||
            (node.description && node.description.toLowerCase().includes(query))
        )
    }

    // Sort by current column
    if (sortState.value.column && sortState.value.direction) {
        const col = sortState.value.column as keyof GridNode
        const dir = sortState.value.direction
        result = [...result].sort((a, b) => {
            const aVal = a[col]
            const bVal = b[col]
            if (aVal === bVal) return 0
            if (aVal === null || aVal === undefined) return 1
            if (bVal === null || bVal === undefined) return -1

            let comparison = 0
            if (typeof aVal === 'string' && typeof bVal === 'string') {
                comparison = aVal.localeCompare(bVal, undefined, { numeric: true, sensitivity: 'base' })
            } else if (typeof aVal === 'number' && typeof bVal === 'number') {
                comparison = aVal - bVal
            } else {
                comparison = String(aVal).localeCompare(String(bVal))
            }
            return dir === 'desc' ? -comparison : comparison
        })
    }

    return result
})

const toggleNode = (nodeId: string) => {
  if (expandedNodeId.value === nodeId) {
    expandedNodeId.value = null
  } else {
    expandedNodeId.value = nodeId
  }
}

const toggleMetrics = async (nodeId: string) => {
    showMetrics.value[nodeId] = !showMetrics.value[nodeId]
    
    // Set default duration if not set
    if (!selectedDuration.value[nodeId]) {
        selectedDuration.value[nodeId] = "1h"
    }

    if (showMetrics.value[nodeId] && !metricsData.value[nodeId]) {
        await fetchHistoricalMetrics(nodeId)
    }
}

const fetchHistoricalMetrics = async (nodeId: string) => {
    loadingMetrics.value[nodeId] = true
    try {
        const duration = selectedDuration.value[nodeId] || "1h"
        const response = await fetch(`/api/grid/${nodeId}/metrics?range=${duration}`)
        if (response.ok) {
            metricsData.value[nodeId] = await response.json()
        }
    } catch (e) {
        console.error('Failed to fetch metrics for node', nodeId, e)
    } finally {
        loadingMetrics.value[nodeId] = false
    }
}

const generatePath = (points: any[] | undefined, width: number, height: number, maxVal: number = 100) => {
    if (!points || points.length < 2) return ""
    
    // Auto-scale maxVal if needed (for traffic)
    if (maxVal === 0) {
        maxVal = Math.max(...points.map(p => p.v), 1)
    }
    
    const xStep = width / (points.length - 1)
    return points.map((p, i) => {
        const x = i * xStep
        const y = height - (p.v / maxVal) * height
        return `${i === 0 ? 'M' : 'L'} ${x} ${y}`
    }).join(" ")
}

const fetchGridData = async () => {
  loading.value = true
  try {
    const response = await fetch('/api/grid')
    if (!response.ok) {
        throw new Error(`Failed to fetch grid data: ${response.status} ${response.statusText}`)
    }
    const data = await response.json()
    nodes.value = data.map((n: any) => {
        const node = {
            ...n,
            // Ensure some defaults if missing from API but expected by UI
            memoryTotalGB: n.memoryTotalGB || 16,
            swapTotalGB: n.swapTotalGB || 0,
            diskTotalRootGB: n.diskTotalRootGB || 500,
            diskTotalNsmGB: n.diskTotalNsmGB || 500,
            osUptimeSeconds: n.osUptimeSeconds || n.uptimeSeconds,
            metricsEnabled: n.metricsEnabled !== undefined ? n.metricsEnabled : true
        }
        
        // Parse processJson for container details
        if (node.processJson) {
            try {
                const details = JSON.parse(node.processJson)
                if (details) {
                    node.statusCode = details.status_code
                    if (details.containers) {
                        node.containers = details.containers.sort((a: any, b: any) => {
                            return a.Name > b.Name ? 1 : -1
                        })
                    }
                }
            } catch (e) {
                console.error('Failed to parse processJson for node', node.id, e)
            }
        }
        
        return node
    })
    error.value = null
  } catch (err: any) {
    console.error('Error fetching grid data:', err)
    error.value = err.message
    
    if (nodes.value.length === 0) {
        nodes.value = [
            {
                id: 'sensor-01',
                gridId: 'default',
                role: 'so-sensor',
                address: '192.168.1.101',
                version: '2.4.70',
                model: 'Virtual',
                consumptionEps: 1250,
                memoryUsedPct: 45,
                memoryTotalGB: 16,
                swapUsedPct: 5,
                swapTotalGB: 2,
                diskUsedRootPct: 12,
                diskTotalRootGB: 500,
                diskUsedNsmPct: 30,
                diskTotalNsmGB: 1000,
                cpuUsedPct: 23,
                ioWaitPct: 0.1,
                trafficManInMbs: 15.5,
                trafficManOutMbs: 12.2,
                trafficMonInMbs: 856.42,
                uptimeSeconds: 123456,
                osUptimeSeconds: 123456,
                highstateAgeSeconds: 3600,
                status: 'ok',
                updateTime: new Date().toISOString(),
                onlineTime: new Date(Date.now() - 86400000).toISOString(),
                processStatus: 'ok',
                connectionStatus: 'ok',
                load1m: 0.5,
                load5m: 0.4,
                load15m: 0.3,
                description: 'Primary network sensor',
                keywords: 'Sensor, Zeek, Suricata',
                metricsEnabled: true,
                containers: [
                    { Name: 'so-zeek', Status: 'running', Details: 'up 2 days' },
                    { Name: 'so-suricata', Status: 'running', Details: 'up 2 days' },
                    { Name: 'so-steno', Status: 'running', Details: 'up 2 days' }
                ]
            },
             {
                id: 'manager-01',
                gridId: 'default',
                role: 'so-manager',
                address: '192.168.1.100',
                version: '2.4.70',
                model: 'Virtual',
                consumptionEps: 0,
                memoryUsedPct: 65,
                memoryTotalGB: 32,
                swapUsedPct: 10,
                swapTotalGB: 4,
                diskUsedRootPct: 45,
                diskTotalRootGB: 1000,
                diskUsedNsmPct: 15,
                diskTotalNsmGB: 2000,
                cpuUsedPct: 12,
                ioWaitPct: 0.5,
                trafficManInMbs: 5.5,
                trafficManOutMbs: 8.2,
                uptimeSeconds: 123456,
                osUptimeSeconds: 123456,
                osNeedsRestart: 1,
                highstateAgeSeconds: 800,
                status: 'ok',
                updateTime: new Date().toISOString(),
                onlineTime: new Date(Date.now() - 86400000).toISOString(),
                processStatus: 'ok',
                connectionStatus: 'ok',
                description: 'Central management node',
                keywords: 'Manager, Kratos, Salt',
                metricsEnabled: true,
                containers: [
                    { Name: 'so-kratos', Status: 'running', Details: 'up 5 days' },
                    { Name: 'so-salt-master', Status: 'running', Details: 'up 5 days' },
                    { Name: 'so-nginx', Status: 'running', Details: 'up 5 days' }
                ]
            },
            {
                id: 'node-fault-02',
                gridId: 'local',
                role: 'so-standalone',
                address: '192.168.1.102',
                version: '2.4.70',
                model: 'Physical',
                consumptionEps: 50,
                memoryUsedPct: 92,
                memoryTotalGB: 8,
                swapUsedPct: 85,
                swapTotalGB: 1,
                diskUsedRootPct: 95,
                diskTotalRootGB: 200,
                diskUsedNsmPct: 90,
                diskTotalNsmGB: 500,
                cpuUsedPct: 88,
                ioWaitPct: 12.5,
                trafficManInMbs: 150.5,
                trafficManOutMbs: 180.2,
                trafficMonInMbs: 423.18,
                uptimeSeconds: 5000,
                osUptimeSeconds: 10000,
                highstateAgeSeconds: 86400 * 5,
                status: 'fault',
                updateTime: new Date().toISOString(),
                onlineTime: new Date(Date.now() - 3600000).toISOString(),
                processStatus: 'fault',
                connectionStatus: 'ok',
                raidStatus: 'unknown',
                description: 'Remote standalone node',
                keywords: 'Standalone, Sensor, Manager',
                metricsEnabled: true,
                containers: [
                    { Name: 'so-elasticsearch', Status: 'exited', Details: 'Error: Out of memory' },
                    { Name: 'so-logstash', Status: 'running', Details: 'unhealthy' }
                ]
            }
        ]
    }
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  fetchGridData()
})

const getStatusIcon = (status: string) => {
  switch (status) {
    case 'ok': return CheckCircle
    case 'fault': return AlertTriangle
    case 'pending': return AlertCircle
    case 'restart': return Info
    default: return AlertCircle
  }
}

const getContainerStatusColor = (status: string) => {
    return status === 'running' ? 'text-green-500' : 'text-red-500'
}


// Check if a node has a monitoring interface (sensors, standalones, heavynodes, eval, import)
const hasMonitoringInterface = (node: GridNode) => {
    const role = node.role?.toLowerCase() || ''
    return role.includes('sensor') ||
           role.includes('standalone') ||
           role.includes('heavynode') ||
           role.includes('eval') ||
           role.includes('import')
}
</script>

<template>
  <div class="space-y-6">
    <div class="flex items-center justify-between">
      <div>
        <h2 class="text-2xl font-bold tracking-tight">Grid Members</h2>
        <p class="text-muted-foreground">Manage and monitor your grid nodes.</p>
      </div>
      <button 
        @click="fetchGridData" 
        class="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 transition-colors"
      >
        <Server class="h-4 w-4" />
        Refresh
      </button>
    </div>

    <!-- Stats Summary -->
    <div class="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <div class="p-4 rounded-lg bg-card border border-border shadow-sm flex items-center justify-between">
             <div>
                <p class="text-sm font-medium text-muted-foreground">Total Nodes</p>
                <div class="flex items-baseline gap-2">
                    <h3 class="text-2xl font-bold">{{ nodes.length }}</h3>
                    <span v-if="nodes.filter(n => n.osNeedsRestart).length > 0" class="text-blue-500 text-xs font-medium">
                        ({{ nodes.filter(n => n.osNeedsRestart).length }} reboot)
                    </span>
                </div>
             </div>
             <Server class="h-8 w-8 text-primary opacity-50" />
        </div>
        <div class="p-4 rounded-lg bg-card border border-border shadow-sm flex items-center justify-between">
             <div>
                <p class="text-sm font-medium text-muted-foreground">Healthy</p>
                <h3 class="text-2xl font-bold text-green-500">{{ nodes.filter(n => n.status === 'ok').length }}</h3>
             </div>
             <CheckCircle class="h-8 w-8 text-green-500 opacity-50" />
        </div>
         <div class="p-4 rounded-lg bg-card border border-border shadow-sm flex items-center justify-between">
             <div>
                <p class="text-sm font-medium text-muted-foreground">Issues</p>
                <h3 class="text-2xl font-bold text-red-500">{{ nodes.filter(n => n.status === 'fault' || n.status === 'pending').length }}</h3>
             </div>
             <AlertTriangle class="h-8 w-8 text-red-500 opacity-50" />
        </div>
         <div class="p-4 rounded-lg bg-card border border-border shadow-sm flex items-center justify-between">
             <div>
                <p class="text-sm font-medium text-muted-foreground">Total EPS</p>
                <h3 class="text-2xl font-bold">{{ nodes.reduce((acc, curr) => acc + (curr.consumptionEps || 0), 0).toLocaleString() }}</h3>
             </div>
             <Activity class="h-8 w-8 text-primary opacity-50" />
        </div>
    </div>

    <!-- Search and Filter Bar -->
    <div class="flex items-center gap-4">
        <div class="relative flex-1 max-w-sm">
            <Search class="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <input
                v-model="searchQuery"
                type="text"
                placeholder="Filter by node name..."
                class="w-full h-10 pl-10 pr-4 rounded-md border border-input bg-background text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
            />
        </div>
        <div v-if="searchQuery" class="text-sm text-muted-foreground">
            Showing {{ filteredNodes.length }} of {{ nodes.length }} nodes
        </div>
    </div>

    <!-- Nodes Table -->
    <div class="rounded-md border border-border bg-card overflow-hidden">
      <div class="overflow-x-auto">
        <table class="w-full text-sm">
          <thead>
            <tr class="border-b border-border bg-muted/50">
              <th class="w-10 px-4"></th>
              <th class="h-12 px-4 text-left align-middle font-medium text-muted-foreground">Status</th>
              <th
                @click="toggleSort('id')"
                class="h-12 px-4 text-left align-middle font-medium text-muted-foreground cursor-pointer hover:text-foreground select-none"
              >
                <div class="flex items-center gap-1">
                  Node
                  <ChevronUp v-if="getSortDirection('id') === 'asc'" class="h-4 w-4" />
                  <ChevronDown v-else-if="getSortDirection('id') === 'desc'" class="h-4 w-4" />
                  <ArrowUpDown v-else class="h-4 w-4 opacity-50" />
                </div>
              </th>
              <th
                @click="toggleSort('role')"
                class="h-12 px-4 text-left align-middle font-medium text-muted-foreground cursor-pointer hover:text-foreground select-none"
              >
                <div class="flex items-center gap-1">
                  Role
                  <ChevronUp v-if="getSortDirection('role') === 'asc'" class="h-4 w-4" />
                  <ChevronDown v-else-if="getSortDirection('role') === 'desc'" class="h-4 w-4" />
                  <ArrowUpDown v-else class="h-4 w-4 opacity-50" />
                </div>
              </th>
              <th
                @click="toggleSort('address')"
                class="h-12 px-4 text-left align-middle font-medium text-muted-foreground cursor-pointer hover:text-foreground select-none"
              >
                <div class="flex items-center gap-1">
                  Address
                  <ChevronUp v-if="getSortDirection('address') === 'asc'" class="h-4 w-4" />
                  <ChevronDown v-else-if="getSortDirection('address') === 'desc'" class="h-4 w-4" />
                  <ArrowUpDown v-else class="h-4 w-4 opacity-50" />
                </div>
              </th>
              <th class="h-12 px-4 text-left align-middle font-medium text-muted-foreground">Stats</th>
              <th
                @click="toggleSort('osUptimeSeconds')"
                class="h-12 px-4 text-left align-middle font-medium text-muted-foreground cursor-pointer hover:text-foreground select-none"
              >
                <div class="flex items-center gap-1">
                  OS Uptime
                  <ChevronUp v-if="getSortDirection('osUptimeSeconds') === 'asc'" class="h-4 w-4" />
                  <ChevronDown v-else-if="getSortDirection('osUptimeSeconds') === 'desc'" class="h-4 w-4" />
                  <ArrowUpDown v-else class="h-4 w-4 opacity-50" />
                </div>
              </th>
              <th
                @click="toggleSort('version')"
                class="h-12 px-4 text-left align-middle font-medium text-muted-foreground cursor-pointer hover:text-foreground select-none"
              >
                <div class="flex items-center gap-1">
                  Version
                  <ChevronUp v-if="getSortDirection('version') === 'asc'" class="h-4 w-4" />
                  <ChevronDown v-else-if="getSortDirection('version') === 'desc'" class="h-4 w-4" />
                  <ArrowUpDown v-else class="h-4 w-4 opacity-50" />
                </div>
              </th>
            </tr>
          </thead>
          <tbody>
            <tr v-if="loading" class="border-b border-border">
                <td colspan="8" class="h-24 text-center text-muted-foreground">Loading grid members...</td>
            </tr>
            <tr v-else-if="filteredNodes.length === 0" class="border-b border-border">
                <td colspan="8" class="h-24 text-center text-muted-foreground">
                    {{ searchQuery ? 'No nodes match your filter.' : 'No nodes found.' }}
                </td>
            </tr>
            <template v-for="node in filteredNodes" :key="node.id">
              <tr 
                @click="toggleNode(node.id)"
                :class="cn(
                    'border-b border-border transition-colors hover:bg-muted/50 cursor-pointer',
                    expandedNodeId === node.id && 'bg-muted/30'
                )"
              >
                <td class="p-4 align-middle text-center">
                    <ChevronDown v-if="expandedNodeId === node.id" class="h-4 w-4 text-muted-foreground" />
                    <ChevronRight v-else class="h-4 w-4 text-muted-foreground" />
                </td>
                <td class="p-4 align-middle">
                   <component :is="getStatusIcon(node.status)" :class="cn('h-5 w-5', getNodeStatusColor(node.status))" />
                </td>
                <td class="p-4 align-middle">
                  <div class="font-medium">{{ node.id }}</div>
                  <div class="text-xs text-muted-foreground">{{ node.model }}</div>
                </td>
                <td class="p-4 align-middle">
                  <span class="inline-flex items-center rounded-full border border-border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 text-foreground">
                      {{ node.role }}
                  </span>
                </td>
                <td class="p-4 align-middle">{{ node.address }}</td>
                <td class="p-4 align-middle">
                   <div class="flex flex-col gap-1 text-xs">
                      <div class="flex items-center gap-1">
                          <Activity class="h-3 w-3 text-muted-foreground" />
                          <span>EPS: {{ node.consumptionEps?.toLocaleString() || 0 }}</span>
                      </div>
                       <div class="flex items-center gap-1">
                          <Cpu class="h-3 w-3 text-muted-foreground" />
                          <span :class="getUsageColor(node.cpuUsedPct)">CPU: {{ Math.round(node.cpuUsedPct) }}%</span>
                      </div>
                       <div class="flex items-center gap-1">
                          <HardDrive class="h-3 w-3 text-muted-foreground" />
                          <span :class="getUsageColor(node.diskUsedRootPct)">Disk: {{ Math.round(node.diskUsedRootPct) }}%</span>
                      </div>
                      <div v-if="hasMonitoringInterface(node)" class="flex items-center gap-1">
                          <Network class="h-3 w-3 text-orange-500" />
                          <span class="text-orange-600 dark:text-orange-400">Mon: {{ (node.trafficMonInMbs || 0).toFixed(1) }} Mb/s</span>
                      </div>
                   </div>
                </td>
                <td class="p-4 align-middle">
                  {{ formatUptime(node.osUptimeSeconds || 0) }}
                  <div v-if="node.osNeedsRestart" class="text-blue-500 text-[10px] font-bold animate-pulse leading-none mt-1">REBOOT</div>
                </td>
                <td class="p-4 align-middle text-muted-foreground">{{ node.version }}</td>
              </tr>
              
              <!-- Expanded Detail View -->
              <tr v-if="expandedNodeId === node.id" class="border-b border-border bg-muted/10">
                <td colspan="8" class="p-6">
                    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6 animate-in fade-in slide-in-from-top-2 duration-300">
                        
                        <!-- Node Info Card -->
                        <div class="space-y-4">
                            <div class="flex items-center gap-2 mb-2 font-semibold text-primary">
                                <Info class="h-5 w-5" />
                                <h3>Node Status</h3>
                            </div>
                            <div class="rounded-lg border border-border bg-card p-4 space-y-3 text-sm">
                                <div class="flex justify-between border-b border-border pb-2">
                                    <span class="text-muted-foreground">ID:</span>
                                    <span class="font-medium">{{ node.id }}</span>
                                </div>
                                <div class="flex justify-between border-b border-border pb-2">
                                    <span class="text-muted-foreground">Grid ID:</span>
                                    <span class="font-medium">{{ node.gridId }}</span>
                                </div>
                                <div class="flex justify-between border-b border-border pb-2">
                                    <span class="text-muted-foreground">Role:</span>
                                    <span class="font-medium">{{ node.role }}</span>
                                </div>
                                <div class="flex justify-between border-b border-border pb-2">
                                    <span class="text-muted-foreground">Date Created:</span>
                                    <span class="font-medium">{{ formatDate(node.onlineTime) }}</span>
                                </div>
                                <div class="flex justify-between border-b border-border pb-2">
                                    <span class="text-muted-foreground">Last Heard From:</span>
                                    <span class="font-medium">{{ formatDate(node.updateTime) }}</span>
                                </div>
                                <div class="flex justify-between border-b border-border pb-2">
                                    <span class="text-muted-foreground">Age:</span>
                                    <span class="font-medium">{{ formatRelativeTime(node.onlineTime) }}</span>
                                </div>
                                <div class="flex justify-between border-b border-border pb-2">
                                    <span class="text-muted-foreground">OS Uptime:</span>
                                    <span class="font-medium">
                                        {{ formatUptime(node.osUptimeSeconds || 0) }}
                                        <span v-if="node.osNeedsRestart" class="text-blue-500 ml-1 text-[10px] animate-pulse">(awaiting reboot)</span>
                                    </span>
                                </div>
                                <div class="flex justify-between border-b border-border pb-2">
                                    <span class="text-muted-foreground">Last Synchronized:</span>
                                    <span class="font-medium">{{ formatUptime(node.highstateAgeSeconds || 0) }} ago</span>
                                </div>
                                <div class="flex justify-between border-b border-border pb-2">
                                    <span class="text-muted-foreground">Process Status:</span>
                                    <span :class="cn('font-medium capitalize', node.processStatus === 'ok' ? 'text-green-500' : 'text-red-500')">
                                        {{ node.processStatus || 'Unknown' }}
                                    </span>
                                </div>
                                <div class="flex justify-between border-b border-border pb-2">
                                    <span class="text-muted-foreground">Connection Status:</span>
                                    <span :class="cn('font-medium capitalize', node.connectionStatus === 'ok' ? 'text-green-500' : 'text-red-500')">
                                        {{ node.connectionStatus || 'Unknown' }}
                                    </span>
                                </div>
                                <div class="flex justify-between border-b border-border pb-2">
                                    <span class="text-muted-foreground">RAID Status:</span>
                                    <span :class="cn('font-medium capitalize', (!node.raidStatus || node.raidStatus === 'unknown') ? 'text-muted-foreground' : (node.raidStatus === 'ok' ? 'text-green-500' : 'text-red-500'))">
                                        {{ (!node.raidStatus || node.raidStatus === 'unknown') ? 'Feature Unavailable' : node.raidStatus }}
                                    </span>
                                </div>
                                <div v-if="node.description" class="pt-2">
                                    <span class="text-xs text-muted-foreground block mb-1">Description:</span>
                                    <p class="text-xs italic">{{ node.description }}</p>
                                </div>
                                <div v-if="node.keywords" class="pt-2">
                                    <span class="text-xs text-muted-foreground block mb-1">Filter Keywords:</span>
                                    <p class="text-[10px] break-words">{{ node.keywords }}</p>
                                </div>
                            </div>
                            
                            <!-- Actions -->
                            <div class="flex flex-wrap gap-2 pt-2">
                                <button 
                                    @click.stop="toggleMetrics(node.id)"
                                    :class="cn(
                                        'flex items-center gap-1.5 px-3 py-1.5 rounded border border-border text-xs transition-colors',
                                        showMetrics[node.id] ? 'bg-primary text-primary-foreground' : 'bg-muted hover:bg-muted/80'
                                    )"
                                >
                                    <BarChart2 class="h-3.5 w-3.5" />
                                    Metrics
                                </button>
                                <button v-if="isUserAdmin()" class="flex items-center gap-1.5 px-3 py-1.5 bg-muted hover:bg-muted/80 rounded border border-border text-xs transition-colors">
                                    <PlayCircle class="h-3.5 w-3.5" />
                                    Test
                                </button>
                                <button class="flex items-center gap-1.5 px-3 py-1.5 bg-muted hover:bg-muted/80 rounded border border-border text-xs transition-colors">
                                    <Upload class="h-3.5 w-3.5" />
                                    Upload
                                </button>
                                <button v-if="isUserAdmin()" class="flex items-center gap-1.5 px-3 py-1.5 bg-muted hover:bg-muted/80 rounded border border-border text-xs transition-colors text-red-500">
                                    <RotateCcw class="h-3.5 w-3.5" />
                                    Restart
                                </button>
                            </div>
                        </div>

                        <!-- Resource Metrics Card -->
                        <div class="space-y-4">
                            <div class="flex items-center gap-2 mb-2 font-semibold text-primary">
                                <Activity class="h-5 w-5" />
                                <h3>Resource Usage</h3>
                            </div>
                            <div class="rounded-lg border border-border bg-card p-4 space-y-6">
                                
                                <!-- CPU -->
                                <div class="space-y-2">
                                    <div class="flex justify-between text-xs font-medium">
                                        <span>CPU Usage</span>
                                        <span :class="getUsageColor(node.cpuUsedPct)">{{ Math.round(node.cpuUsedPct) }}%</span>
                                    </div>
                                    <div class="h-2 w-full bg-muted rounded-full overflow-hidden">
                                        <div 
                                            :class="cn('h-full transition-all duration-500', getProgressColor(node.cpuUsedPct))"
                                            :style="{ width: `${node.cpuUsedPct}%` }"
                                        ></div>
                                    </div>
                                </div>

                                <!-- Memory -->
                                <div class="space-y-2">
                                    <div class="flex justify-between text-xs font-medium">
                                        <span>Memory Usage</span>
                                        <span :class="getUsageColor(node.memoryUsedPct)">{{ Math.round(node.memoryUsedPct) }}%</span>
                                    </div>
                                    <div class="h-2 w-full bg-muted rounded-full overflow-hidden">
                                        <div 
                                            :class="cn('h-full transition-all duration-500', getProgressColor(node.memoryUsedPct))"
                                            :style="{ width: `${node.memoryUsedPct}%` }"
                                        ></div>
                                    </div>
                                    <p class="text-[10px] text-muted-foreground text-right italic">
                                        {{ Math.round((node.memoryUsedPct / 100) * (node.memoryTotalGB || 0) * 10) / 10 }}GB used of {{ node.memoryTotalGB }}GB
                                    </p>
                                </div>

                                <!-- Swap -->
                                <div class="space-y-2">
                                    <div class="flex justify-between text-xs font-medium">
                                        <span>Swap Usage</span>
                                        <span :class="getUsageColor(node.swapUsedPct || 0)">{{ Math.round(node.swapUsedPct || 0) }}%</span>
                                    </div>
                                    <div class="h-1.5 w-full bg-muted rounded-full overflow-hidden">
                                        <div 
                                            :class="cn('h-full transition-all duration-500 opacity-80', getProgressColor(node.swapUsedPct || 0))"
                                            :style="{ width: `${node.swapUsedPct || 0}%` }"
                                        ></div>
                                    </div>
                                    <p class="text-[10px] text-muted-foreground text-right italic">
                                        {{ Math.round(((node.swapUsedPct || 0) / 100) * (node.swapTotalGB || 0) * 10) / 10 }}GB used of {{ node.swapTotalGB }}GB
                                    </p>
                                </div>

                                <!-- Disk (Root) -->
                                <div class="space-y-2">
                                    <div class="flex justify-between text-xs font-medium">
                                        <span>Root Partition Usage</span>
                                        <span :class="getUsageColor(node.diskUsedRootPct)">{{ Math.round(node.diskUsedRootPct) }}%</span>
                                    </div>
                                    <div class="h-2 w-full bg-muted rounded-full overflow-hidden">
                                        <div 
                                            :class="cn('h-full transition-all duration-500', getProgressColor(node.diskUsedRootPct))"
                                            :style="{ width: `${node.diskUsedRootPct}%` }"
                                        ></div>
                                    </div>
                                    <p class="text-[10px] text-muted-foreground text-right italic">
                                        {{ Math.round((node.diskUsedRootPct / 100) * (node.diskTotalRootGB || 0) * 10) / 10 }}GB used of {{ node.diskTotalRootGB }}GB
                                    </p>
                                </div>

                                <!-- Disk (NSM) -->
                                <div v-if="node.diskTotalNsmGB" class="space-y-2">
                                    <div class="flex justify-between text-xs font-medium">
                                        <span>NSM Partition Usage</span>
                                        <span :class="getUsageColor(node.diskUsedNsmPct || 0)">{{ Math.round(node.diskUsedNsmPct || 0) }}%</span>
                                    </div>
                                    <div class="h-2 w-full bg-muted rounded-full overflow-hidden">
                                        <div 
                                            :class="cn('h-full transition-all duration-500', getProgressColor(node.diskUsedNsmPct || 0))"
                                            :style="{ width: `${node.diskUsedNsmPct || 0}%` }"
                                        ></div>
                                    </div>
                                    <p class="text-[10px] text-muted-foreground text-right italic">
                                        {{ Math.round(((node.diskUsedNsmPct || 0) / 100) * (node.diskTotalNsmGB || 0) * 10) / 10 }}GB used of {{ node.diskTotalNsmGB }}GB
                                    </p>
                                </div>

                                <div class="grid grid-cols-2 gap-4 pt-4 border-t border-border">
                                    <div class="p-2 rounded bg-muted/30 border border-border/50 text-center">
                                        <p class="text-[10px] text-muted-foreground uppercase">I/O Wait</p>
                                        <p :class="cn('text-sm font-bold', (node.ioWaitPct || 0) > 2 ? 'text-amber-500' : 'text-foreground')">{{ Math.round(node.ioWaitPct || 0) }}%</p>
                                    </div>
                                    <div class="p-2 rounded bg-muted/30 border border-border/50 text-center">
                                        <p class="text-[10px] text-muted-foreground uppercase">In Mgmt</p>
                                        <p class="text-sm font-bold">{{ (node.trafficManInMbs || 0).toFixed(2) }} Mb/s</p>
                                    </div>
                                    <div class="p-2 rounded bg-muted/30 border border-border/50 text-center">
                                        <p class="text-[10px] text-muted-foreground uppercase">Out Mgmt</p>
                                        <p class="text-sm font-bold">{{ (node.trafficManOutMbs || 0).toFixed(2) }} Mb/s</p>
                                    </div>
                                    <div class="p-2 rounded bg-muted/30 border border-border/50 text-center">
                                        <p class="text-[10px] text-muted-foreground uppercase">Load Avg</p>
                                        <p class="text-xs font-bold">{{ node.load1m }}, {{ node.load5m }}, {{ node.load15m }}</p>
                                    </div>
                                    <div v-if="hasMonitoringInterface(node)" class="col-span-2 p-2 rounded bg-orange-500/10 border border-orange-500/30 text-center">
                                        <p class="text-[10px] text-orange-600 dark:text-orange-400 uppercase font-semibold">Monitoring Interface</p>
                                        <p class="text-sm font-bold text-orange-600 dark:text-orange-400">{{ (node.trafficMonInMbs || 0).toFixed(2) }} Mb/s</p>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <!-- Containers Status Card -->
                        <div class="space-y-4">
                            <div class="flex items-center gap-2 mb-2 font-semibold text-primary">
                                <Network class="h-5 w-5" />
                                <h3>Container Status</h3>
                            </div>
                            <div class="rounded-lg border border-border bg-card overflow-hidden">
                                <table class="w-full text-[11px]">
                                    <thead>
                                        <tr class="bg-muted border-b border-border">
                                            <th class="px-3 py-2 text-left">Container</th>
                                            <th class="px-3 py-2 text-left">Status</th>
                                            <th class="px-3 py-2 text-left">Details</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <tr v-if="!node.containers || node.containers.length === 0">
                                            <td colspan="3" class="px-3 py-4 text-center text-muted-foreground italic">
                                                No container information available
                                            </td>
                                        </tr>
                                        <tr v-for="container in node.containers" :key="container.Name" class="border-b border-border last:border-0">
                                            <td class="px-3 py-2 font-medium">{{ container.Name }}</td>
                                            <td class="px-3 py-2">
                                                <span :class="getContainerStatusColor(container.Status)">
                                                    {{ container.Status }}
                                                </span>
                                            </td>
                                            <td class="px-3 py-2 text-muted-foreground">{{ container.Details }}</td>
                                        </tr>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>

                    <!-- Historical Metrics Section -->
                    <div v-if="showMetrics[node.id]" class="mt-8 pt-8 border-t border-border animate-in fade-in slide-in-from-top-4 duration-500">
                        <div class="flex items-center justify-between mb-6">
                            <div class="flex items-center gap-2 font-semibold text-primary text-lg">
                                <BarChart2 class="h-6 w-6" />
                                <h3>Performance Metrics</h3>
                            </div>
                            <div class="flex items-center gap-4">
                                <div v-if="loadingMetrics[node.id]" class="flex items-center gap-2 text-xs text-muted-foreground">
                                    <RotateCcw class="h-3 w-3 animate-spin" />
                                    Loading data...
                                </div>
                                <select 
                                    v-model="selectedDuration[node.id]" 
                                    @change="fetchHistoricalMetrics(node.id)"
                                    class="h-8 rounded-md border border-input bg-background px-2 py-1 text-xs ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
                                >
                                    <option value="1h">Last 1 Hour</option>
                                    <option value="24h">Last 24 Hours</option>
                                    <option value="7d">Last 7 Days</option>
                                </select>
                            </div>
                        </div>

                        <div v-if="metricsData[node.id]" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-6">
                            <!-- CPU Graph -->
                            <div class="rounded-lg border border-border bg-card p-4 space-y-3">
                                <div class="flex justify-between items-end">
                                    <div>
                                        <p class="text-[10px] text-muted-foreground uppercase font-bold tracking-wider">CPU Usage</p>
                                        <h4 class="text-xl font-bold">{{ Math.round(node.cpuUsedPct) }}%</h4>
                                    </div>
                                    <div class="text-[10px] text-muted-foreground italic mb-1">Mean</div>
                                </div>
                                <div class="h-24 w-full relative group">
                                    <svg class="w-full h-full" viewBox="0 0 300 100" preserveAspectRatio="none">
                                        <!-- Grid Lines -->
                                        <line x1="0" y1="25" x2="300" y2="25" class="stroke-muted-foreground/10" stroke-width="1" />
                                        <line x1="0" y1="50" x2="300" y2="50" class="stroke-muted-foreground/10" stroke-width="1" />
                                        <line x1="0" y1="75" x2="300" y2="75" class="stroke-muted-foreground/10" stroke-width="1" />
                                        
                                        <!-- Area -->
                                        <path 
                                            :d="`${generatePath(metricsData[node.id].cpu, 300, 100, 100)} L 300 100 L 0 100 Z`" 
                                            class="fill-primary/10 transition-all duration-700"
                                        />
                                        <!-- Line -->
                                        <path 
                                            :d="generatePath(metricsData[node.id].cpu, 300, 100, 100)" 
                                            class="stroke-primary fill-none transition-all duration-700" 
                                            stroke-width="2" 
                                            stroke-linecap="round" 
                                            stroke-linejoin="round"
                                        />
                                    </svg>
                                </div>
                            </div>

                            <!-- Memory Graph -->
                            <div class="rounded-lg border border-border bg-card p-4 space-y-3">
                                <div class="flex justify-between items-end">
                                    <div>
                                        <p class="text-[10px] text-muted-foreground uppercase font-bold tracking-wider">Memory Usage</p>
                                        <h4 class="text-xl font-bold">{{ Math.round(node.memoryUsedPct) }}%</h4>
                                    </div>
                                    <div class="text-[10px] text-muted-foreground italic mb-1">Mean</div>
                                </div>
                                <div class="h-24 w-full relative">
                                    <svg class="w-full h-full" viewBox="0 0 300 100" preserveAspectRatio="none">
                                        <line x1="0" y1="25" x2="300" y2="25" class="stroke-muted-foreground/10" stroke-width="1" />
                                        <line x1="0" y1="50" x2="300" y2="50" class="stroke-muted-foreground/10" stroke-width="1" />
                                        <line x1="0" y1="75" x2="300" y2="75" class="stroke-muted-foreground/10" stroke-width="1" />
                                        
                                        <path 
                                            :d="`${generatePath(metricsData[node.id].memory, 300, 100, 100)} L 300 100 L 0 100 Z`" 
                                            class="fill-blue-500/10 transition-all duration-700"
                                        />
                                        <path 
                                            :d="generatePath(metricsData[node.id].memory, 300, 100, 100)" 
                                            class="stroke-blue-500 fill-none transition-all duration-700" 
                                            stroke-width="2" 
                                            stroke-linecap="round" 
                                            stroke-linejoin="round"
                                        />
                                    </svg>
                                </div>
                            </div>

                            <!-- Mgmt In Graph -->
                            <div class="rounded-lg border border-border bg-card p-4 space-y-3">
                                <div class="flex justify-between items-end">
                                    <div>
                                        <p class="text-[10px] text-muted-foreground uppercase font-bold tracking-wider">In Mgmt Traffic</p>
                                        <h4 class="text-xl font-bold">{{ (node.trafficManInMbs || 0).toFixed(2) }} <span class="text-xs font-normal">Mb/s</span></h4>
                                    </div>
                                    <div class="text-[10px] text-muted-foreground italic mb-1">Mean</div>
                                </div>
                                <div class="h-24 w-full relative">
                                    <svg class="w-full h-full" viewBox="0 0 300 100" preserveAspectRatio="none">
                                        <line x1="0" y1="25" x2="300" y2="25" class="stroke-muted-foreground/10" stroke-width="1" />
                                        <line x1="0" y1="50" x2="300" y2="50" class="stroke-muted-foreground/10" stroke-width="1" />
                                        <line x1="0" y1="75" x2="300" y2="75" class="stroke-muted-foreground/10" stroke-width="1" />
                                        
                                        <path 
                                            :d="`${generatePath(metricsData[node.id].mgmtIn, 300, 100, 0)} L 300 100 L 0 100 Z`" 
                                            class="fill-green-500/10 transition-all duration-700"
                                        />
                                        <path 
                                            :d="generatePath(metricsData[node.id].mgmtIn, 300, 100, 0)" 
                                            class="stroke-green-500 fill-none transition-all duration-700" 
                                            stroke-width="2" 
                                            stroke-linecap="round" 
                                            stroke-linejoin="round"
                                        />
                                    </svg>
                                </div>
                                <p class="text-[10px] text-muted-foreground text-right italic">Auto-scaled to peak</p>
                            </div>

                            <!-- Mgmt Out Graph -->
                            <div class="rounded-lg border border-border bg-card p-4 space-y-3">
                                <div class="flex justify-between items-end">
                                    <div>
                                        <p class="text-[10px] text-muted-foreground uppercase font-bold tracking-wider">Out Mgmt Traffic</p>
                                        <h4 class="text-xl font-bold">{{ (node.trafficManOutMbs || 0).toFixed(2) }} <span class="text-xs font-normal">Mb/s</span></h4>
                                    </div>
                                    <div class="text-[10px] text-muted-foreground italic mb-1">Mean</div>
                                </div>
                                <div class="h-24 w-full relative">
                                    <svg class="w-full h-full" viewBox="0 0 300 100" preserveAspectRatio="none">
                                        <line x1="0" y1="25" x2="300" y2="25" class="stroke-muted-foreground/10" stroke-width="1" />
                                        <line x1="0" y1="50" x2="300" y2="50" class="stroke-muted-foreground/10" stroke-width="1" />
                                        <line x1="0" y1="75" x2="300" y2="75" class="stroke-muted-foreground/10" stroke-width="1" />
                                        
                                        <path 
                                            :d="`${generatePath(metricsData[node.id].mgmtOut, 300, 100, 0)} L 300 100 L 0 100 Z`" 
                                            class="fill-purple-500/10 transition-all duration-700"
                                        />
                                        <path 
                                            :d="generatePath(metricsData[node.id].mgmtOut, 300, 100, 0)" 
                                            class="stroke-purple-500 fill-none transition-all duration-700" 
                                            stroke-width="2" 
                                            stroke-linecap="round" 
                                            stroke-linejoin="round"
                                        />
                                    </svg>
                                </div>
                                <p class="text-[10px] text-muted-foreground text-right italic">Auto-scaled to peak</p>
                            </div>

                            <!-- Bond In Graph (Monitoring) - Only for sensors with monitoring interfaces -->
                            <div v-if="hasMonitoringInterface(node)" class="rounded-lg border border-orange-500/30 bg-card p-4 space-y-3">
                                <div class="flex justify-between items-end">
                                    <div>
                                        <p class="text-[10px] text-orange-600 dark:text-orange-400 uppercase font-bold tracking-wider">Monitoring Traffic</p>
                                        <h4 class="text-xl font-bold text-orange-600 dark:text-orange-400">{{ (node.trafficMonInMbs || 0).toFixed(2) }} <span class="text-xs font-normal">Mb/s</span></h4>
                                    </div>
                                    <div class="text-[10px] text-muted-foreground italic mb-1">Mean</div>
                                </div>
                                <div v-if="metricsData[node.id].bondIn && metricsData[node.id].bondIn.length > 0" class="h-24 w-full relative">
                                    <svg class="w-full h-full" viewBox="0 0 300 100" preserveAspectRatio="none">
                                        <line x1="0" y1="25" x2="300" y2="25" class="stroke-muted-foreground/10" stroke-width="1" />
                                        <line x1="0" y1="50" x2="300" y2="50" class="stroke-muted-foreground/10" stroke-width="1" />
                                        <line x1="0" y1="75" x2="300" y2="75" class="stroke-muted-foreground/10" stroke-width="1" />

                                        <path
                                            :d="`${generatePath(metricsData[node.id].bondIn, 300, 100, 0)} L 300 100 L 0 100 Z`"
                                            class="fill-orange-500/10 transition-all duration-700"
                                        />
                                        <path
                                            :d="generatePath(metricsData[node.id].bondIn, 300, 100, 0)"
                                            class="stroke-orange-500 fill-none transition-all duration-700"
                                            stroke-width="2"
                                            stroke-linecap="round"
                                            stroke-linejoin="round"
                                        />
                                    </svg>
                                </div>
                                <div v-else class="h-24 w-full flex items-center justify-center text-muted-foreground text-xs italic">
                                    No historical data available
                                </div>
                                <p class="text-[10px] text-muted-foreground text-right italic">Auto-scaled to peak</p>
                            </div>
                        </div>
                        <div v-else-if="!loadingMetrics[node.id]" class="flex flex-col items-center justify-center p-12 bg-muted/20 rounded-lg border border-dashed border-border text-muted-foreground">
                            <Activity class="h-10 w-10 mb-2 opacity-20" />
                            <p>No historical data available for this node.</p>
                        </div>
                    </div>
                </td>
            </tr>
            </template>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>
