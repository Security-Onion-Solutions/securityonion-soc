<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { 
  FileText, // For Jobs
  Plus, 
  Search, 
  RefreshCw, 
  Trash2,
  Clock, // Queue
  CheckCircle2, // Completed
  AlertTriangle, // Incomplete/Failed
  XCircle, // Deleted
  Eye,
  Server
} from 'lucide-vue-next'
import { cn } from '../lib/utils'
import { useUsers } from '../composables/useUsers'
import { useFormatters } from '../composables/useFormatters'
import { useStatusStyles } from '../composables/useStatusStyles'

const emit = defineEmits(['view-detail'])
const { getUserName } = useUsers()
const { formatDate } = useFormatters()
const { getJobStatusStyles } = useStatusStyles()

interface Job {
    id: string
    nodeId: string
    userId: string
    owner?: string
    status: number
    createTime: string
    completeTime: string
    failTime: string
    failure: string
    size: number
    fileExtension: string
    filter?: {
        importId?: string
        protocol?: string
        srcIp?: string
        srcPort?: number
        dstIp?: string
        dstPort?: number
        beginTime?: string
        endTime?: string
        parameters?: any
    }
}

interface GridNode {
    id: string
    role: string
    pcapDays: number
}

const JobStatus = {
    Pending: 0,
    Completed: 1,
    Incomplete: 2,
    Deleted: 3
}

const jobs = ref<Job[]>([])
const loading = ref(true)
const searchQuery = ref('')


// PCAP-capable nodes
const pcapNodes = ref<GridNode[]>([])
const nodesLoading = ref(false)

// Create Job Form
const showCreateForm = ref(false)
const createForm = ref({
    sensorId: '',
    importId: '',
    protocol: '',
    srcIp: '',
    srcPort: '',
    dstIp: '',
    dstPort: '',
    startTime: '',
    endTime: ''
})

const fetchJobs = async () => {
    loading.value = true
    try {
        const response = await fetch('/api/jobs?kind=pcap')
        if (response.ok) {
            jobs.value = await response.json()
        } else {
            console.error("Failed to fetch jobs")
        }
    } catch (e) {
        console.error("Error fetching jobs", e)
    } finally {
        loading.value = false
    }
}

const fetchPcapNodes = async () => {
    if (pcapNodes.value.length > 0) return // Already loaded
    nodesLoading.value = true
    try {
        const response = await fetch('/api/grid')
        if (response.ok) {
            const allNodes: GridNode[] = await response.json()
            // Filter to nodes that have PCAP capability (pcapDays > 0)
            pcapNodes.value = allNodes.filter(node => node.pcapDays > 0)
        } else {
            console.error("Failed to fetch nodes")
        }
    } catch (e) {
        console.error("Error fetching nodes", e)
    } finally {
        nodesLoading.value = false
    }
}

const openCreateForm = () => {
    showCreateForm.value = true
    fetchPcapNodes()
}

const deleteJob = async (id: string) => {
    if (!confirm("Are you sure you want to delete this job?")) return
    try {
        await fetch(`/api/job/${id}`, { method: 'DELETE' })
        jobs.value = jobs.value.filter(j => j.id !== id)
    } catch (e) {
        console.error("Failed to delete job", e)
    }
}

const createJob = async () => {
    try {
        const filter: any = {}
        if (createForm.value.importId) filter.importId = createForm.value.importId
        if (createForm.value.protocol) filter.protocol = createForm.value.protocol.toLowerCase()
        if (createForm.value.srcIp) filter.srcIp = createForm.value.srcIp
        if (createForm.value.srcPort) filter.srcPort = parseInt(createForm.value.srcPort)
        if (createForm.value.dstIp) filter.dstIp = createForm.value.dstIp
        if (createForm.value.dstPort) filter.dstPort = parseInt(createForm.value.dstPort)
        if (createForm.value.startTime && createForm.value.endTime) {
            filter.beginTime = new Date(createForm.value.startTime).toISOString()
            filter.endTime = new Date(createForm.value.endTime).toISOString()
        }

        const payload = {
            nodeId: createForm.value.sensorId,
            filter: filter
        }

        const response = await fetch('/api/job/', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        })

        if (response.ok) {
            showCreateForm.value = false
            fetchJobs()
             // Reset form partially? or keep for reuse
        } else {
            alert("Failed to create job")
        }
    } catch (e) {
        console.error("Error creating job", e)
    }
}

const filteredJobs = computed(() => {
    if (!searchQuery.value) return jobs.value
    const q = searchQuery.value.toLowerCase()
    return jobs.value.filter(j =>
        j.id.toLowerCase().includes(q) ||
        j.nodeId.toLowerCase().includes(q) ||
        getUserName(j.userId)?.toLowerCase().includes(q)
    )
})

const getStatusText = (status: number) => {
     switch (status) {
        case JobStatus.Completed: return "Completed"
        case JobStatus.Pending: return "Pending"
        case JobStatus.Incomplete: return "Incomplete"
        case JobStatus.Deleted: return "Deleted"
        default: return "Unknown"
    }
}

onMounted(() => {
    fetchJobs()
})
</script>

<template>
  <div class="space-y-6 animate-in fade-in duration-500">
    <div class="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
      <div>
        <h2 class="text-3xl font-bold tracking-tight text-primary flex items-center gap-2">
          <FileText class="h-8 w-8" />
          PCAP Jobs
        </h2>
        <p class="text-muted-foreground">Manage and retrieve packet captures from your sensors.</p>
      </div>
      <div class="flex items-center gap-2">
         <div class="relative w-64">
          <Search class="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <input 
            v-model="searchQuery"
            type="text" 
            placeholder="Search jobs..." 
            class="w-full pl-9 pr-4 py-2 bg-card border border-border rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-primary/50 transition-all"
          />
        </div>
        <button 
          @click="fetchJobs"
          class="p-2 hover:bg-muted rounded-md transition-colors text-muted-foreground"
          :class="{ 'animate-spin': loading }"
        >
          <RefreshCw class="h-5 w-5" />
        </button>
        <button
            @click="openCreateForm"
            class="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 transition-all shadow-lg active:scale-95"
        >
          <Plus class="h-4 w-4" />
          New Job
        </button>
      </div>
    </div>

    <!-- Create Job Panel -->
    <div v-if="showCreateForm" class="bg-card border border-border rounded-xl p-6 shadow-sm animate-in slide-in-from-top-4 duration-300">
        <h3 class="text-lg font-semibold mb-4">Create New PCAP Job</h3>
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <div class="space-y-2">
                <label class="text-sm font-medium">Sensor <span class="text-red-500">*</span></label>
                <select
                    v-model="createForm.sensorId"
                    class="w-full p-2 bg-card text-foreground border border-border rounded-md focus:outline-none focus:ring-2 focus:ring-primary/50 cursor-pointer"
                    :disabled="nodesLoading"
                >
                    <option value="" disabled class="bg-card text-muted-foreground">{{ nodesLoading ? 'Loading...' : 'Select a sensor' }}</option>
                    <option v-for="node in pcapNodes" :key="node.id" :value="node.id" class="bg-card text-foreground">
                        {{ node.id }}
                    </option>
                </select>
            </div>
            <div class="space-y-2">
                <label class="text-sm font-medium">Import ID</label>
                <input v-model="createForm.importId" type="text" class="w-full p-2 bg-muted/20 border border-border rounded-md focus:outline-none focus:ring-2 focus:ring-primary/50" />
            </div>
            <div class="space-y-2">
                <label class="text-sm font-medium">Protocol</label>
                <input v-model="createForm.protocol" type="text" class="w-full p-2 bg-muted/20 border border-border rounded-md focus:outline-none focus:ring-2 focus:ring-primary/50" placeholder="tcp, udp, etc" />
            </div>
             <div class="space-y-2">
                <label class="text-sm font-medium">Source IP</label>
                <input v-model="createForm.srcIp" type="text" class="w-full p-2 bg-muted/20 border border-border rounded-md focus:outline-none focus:ring-2 focus:ring-primary/50" />
            </div>
             <div class="space-y-2">
                <label class="text-sm font-medium">Source Port</label>
                <input v-model="createForm.srcPort" type="number" class="w-full p-2 bg-muted/20 border border-border rounded-md focus:outline-none focus:ring-2 focus:ring-primary/50" />
            </div>
             <div class="space-y-2">
                <label class="text-sm font-medium">Dest IP</label>
                <input v-model="createForm.dstIp" type="text" class="w-full p-2 bg-muted/20 border border-border rounded-md focus:outline-none focus:ring-2 focus:ring-primary/50" />
            </div>
             <div class="space-y-2">
                <label class="text-sm font-medium">Dest Port</label>
                <input v-model="createForm.dstPort" type="number" class="w-full p-2 bg-muted/20 border border-border rounded-md focus:outline-none focus:ring-2 focus:ring-primary/50" />
            </div>
             <div class="space-y-2">
                <label class="text-sm font-medium">Start Time</label>
                <input v-model="createForm.startTime" type="datetime-local" class="w-full p-2 bg-muted/20 border border-border rounded-md focus:outline-none focus:ring-2 focus:ring-primary/50" />
            </div>
             <div class="space-y-2">
                <label class="text-sm font-medium">End Time</label>
                <input v-model="createForm.endTime" type="datetime-local" class="w-full p-2 bg-muted/20 border border-border rounded-md focus:outline-none focus:ring-2 focus:ring-primary/50" />
            </div>
        </div>
         <div class="mt-6 flex justify-end gap-3">
            <button @click="showCreateForm = false" class="px-4 py-2 text-muted-foreground hover:bg-muted rounded-md transition-colors">Cancel</button>
            <button @click="createJob" class="px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 transition-colors shadow-md">Create Job</button>
        </div>
    </div>

    <!-- Jobs Table -->
    <div class="rounded-xl border border-border bg-card overflow-hidden shadow-sm">
      <div class="overflow-x-auto">
        <table class="w-full text-sm">
          <thead>
            <tr class="border-b border-border bg-muted/30">
              <th class="h-12 px-6 text-left align-middle font-semibold text-muted-foreground">ID</th>
              <th class="h-12 px-6 text-left align-middle font-semibold text-muted-foreground">Status</th>
              <th class="h-12 px-6 text-left align-middle font-semibold text-muted-foreground">Owner</th>
              <th class="h-12 px-6 text-left align-middle font-semibold text-muted-foreground">Sensor</th>
              <th class="h-12 px-6 text-left align-middle font-semibold text-muted-foreground">Created</th>
              <th class="h-12 px-6 text-left align-middle font-semibold text-muted-foreground">Completed</th>
              <th class="h-12 px-6 text-right align-middle font-semibold text-muted-foreground">Actions</th>
            </tr>
          </thead>
           <tbody class="divide-y divide-border">
            <tr v-if="loading && jobs.length === 0" class="animate-pulse">
                <td colspan="7" class="h-32 text-center text-muted-foreground">Loading jobs...</td>
            </tr>
            <tr v-else-if="filteredJobs.length === 0" class="h-32 text-center text-muted-foreground">
                <td colspan="7">No jobs found.</td>
            </tr>
            <tr 
              v-for="job in filteredJobs" 
              :key="job.id"
              class="group transition-colors hover:bg-muted/30 cursor-pointer"
              @click="emit('view-detail', job.id)"
            >
                <td class="px-6 py-4 font-mono text-xs">{{ job.id }}</td>
                <td class="px-6 py-4">
                    <span :class="cn('px-2.5 py-0.5 rounded-full text-xs font-bold border flex w-fit items-center gap-1', getJobStatusStyles(job.status))">
                        <CheckCircle2 v-if="job.status === JobStatus.Completed" class="h-3 w-3" />
                        <Clock v-else-if="job.status === JobStatus.Pending" class="h-3 w-3" />
                        <AlertTriangle v-else-if="job.status === JobStatus.Incomplete" class="h-3 w-3" />
                        <XCircle v-else class="h-3 w-3" />
                        {{ getStatusText(job.status) }}
                    </span>
                </td>
                <td class="px-6 py-4 text-muted-foreground">{{ getUserName(job.userId) }}</td>
                <td class="px-6 py-4 text-muted-foreground flex items-center gap-1">
                    <Server class="h-3 w-3" />
                    {{ job.nodeId }}
                </td>
                <td class="px-6 py-4 text-muted-foreground">{{ formatDate(job.createTime) }}</td>
                <td class="px-6 py-4 text-muted-foreground">{{ formatDate(job.completeTime) }}</td>
                <td class="px-6 py-4 text-right" @click.stop>
                    <div class="flex items-center justify-end gap-1">
                        <button v-if="job.status === JobStatus.Completed" @click="emit('view-detail', job.id)" class="p-2 hover:bg-muted rounded text-muted-foreground hover:text-primary transition-all" title="View Packets">
                            <Eye class="h-4 w-4" />
                        </button>
                         <button @click="deleteJob(job.id)" class="p-2 hover:bg-muted rounded text-muted-foreground hover:text-red-500 transition-all" title="Delete Job">
                            <Trash2 class="h-4 w-4" />
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
