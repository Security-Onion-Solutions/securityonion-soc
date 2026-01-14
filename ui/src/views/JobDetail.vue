<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import {
  ArrowLeft,
  Download,
  RefreshCw,
  FileText,
  Maximize2,
  Minimize2,
  ChevronRight,
  ChevronDown
} from 'lucide-vue-next'
import { cn } from '../lib/utils'

const route = useRoute()
const router = useRouter()

// Get ID from route params (with fallback to props for compatibility)
const props = defineProps<{ id?: string }>()
const jobId = computed(() => (route.params.id as string) || props.id || '')

const goBack = () => router.push({ name: 'jobs' })

const job = ref<any>(null)
const packets = ref<any[]>([])
const loading = ref(true)
const packetsLoading = ref(false)
const error = ref<string | null>(null)
const expandedPackets = ref<Set<number>>(new Set())
const packetViewMode = ref<'hex' | 'ascii'>('hex')
const displayMode = ref<'packets' | 'transcript'>('packets')

const setViewMode = (mode: 'hex' | 'ascii') => {
    const scrollY = window.scrollY
    packetViewMode.value = mode
    // Preserve scroll position after Vue re-renders
    requestAnimationFrame(() => {
        window.scrollTo(0, scrollY)
    })
}
const unwrap = ref(false)

const headers = [
    { title: 'No.', key: 'number' },
    { title: 'Time', key: 'timestamp' },
    { title: 'Type', key: 'type' },
    { title: 'Source', key: 'srcIp' },
    { title: 'Src Port', key: 'srcPort' },
    { title: 'Destination', key: 'dstIp' },
    { title: 'Dst Port', key: 'dstPort' },
    { title: 'Flags', key: 'flags' },
    { title: 'Length', key: 'length' }
]

const fetchJob = async () => {
    loading.value = true
    try {
        const response = await fetch(`/api/job?jobId=${jobId.value}`)
        if (response.ok) {
            job.value = await response.json()
            error.value = null
            fetchPackets()
        } else {
            error.value = "Failed to fetch job details."
        }
    } catch (e: any) {
        error.value = e.message
    } finally {
        loading.value = false
    }
}

const fetchPackets = async () => {
    if (!job.value) return
    packetsLoading.value = true
    try {
        const response = await fetch(`/api/packets?jobId=${jobId.value}&offset=0&count=500&unwrap=${unwrap.value}`)
        if (response.ok) {
            packets.value = await response.json()
        } else {
            console.error("Failed to fetch packets")
        }
    } catch (e) {
        console.error("Error fetching packets", e)
    } finally {
        packetsLoading.value = false
    }
}

const toggleExpand = (packetNumber: number) => {
    if (expandedPackets.value.has(packetNumber)) {
        expandedPackets.value.delete(packetNumber)
    } else {
        expandedPackets.value.add(packetNumber)
    }
}

const expandAll = () => {
    packets.value.forEach(p => expandedPackets.value.add(p.number))
}

const collapseAll = () => {
    expandedPackets.value.clear()
}

const formatPayload = (payloadBase64: string, offset: number) => {
    if (!payloadBase64) return ''
    try {
        const binaryString = atob(payloadBase64)
        const bytes = Uint8Array.from(binaryString, c => c.charCodeAt(0))
        const sliced = bytes.slice(offset)
        
        if (packetViewMode.value === 'ascii') {
            return new TextDecoder('utf-8').decode(sliced).replace(/[^\x20-\x7E]/g, '.')
        } else {
            // Hex view
             let output = ''
             for (let i = 0; i < sliced.length; i += 16) {
                 const chunk = sliced.slice(i, i + 16)
                 
                 // Offset
                 output += i.toString(16).padStart(4, '0') + '  '
                 
                 // Hex
                 let hex = ''
                 let ascii = ''
                 for (let j = 0; j < 16; j++) {
                     if (j < chunk.length) {
                         const byte = chunk[j]
                         hex += byte.toString(16).padStart(2, '0').toUpperCase() + ' '
                         ascii += (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.'
                     } else {
                         hex += '   '
                     }
                     if (j === 7) hex += ' '
                 }
                 output += hex + ' | ' + ascii + '\n'
             }
             return output
        }
    } catch (e) {
        return "Error decoding payload"
    }
}

const downloadPcap = () => {
    if (!job.value) return
    const url = `/api/stream?jobId=${job.value.id}&ext=pcap`
    window.location.href = url
}

const getTypeColor = (type: string) => {
    if (!type) return 'bg-gray-100 text-gray-800'
    if (type.includes('TCP')) return 'bg-blue-100 text-blue-800 border-blue-200'
    if (type.includes('UDP')) return 'bg-green-100 text-green-800 border-green-200'
    if (type.includes('ICMP')) return 'bg-cyan-100 text-cyan-800 border-cyan-200'
    if (type.includes('DNS')) return 'bg-purple-100 text-purple-800 border-purple-200'
    return 'bg-gray-100 text-gray-800 border-gray-200'
}

interface TranscriptSegment {
    text: string
    direction: 'client' | 'server'
    directionChanged: boolean
}

const getAsciiTranscriptSegments = (): TranscriptSegment[] => {
    if (packets.value.length === 0) return []

    const segments: TranscriptSegment[] = []
    // Use first packet's source as "client" direction
    const clientIp = packets.value[0]?.srcIp
    const clientPort = packets.value[0]?.srcPort
    let lastDirection: 'client' | 'server' | null = null

    for (const packet of packets.value) {
        if (!packet.payload) continue
        try {
            const binaryString = atob(packet.payload)
            const bytes = Uint8Array.from(binaryString, c => c.charCodeAt(0))
            const sliced = bytes.slice(packet.payloadOffset || 0)
            const ascii = new TextDecoder('utf-8').decode(sliced).replace(/[^\x20-\x7E\n\r\t]/g, '.')
            if (ascii.trim()) {
                const isClient = packet.srcIp === clientIp && packet.srcPort === clientPort
                const direction = isClient ? 'client' : 'server'
                const directionChanged = lastDirection !== null && lastDirection !== direction
                segments.push({
                    text: ascii,
                    direction,
                    directionChanged
                })
                lastDirection = direction
            }
        } catch (e) {
            // Skip packets with decode errors
        }
    }
    return segments
}

onMounted(() => {
    fetchJob()
})
</script>

<template>
  <div class="space-y-6 animate-in slide-in-from-right duration-500">
     <!-- Header -->
    <div class="flex flex-col gap-4">
      <button @click="goBack()" class="flex items-center gap-2 text-sm text-muted-foreground hover:text-primary transition-colors w-fit group">
        <ArrowLeft class="h-4 w-4 group-hover:-translate-x-1 transition-transform" />
        Back to Jobs
      </button>

      <div class="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div>
              <h2 class="text-3xl font-bold tracking-tight text-foreground flex items-center gap-3">
                  <FileText class="h-8 w-8 text-primary" />
                  Job {{ jobId }}
              </h2>
               <div v-if="job && job.filter" class="flex items-center gap-4 mt-2 text-sm text-muted-foreground font-mono">
                  <div class="bg-muted px-2 py-1 rounded border border-border">
                      {{ job.nodeId }}
                  </div>
                  <div class="flex items-center gap-2">
                      <span>{{ job.filter.srcIp }}:{{ job.filter.srcPort }}</span>
                      <ChevronRight class="h-3 w-3" />
                      <span>{{ job.filter.dstIp }}:{{ job.filter.dstPort }}</span>
                  </div>
              </div>
          </div>
      </div>
    </div>

    <!-- Packets Table -->
    <div class="rounded-xl border border-border bg-card overflow-hidden shadow-sm">
        <!-- Toolbar inside card -->
        <div class="flex items-center justify-between p-3 border-b border-border bg-muted/30">
            <!-- Left side: Display mode toggle -->
            <div class="flex items-center gap-1 bg-muted rounded-lg p-1">
                <button
                    @click="displayMode = 'packets'"
                    :class="cn('px-3 py-1.5 rounded-md text-sm font-medium transition-colors', displayMode === 'packets' ? 'bg-background text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground')"
                >
                    Packets
                </button>
                <button
                    @click="displayMode = 'transcript'"
                    :class="cn('px-3 py-1.5 rounded-md text-sm font-medium transition-colors', displayMode === 'transcript' ? 'bg-background text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground')"
                >
                    Transcript
                </button>
            </div>

            <!-- Right side: Tools -->
            <div class="flex items-center gap-2">
                <button @click="fetchPackets" class="p-2 hover:bg-muted rounded-md transition-colors text-muted-foreground" title="Refresh Packets">
                    <RefreshCw class="h-5 w-5" :class="{ 'animate-spin': packetsLoading }" />
                </button>
                <template v-if="displayMode === 'packets'">
                    <div class="h-6 w-px bg-border mx-1"></div>
                    <button
                        @click="setViewMode('hex')"
                        :class="cn('px-3 py-1.5 rounded-md text-sm font-medium transition-colors border', packetViewMode === 'hex' ? 'bg-primary/10 text-primary border-primary/20' : 'text-muted-foreground border-transparent hover:bg-muted')"
                    >
                        Hex
                    </button>
                    <button
                        @click="setViewMode('ascii')"
                        :class="cn('px-3 py-1.5 rounded-md text-sm font-medium transition-colors border', packetViewMode === 'ascii' ? 'bg-primary/10 text-primary border-primary/20' : 'text-muted-foreground border-transparent hover:bg-muted')"
                    >
                        ASCII
                    </button>
                    <div class="h-6 w-px bg-border mx-1"></div>
                    <button @click="expandAll" class="p-2 hover:bg-muted rounded-md transition-colors text-muted-foreground" title="Expand All">
                        <Maximize2 class="h-5 w-5" />
                    </button>
                    <button @click="collapseAll" class="p-2 hover:bg-muted rounded-md transition-colors text-muted-foreground" title="Collapse All">
                        <Minimize2 class="h-5 w-5" />
                    </button>
                </template>
                <div class="h-6 w-px bg-border mx-1"></div>
                <button @click="downloadPcap" class="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 transition-all shadow-lg active:scale-95">
                    <Download class="h-4 w-4" />
                    Download PCAP
                </button>
            </div>
        </div>

        <!-- Packets Table View -->
        <div v-if="displayMode === 'packets'" class="overflow-x-auto">
            <table class="w-full text-sm font-mono">
                <thead>
                    <tr class="bg-muted/30 border-b border-border">
                        <th class="w-10"></th> <!-- Expand toggle -->
                        <th v-for="header in headers" :key="header.key" class="px-4 py-3 text-left font-semibold text-muted-foreground whitespace-nowrap">
                            {{ header.title }}
                        </th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-border">
                    <tr v-if="packetsLoading && packets.length === 0">
                        <td colspan="10" class="h-32 text-center text-muted-foreground font-sans">Loading packets...</td>
                    </tr>
                    <template v-for="packet in packets" :key="packet.number">
                        <tr
                            @click="toggleExpand(packet.number)"
                            class="hover:bg-muted/50 cursor-pointer transition-colors"
                            :class="{ 'bg-muted/20': expandedPackets.has(packet.number) }"
                        >
                            <td class="px-4 py-2 text-center">
                                <ChevronDown
                                    class="h-4 w-4 text-muted-foreground transition-transform duration-200"
                                    :class="{ '-rotate-90': !expandedPackets.has(packet.number) }"
                                />
                            </td>
                            <td class="px-4 py-2">{{ packet.number }}</td>
                            <td class="px-4 py-2 whitespace-nowrap">{{ new Date(packet.timestamp).toLocaleTimeString() }}</td>
                            <td class="px-4 py-2">
                                <span :class="cn('px-1.5 py-0.5 rounded text-xs font-bold border', getTypeColor(packet.type))">
                                    {{ packet.type }}
                                </span>
                            </td>
                            <td class="px-4 py-2">{{ packet.srcIp }}</td>
                            <td class="px-4 py-2">{{ packet.srcPort }}</td>
                            <td class="px-4 py-2">{{ packet.dstIp }}</td>
                            <td class="px-4 py-2">{{ packet.dstPort }}</td>
                            <td class="px-4 py-2">
                                <span v-for="flag in packet.flags" :key="flag" class="inline-block px-1 py-0.5 rounded text-xs bg-muted mr-1">
                                    {{ flag }}
                                </span>
                            </td>
                             <td class="px-4 py-2">{{ packet.length }}</td>
                        </tr>
                        <!-- Payload Row -->
                        <tr v-if="expandedPackets.has(packet.number)">
                            <td colspan="10" class="bg-muted/10 p-4 border-b border-border">
                                <div class="bg-card border border-border rounded-lg p-4 font-mono text-xs leading-relaxed select-text shadow-inner whitespace-pre-wrap break-words" style="overflow-wrap: anywhere;">
                                    {{ formatPayload(packet.payload, packet.payloadOffset) }}
                                </div>
                            </td>
                        </tr>
                    </template>
                </tbody>
            </table>
        </div>

        <!-- ASCII Transcript View -->
        <div v-else-if="displayMode === 'transcript'" class="p-4">
            <div v-if="packetsLoading" class="h-32 flex items-center justify-center text-muted-foreground">
                Loading packets...
            </div>
            <div v-else-if="packets.length === 0" class="h-32 flex items-center justify-center text-muted-foreground">
                No packets found
            </div>
            <template v-else>
                <div class="flex items-center gap-4 mb-3 text-xs">
                    <div class="flex items-center gap-2">
                        <span class="w-3 h-3 rounded bg-red-500"></span>
                        <span class="text-muted-foreground">Client → Server</span>
                    </div>
                    <div class="flex items-center gap-2">
                        <span class="w-3 h-3 rounded bg-blue-500"></span>
                        <span class="text-muted-foreground">Server → Client</span>
                    </div>
                </div>
                <div class="bg-card border border-border rounded-lg p-4 font-mono text-xs leading-relaxed select-text shadow-inner whitespace-pre-wrap break-words" style="overflow-wrap: anywhere;"><template
                    v-for="(segment, idx) in getAsciiTranscriptSegments()"
                    :key="idx"
                ><span v-if="segment.directionChanged" class="block my-3 border-t border-border"></span><span
                    :class="segment.direction === 'client' ? 'text-red-500' : 'text-blue-500'"
                >{{ segment.text }}</span></template></div>
            </template>
        </div>
    </div>
  </div>
</template>
