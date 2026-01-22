<script setup lang="ts">
defineOptions({ name: 'Detections' })

import { onMounted } from 'vue'
import { useRouter } from 'vue-router'
import {
  ShieldAlert,
  Search,
  CheckCircle2,
  Circle,
  MoreVertical,
  Eye,
  RefreshCw,
  Plus,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft
} from 'lucide-vue-next'
import { cn } from '../lib/utils'
import { useStatusStyles } from '../composables/useStatusStyles'
import { useDetections } from '../composables/useDetections'

const router = useRouter()
const { getSeverityStyles } = useStatusStyles()

const {
  detections,
  totalEvents,
  loading,
  error,
  searchQuery,
  currentPage,
  totalPages,
  hasNextPage,
  hasPrevPage,
  enabledCount,
  disabledCount,
  fetchDetections,
  search,
  refresh,
  toggleEnabled,
  nextPage,
  prevPage,
  firstPage
} = useDetections()

onMounted(() => {
  fetchDetections()
})

const handleSearch = (event: Event) => {
  const target = event.target as HTMLInputElement
  search(target.value)
}

const viewDetail = (id: string) => {
  router.push({ name: 'detection-detail', params: { id } })
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
            :value="searchQuery"
            @input="handleSearch"
            type="text"
            placeholder="Search rules..."
            class="w-full pl-9 pr-4 py-2 bg-card border border-border rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-primary/50 transition-all"
          />
        </div>
        <button
          @click="refresh"
          class="p-2 hover:bg-muted rounded-md transition-colors text-muted-foreground"
          :class="{ 'animate-spin': loading }"
          :disabled="loading"
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
                    <h3 class="text-3xl font-bold">{{ totalEvents.toLocaleString() }}</h3>
                    <span class="text-xs text-muted-foreground mb-1">{{ searchQuery ? 'matching' : 'total' }}</span>
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
                    <h3 class="text-3xl font-bold text-green-500">{{ enabledCount.toLocaleString() }}</h3>
                    <span class="text-xs text-muted-foreground mb-1">{{ searchQuery ? 'matching' : 'total' }}</span>
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
                    <h3 class="text-3xl font-bold text-amber-500">{{ disabledCount.toLocaleString() }}</h3>
                    <span class="text-xs text-muted-foreground mb-1">{{ searchQuery ? 'matching' : 'total' }}</span>
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
            <tr v-if="loading && detections.length === 0" class="animate-pulse">
                <td colspan="6" class="h-32 text-center text-muted-foreground">Loading detections...</td>
            </tr>
            <tr v-else-if="!loading && detections.length === 0" class="h-32 text-center text-muted-foreground">
                <td colspan="6">No detections found.</td>
            </tr>
            <tr
              v-for="detection in detections"
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

      <!-- Pagination -->
      <div v-if="totalPages > 1" class="flex items-center justify-between px-6 py-4 border-t border-border bg-muted/20">
        <div class="text-sm text-muted-foreground">
          Page {{ currentPage }} of {{ totalPages.toLocaleString() }}
          <span class="ml-2">({{ totalEvents.toLocaleString() }} total)</span>
        </div>
        <div class="flex items-center gap-1">
          <button
            @click="firstPage"
            :disabled="!hasPrevPage || loading"
            class="p-2 hover:bg-muted rounded-md transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            title="First page"
          >
            <ChevronsLeft class="h-4 w-4" />
          </button>
          <button
            @click="prevPage"
            :disabled="!hasPrevPage || loading"
            class="p-2 hover:bg-muted rounded-md transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            title="Previous page"
          >
            <ChevronLeft class="h-4 w-4" />
          </button>
          <span class="px-3 py-1 text-sm font-medium">{{ currentPage }}</span>
          <button
            @click="nextPage"
            :disabled="!hasNextPage || loading"
            class="p-2 hover:bg-muted rounded-md transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            title="Next page"
          >
            <ChevronRight class="h-4 w-4" />
          </button>
        </div>
      </div>
    </div>
  </div>
</template>
