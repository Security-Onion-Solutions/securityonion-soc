<script setup lang="ts">
import { ref, onMounted, watch, computed } from 'vue'
import { useDebounceFn, useVirtualList } from '@vueuse/core'
import { BookOpen, Search, Plus, RefreshCw, Globe, Users, Shield, ChevronDown } from 'lucide-vue-next'
import { cn } from '../lib/utils'
import { usePlaybook, type Playbook, type PlaybookStats } from '../composables/usePlaybook'
import PlaybookCard from '../components/playbook/PlaybookCard.vue'
import PlaybookEditor from '../components/playbook/PlaybookEditor.vue'

const { getPlaybooksPaginated, createPlaybook, updatePlaybook, deletePlaybook } = usePlaybook()

// Pagination settings
const PAGE_SIZE = 100

// State
const playbooks = ref<Playbook[]>([])
const loading = ref(true)
const loadingMore = ref(false)
const error = ref<string | null>(null)
const searchQuery = ref('')
const typeFilter = ref('all') // all, global, sigma, nids, yara
const sourceFilter = ref('all') // all, community, custom

// Pagination state
const offset = ref(0)
const total = ref(0)
const stats = ref<PlaybookStats>({ total: 0, community: 0, custom: 0, global: 0 })
const hasMore = computed(() => offset.value + playbooks.value.length < total.value)

// Editor state
const showEditor = ref(false)
const editingPlaybook = ref<Playbook | null>(null)

// Virtual list for efficient rendering
const { list: virtualList, containerProps, wrapperProps } = useVirtualList(
  playbooks,
  {
    itemHeight: 120,
    overscan: 5
  }
)

// Fetch playbooks with current filters
const fetchPlaybooks = async (append = false) => {
  if (append) {
    loadingMore.value = true
  } else {
    loading.value = true
    offset.value = 0
  }
  error.value = null

  try {
    const response = await getPlaybooksPaginated({
      search: searchQuery.value || undefined,
      type: typeFilter.value !== 'all' ? typeFilter.value : undefined,
      source: sourceFilter.value !== 'all' ? sourceFilter.value : undefined,
      limit: PAGE_SIZE,
      offset: append ? offset.value + PAGE_SIZE : 0
    })

    if (append) {
      playbooks.value = [...playbooks.value, ...response.playbooks]
      offset.value += PAGE_SIZE
    } else {
      playbooks.value = response.playbooks
      offset.value = 0
    }
    total.value = response.total
    stats.value = response.stats
  } catch (e: any) {
    console.error('[Playbooks] Fetch error:', e)
    error.value = e.message || 'Failed to fetch playbooks'
  } finally {
    loading.value = false
    loadingMore.value = false
  }
}

// Load more playbooks
const loadMore = () => {
  if (!loadingMore.value && hasMore.value) {
    fetchPlaybooks(true)
  }
}

// Debounced search - wait 300ms after user stops typing
const debouncedFetch = useDebounceFn(() => {
  fetchPlaybooks()
}, 300)

// Watch for filter changes
watch([typeFilter, sourceFilter], () => {
  fetchPlaybooks()
})

// Watch for search changes (debounced)
watch(searchQuery, () => {
  debouncedFetch()
})

// Create new playbook
const handleCreate = () => {
  editingPlaybook.value = null
  showEditor.value = true
}

// Edit playbook
const handleEdit = (playbook: Playbook) => {
  editingPlaybook.value = playbook
  showEditor.value = true
}

// Duplicate playbook
const handleDuplicate = async (playbook: Playbook) => {
  const duplicate: Playbook = {
    name: `${playbook.name} (Copy)`,
    description: playbook.description,
    detection_id: playbook.detection_id,
    detection_category: playbook.detection_category,
    detection_type: playbook.detection_type,
    is_global: playbook.is_global,
    contributors: playbook.contributors ? [...playbook.contributors] : [],
    questions: playbook.questions ? playbook.questions.map(q => ({ ...q })) : []
  }
  editingPlaybook.value = duplicate
  showEditor.value = true
}

// Save playbook (create or update)
const handleSave = async (playbook: Playbook) => {
  try {
    if (playbook.id) {
      await updatePlaybook(playbook)
    } else {
      await createPlaybook(playbook)
    }
    showEditor.value = false
    editingPlaybook.value = null
    await fetchPlaybooks()
  } catch (e: any) {
    console.error('[Playbooks] Save error:', e)
    error.value = e.message || 'Failed to save playbook'
  }
}

// Delete playbook
const handleDelete = async (playbook: Playbook) => {
  if (!playbook.id) return
  if (!confirm(`Are you sure you want to delete "${playbook.name}"?`)) return

  try {
    await deletePlaybook(playbook.id)
    await fetchPlaybooks()
  } catch (e: any) {
    console.error('[Playbooks] Delete error:', e)
    error.value = e.message || 'Failed to delete playbook'
  }
}

onMounted(() => {
  fetchPlaybooks()
})
</script>

<template>
  <div class="space-y-6 animate-in fade-in duration-500">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h2 class="text-3xl font-bold tracking-tight">Playbooks</h2>
        <p class="text-muted-foreground">Manage investigation playbooks for guided analysis.</p>
      </div>
      <div class="flex items-center gap-4">
        <!-- Type Filter -->
        <div class="flex items-center bg-muted rounded-lg p-1">
          <button
            v-for="type in ['all', 'global', 'sigma', 'nids', 'yara']"
            :key="type"
            @click="typeFilter = type"
            :class="cn(
              'px-3 py-1.5 rounded-md text-xs font-medium capitalize transition-all',
              typeFilter === type
                ? 'bg-background text-foreground shadow-sm'
                : 'text-muted-foreground hover:text-foreground'
            )"
          >
            {{ type === 'nids' ? 'NIDS' : type }}
          </button>
        </div>

        <!-- Source Filter -->
        <div class="flex items-center bg-muted rounded-lg p-1">
          <button
            v-for="source in ['all', 'community', 'custom']"
            :key="source"
            @click="sourceFilter = source"
            :class="cn(
              'px-3 py-1.5 rounded-md text-xs font-medium capitalize transition-all',
              sourceFilter === source
                ? 'bg-background text-foreground shadow-sm'
                : 'text-muted-foreground hover:text-foreground'
            )"
          >
            {{ source }}
          </button>
        </div>

        <!-- Search -->
        <div class="relative w-64">
          <Search class="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
          <input
            v-model="searchQuery"
            type="search"
            placeholder="Search playbooks..."
            class="w-full bg-background border border-border rounded-md pl-9 pr-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary/50"
          />
        </div>

        <!-- Refresh -->
        <button
          @click="fetchPlaybooks()"
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
          Create Playbook
        </button>
      </div>
    </div>

    <!-- Stats Cards -->
    <div class="grid gap-4 md:grid-cols-4">
      <div class="p-6 rounded-xl border border-border bg-card shadow-sm">
        <div class="flex items-center gap-2 text-sm font-medium text-muted-foreground mb-2">
          <BookOpen class="h-4 w-4" />
          Total Playbooks
        </div>
        <div class="text-2xl font-bold">{{ stats.total.toLocaleString() }}</div>
      </div>
      <div class="p-6 rounded-xl border border-border bg-card shadow-sm">
        <div class="flex items-center gap-2 text-sm font-medium text-muted-foreground mb-2">
          <Users class="h-4 w-4 text-blue-500" />
          Community
        </div>
        <div class="text-2xl font-bold">{{ stats.community.toLocaleString() }}</div>
      </div>
      <div class="p-6 rounded-xl border border-border bg-card shadow-sm">
        <div class="flex items-center gap-2 text-sm font-medium text-muted-foreground mb-2">
          <Shield class="h-4 w-4 text-cyan-500" />
          Custom
        </div>
        <div class="text-2xl font-bold">{{ stats.custom.toLocaleString() }}</div>
      </div>
      <div class="p-6 rounded-xl border border-border bg-card shadow-sm">
        <div class="flex items-center gap-2 text-sm font-medium text-muted-foreground mb-2">
          <Globe class="h-4 w-4 text-green-500" />
          Global
        </div>
        <div class="text-2xl font-bold">{{ stats.global.toLocaleString() }}</div>
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
          </div>
        </div>
      </div>
    </div>

    <!-- Playbooks List - Virtual Scrolling -->
    <div v-else-if="playbooks.length > 0">
      <p class="text-sm text-muted-foreground mb-4">
        Showing {{ playbooks.length.toLocaleString() }} of {{ total.toLocaleString() }} playbooks
      </p>
      <div
        v-bind="containerProps"
        class="h-[calc(100vh-400px)] min-h-[400px] overflow-auto"
      >
        <div v-bind="wrapperProps" class="space-y-4">
          <PlaybookCard
            v-for="{ data: playbook, index } in virtualList"
            :key="playbook.id || `${playbook.name}-${index}`"
            :playbook="playbook"
            @edit="handleEdit(playbook)"
            @delete="handleDelete(playbook)"
            @duplicate="handleDuplicate(playbook)"
          />
        </div>
      </div>

      <!-- Load More Button -->
      <div v-if="hasMore" class="mt-4 text-center">
        <button
          @click="loadMore"
          :disabled="loadingMore"
          class="inline-flex items-center gap-2 px-6 py-2 border border-border rounded-md hover:bg-muted transition-colors text-sm font-medium"
        >
          <RefreshCw v-if="loadingMore" class="h-4 w-4 animate-spin" />
          <ChevronDown v-else class="h-4 w-4" />
          {{ loadingMore ? 'Loading...' : `Load More (${(total - playbooks.length).toLocaleString()} remaining)` }}
        </button>
      </div>
    </div>

    <!-- Empty State -->
    <div v-else class="text-center py-16">
      <BookOpen class="h-12 w-12 text-muted-foreground/50 mx-auto mb-4" />
      <h3 class="text-lg font-medium text-foreground mb-1">No playbooks found</h3>
      <p class="text-sm text-muted-foreground mb-4">
        {{ searchQuery || typeFilter !== 'all' || sourceFilter !== 'all'
          ? 'Try adjusting your filters or search query.'
          : 'Create a playbook to get started with guided analysis.' }}
      </p>
      <button
        v-if="!searchQuery && typeFilter === 'all' && sourceFilter === 'all'"
        @click="handleCreate"
        class="inline-flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 transition-colors font-medium"
      >
        <Plus class="h-4 w-4" />
        Create Playbook
      </button>
    </div>

    <!-- Editor Dialog -->
    <PlaybookEditor
      v-if="showEditor"
      :playbook="editingPlaybook"
      @save="handleSave"
      @cancel="showEditor = false"
    />
  </div>
</template>
