<script setup lang="ts">
import { onMounted, ref, watch, computed } from 'vue'
import { useConfig } from '../../composables/useConfig'
import { useGridMembers } from '../../composables/useGridMembers'
import ConfigCategory from '../../components/config/ConfigCategory.vue'
import ConfigEditor from '../../components/config/ConfigEditor.vue'
import {
    Settings,
    Search,
    RefreshCw,
    AlertTriangle,
    Sliders,
    Check
} from 'lucide-vue-next'
import { cn } from '../../lib/utils'

const {
    categories,
    changedModules,
    advanced,
    loading,
    error,
    totalSettings,
    totalCustomized,
    selectedSetting,
    selectedSettingId,
    fetchCategories,
    toggleAdvanced,
    syncAll,
    syncModule,
    selectSetting,
    loadLocalSettings,
    saveLocalSettings
} = useConfig()

const { fetchMembers, accepted: gridNodes } = useGridMembers()

const searchQuery = ref('')
const syncing = ref(false)
const syncingModule = ref<string | null>(null)

onMounted(async () => {
    loadLocalSettings()
    await Promise.all([
        fetchCategories(),
        fetchMembers()
    ])
})

watch(advanced, () => {
    saveLocalSettings()
})

const handleToggleAdvanced = async () => {
    await toggleAdvanced()
}

const handleSyncAll = async () => {
    syncing.value = true
    try {
        await syncAll()
    } catch (e) {
        console.error('Sync failed:', e)
    } finally {
        syncing.value = false
    }
}

const handleSyncModule = async (module: string) => {
    syncingModule.value = module
    try {
        await syncModule(module)
    } catch (e) {
        console.error('Module sync failed:', e)
    } finally {
        syncingModule.value = null
    }
}

const handleRefresh = async () => {
    await fetchCategories()
}

const filteredCategories = computed(() => {
    if (!searchQuery.value) {
        return categories.value
    }
    const query = searchQuery.value.toLowerCase()
    return categories.value.filter(cat =>
        cat.id.toLowerCase().includes(query) ||
        cat.name.toLowerCase().includes(query)
    )
})

const closeEditor = () => {
    selectSetting(null)
}
</script>

<template>
    <div class="space-y-6 animate-in fade-in duration-500">
        <!-- Header -->
        <div class="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
            <div>
                <h2 class="text-3xl font-bold tracking-tight text-primary flex items-center gap-2">
                    <Settings class="h-8 w-8" />
                    Configuration
                </h2>
                <p class="text-muted-foreground">
                    Manage system settings across your grid.
                </p>
            </div>
            <div class="flex items-center gap-2">
                <!-- Search -->
                <div class="relative w-64">
                    <Search class="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                    <input
                        v-model="searchQuery"
                        type="text"
                        placeholder="Search categories..."
                        class="w-full pl-9 pr-4 py-2 bg-card border border-border rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-primary/50 transition-all"
                    />
                </div>

                <!-- Advanced Toggle -->
                <button
                    @click="handleToggleAdvanced"
                    :class="cn(
                        'flex items-center gap-2 px-3 py-2 rounded-md text-sm font-medium transition-colors',
                        advanced
                            ? 'bg-primary text-primary-foreground'
                            : 'bg-muted text-muted-foreground hover:bg-muted/80'
                    )"
                >
                    <Sliders class="h-4 w-4" />
                    Advanced
                </button>

                <!-- Refresh -->
                <button
                    @click="handleRefresh"
                    class="p-2 rounded-md hover:bg-muted text-muted-foreground hover:text-foreground transition-colors"
                    :class="{ 'animate-spin': loading }"
                >
                    <RefreshCw class="h-5 w-5" />
                </button>
            </div>
        </div>

        <!-- Error State -->
        <div v-if="error" class="p-4 rounded-md bg-destructive/15 text-destructive flex items-center gap-2">
            <AlertTriangle class="h-5 w-5" />
            <span class="text-sm font-medium">{{ error }}</span>
        </div>

        <!-- Sync Toolbar -->
        <div v-if="changedModules.length > 0" class="rounded-xl border border-amber-500/50 bg-amber-500/10 p-4">
            <div class="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
                <div class="flex items-center gap-2">
                    <AlertTriangle class="h-5 w-5 text-amber-500" />
                    <span class="text-sm font-medium">
                        Unsynchronized changes in:
                        <span class="font-bold">{{ changedModules.join(', ') }}</span>
                    </span>
                </div>
                <div class="flex items-center gap-2 flex-wrap">
                    <button
                        v-for="module in changedModules"
                        :key="module"
                        @click="handleSyncModule(module)"
                        :disabled="syncingModule === module"
                        class="px-3 py-1.5 rounded-md text-xs font-medium bg-amber-500/20 text-amber-700 hover:bg-amber-500/30 transition-colors disabled:opacity-50"
                    >
                        {{ syncingModule === module ? 'Syncing...' : `Sync ${module}` }}
                    </button>
                    <button
                        @click="handleSyncAll"
                        :disabled="syncing"
                        class="px-3 py-1.5 rounded-md text-xs font-medium bg-primary text-primary-foreground hover:bg-primary/90 transition-colors disabled:opacity-50"
                    >
                        {{ syncing ? 'Syncing All...' : 'Sync All' }}
                    </button>
                </div>
            </div>
        </div>

        <!-- Stats -->
        <div class="grid gap-4 md:grid-cols-3">
            <div class="p-6 rounded-xl border border-border bg-card shadow-sm">
                <div class="flex items-center gap-2 text-sm font-medium text-muted-foreground mb-2">
                    <Settings class="h-4 w-4" />
                    Total Settings
                </div>
                <div class="text-2xl font-bold">{{ totalSettings }}</div>
            </div>
            <div class="p-6 rounded-xl border border-border bg-card shadow-sm">
                <div class="flex items-center gap-2 text-sm font-medium text-muted-foreground mb-2">
                    <Sliders class="h-4 w-4 text-amber-500" />
                    Customized
                </div>
                <div class="text-2xl font-bold">{{ totalCustomized }}</div>
            </div>
            <div class="p-6 rounded-xl border border-border bg-card shadow-sm">
                <div class="flex items-center gap-2 text-sm font-medium text-muted-foreground mb-2">
                    <Check class="h-4 w-4 text-green-500" />
                    Categories
                </div>
                <div class="text-2xl font-bold">{{ categories.length }}</div>
            </div>
        </div>

        <!-- Main Content -->
        <div class="space-y-3">
            <!-- Loading Skeleton -->
            <div v-if="loading && categories.length === 0" class="space-y-3">
                <div v-for="i in 5" :key="i" class="animate-pulse">
                    <div class="h-16 rounded-xl bg-muted"></div>
                </div>
            </div>

            <!-- Empty State -->
            <div v-else-if="!loading && filteredCategories.length === 0" class="p-8 text-center text-muted-foreground">
                <Settings class="h-12 w-12 mx-auto mb-4 opacity-50" />
                <p>No configuration categories found.</p>
            </div>

            <!-- Categories -->
            <ConfigCategory
                v-else
                v-for="category in filteredCategories"
                :key="category.id"
                :category="category"
                :search-query="searchQuery"
            />
        </div>

        <!-- Slide-out Editor Panel -->
        <Teleport to="body">
            <Transition name="drawer">
                <div
                    v-if="selectedSettingId && selectedSetting"
                    class="fixed inset-0 z-50"
                >
                    <!-- Backdrop -->
                    <div
                        class="absolute inset-0 bg-black/50 backdrop-blur-sm"
                        @click="closeEditor"
                    />

                    <!-- Panel -->
                    <div class="absolute top-0 right-0 h-full w-full max-w-xl bg-background border-l border-border shadow-2xl overflow-y-auto">
                        <ConfigEditor
                            :setting="selectedSetting"
                            :nodes="gridNodes"
                            @close="closeEditor"
                        />
                    </div>
                </div>
            </Transition>
        </Teleport>
    </div>
</template>

<style scoped>
.drawer-enter-active,
.drawer-leave-active {
    transition: opacity 0.2s ease;
}

.drawer-enter-active > div:last-child,
.drawer-leave-active > div:last-child {
    transition: transform 0.2s ease;
}

.drawer-enter-from,
.drawer-leave-to {
    opacity: 0;
}

.drawer-enter-from > div:last-child,
.drawer-leave-to > div:last-child {
    transform: translateX(100%);
}
</style>
