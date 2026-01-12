<script setup lang="ts">
import { computed } from 'vue'
import { useConfig, type ConfigCategory } from '../../composables/useConfig'
import ConfigTree from './ConfigTree.vue'
import {
    ChevronRight,
    ChevronDown,
    Loader2,
    Settings,
    AlertCircle
} from 'lucide-vue-next'
import { cn } from '../../lib/utils'

const props = defineProps<{
    category: ConfigCategory
    searchQuery?: string
}>()

const {
    toggleCategory,
    isCategoryExpanded,
    getCategoryState
} = useConfig()

const isExpanded = computed(() => isCategoryExpanded(props.category.id))
const state = computed(() => getCategoryState(props.category.id))

const handleToggle = () => {
    toggleCategory(props.category.id)
}

// Get icon based on category id
const getCategoryIcon = (id: string) => {
    const iconMap: Record<string, string> = {
        'elasticsearch': 'database',
        'zeek': 'eye',
        'suricata': 'shield',
        'firewall': 'lock',
        'soc': 'layout',
        'kratos': 'users',
        'strelka': 'file-search',
        'influxdb': 'bar-chart',
        'playbook': 'book-open',
        'salt': 'cpu',
        'telegraf': 'activity'
    }
    return iconMap[id] || 'settings'
}
</script>

<template>
    <div class="rounded-xl border border-border bg-card overflow-hidden shadow-sm transition-all">
        <!-- Header -->
        <div
            @click="handleToggle"
            :class="cn(
                'flex items-center justify-between px-4 py-3 cursor-pointer transition-colors',
                'hover:bg-muted/50',
                isExpanded && 'bg-muted/30 border-b border-border'
            )"
        >
            <div class="flex items-center gap-3">
                <!-- Expand Icon -->
                <div class="text-muted-foreground">
                    <ChevronDown v-if="isExpanded" class="h-5 w-5" />
                    <ChevronRight v-else class="h-5 w-5" />
                </div>

                <!-- Category Icon -->
                <div class="h-8 w-8 rounded-lg bg-primary/10 flex items-center justify-center text-primary">
                    <Settings class="h-4 w-4" />
                </div>

                <!-- Name -->
                <div>
                    <div class="font-medium">{{ category.name }}</div>
                    <div class="text-xs text-muted-foreground">
                        {{ category.settingsCount }} settings
                    </div>
                </div>
            </div>

            <!-- Right Side -->
            <div class="flex items-center gap-3">
                <!-- Loading Indicator -->
                <Loader2
                    v-if="state?.loading"
                    class="h-4 w-4 animate-spin text-muted-foreground"
                />

                <!-- Error Indicator -->
                <AlertCircle
                    v-if="state?.error"
                    class="h-4 w-4 text-destructive"
                    :title="state.error"
                />

                <!-- Customized Badge -->
                <span
                    v-if="category.customizedCount > 0"
                    class="px-2 py-0.5 rounded-full text-xs font-medium bg-amber-500/10 text-amber-600"
                >
                    {{ category.customizedCount }} customized
                </span>

                <!-- Advanced Badge -->
                <span
                    v-if="category.advanced"
                    class="px-2 py-0.5 rounded-full text-xs font-medium bg-purple-500/10 text-purple-600"
                >
                    Advanced
                </span>
            </div>
        </div>

        <!-- Expanded Content -->
        <div
            v-if="isExpanded"
            class="animate-in fade-in slide-in-from-top-2 duration-200"
        >
            <!-- Loading State -->
            <div v-if="state?.loading" class="p-4">
                <div class="space-y-2">
                    <div v-for="i in 3" :key="i" class="animate-pulse">
                        <div class="h-8 bg-muted rounded"></div>
                    </div>
                </div>
            </div>

            <!-- Error State -->
            <div v-else-if="state?.error" class="p-4">
                <div class="flex items-center gap-2 text-destructive text-sm">
                    <AlertCircle class="h-4 w-4" />
                    <span>{{ state.error }}</span>
                </div>
            </div>

            <!-- Tree View -->
            <div v-else-if="state?.hierarchy" class="p-2">
                <ConfigTree
                    :nodes="state.hierarchy"
                    :depth="0"
                    :search-query="searchQuery"
                />
            </div>
        </div>
    </div>
</template>
