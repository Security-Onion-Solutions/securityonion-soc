<script setup lang="ts">
import { Bot, PanelRight, Maximize2, X, RefreshCw } from 'lucide-vue-next'

defineProps<{
    isHealthy: boolean
    showSidebar: boolean
    loading?: boolean
}>()

const emit = defineEmits<{
    toggleSidebar: []
    openFull: []
    minimize: []
    refresh: []
}>()
</script>

<template>
    <div class="flex items-center justify-between px-3 py-2 border-b border-border bg-card shrink-0">
        <div class="flex items-center gap-2">
            <Bot class="h-4 w-4 text-primary" />
            <span class="text-sm font-medium">AI Assistant</span>
            <span
                class="w-2 h-2 rounded-full"
                :class="isHealthy ? 'bg-green-500' : 'bg-red-500'"
                :title="isHealthy ? 'Service healthy' : 'Service unavailable'"
            />
        </div>
        <div class="flex items-center gap-1">
            <button
                @click="emit('refresh')"
                class="p-1.5 rounded hover:bg-muted text-muted-foreground hover:text-foreground transition-colors"
                title="Refresh sessions"
                :disabled="loading"
            >
                <RefreshCw class="h-4 w-4" :class="{ 'animate-spin': loading }" />
            </button>
            <button
                @click="emit('toggleSidebar')"
                class="p-1.5 rounded hover:bg-muted transition-colors"
                :class="showSidebar ? 'text-primary' : 'text-muted-foreground hover:text-foreground'"
                title="Toggle session history"
            >
                <PanelRight class="h-4 w-4" />
            </button>
            <button
                @click="emit('openFull')"
                class="p-1.5 rounded hover:bg-muted text-muted-foreground hover:text-foreground transition-colors"
                title="Open in full page"
            >
                <Maximize2 class="h-4 w-4" />
            </button>
            <button
                @click="emit('minimize')"
                class="p-1.5 rounded hover:bg-muted text-muted-foreground hover:text-foreground transition-colors"
                title="Close panel"
            >
                <X class="h-4 w-4" />
            </button>
        </div>
    </div>
</template>
