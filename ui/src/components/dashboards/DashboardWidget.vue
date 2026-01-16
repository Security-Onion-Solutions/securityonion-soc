<script setup lang="ts">
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

import { computed, ref } from 'vue'
import {
    MoreVertical,
    Maximize2,
    Settings,
    Trash2,
    RefreshCw,
    Loader2
} from 'lucide-vue-next'
import { cn } from '../../lib/utils'
import type { WidgetData, WidgetSize } from '../../types/dashboard'

// Widget Components
import CountWidget from './widgets/CountWidget.vue'
import PieWidget from './widgets/PieWidget.vue'
import BarWidget from './widgets/BarWidget.vue'
import LineWidget from './widgets/LineWidget.vue'
import TableWidget from './widgets/TableWidget.vue'
import MapWidget from './widgets/MapWidget.vue'

// Lazy load SankeyWidget to avoid bundling with mermaid's d3-sankey
import { defineAsyncComponent, h } from 'vue'
const SankeyWidget = defineAsyncComponent({
    loader: () => import('./widgets/SankeyWidget.vue'),
    loadingComponent: {
        render() {
            return h('div', { class: 'flex items-center justify-center h-full text-muted-foreground text-sm' }, 'Loading...')
        }
    },
    errorComponent: {
        render() {
            return h('div', { class: 'flex items-center justify-center h-full text-destructive text-sm' }, 'Failed to load chart')
        }
    },
    delay: 200,
    timeout: 10000
})

const props = defineProps<{
    widget: WidgetData
    editMode?: boolean
}>()

const emit = defineEmits<{
    'edit': [widget: WidgetData]
    'delete': [widget: WidgetData]
    'maximize': [widget: WidgetData]
    'refresh': [widget: WidgetData]
}>()

const showMenu = ref(false)
const loading = ref(false)

const widgetComponent = computed(() => {
    switch (props.widget.type) {
        case 'count': return CountWidget
        case 'pie':
        case 'donut': return PieWidget
        case 'bar': return BarWidget
        case 'line': return LineWidget
        case 'table': return TableWidget
        case 'sankey': return SankeyWidget
        case 'map': return MapWidget
        default: return null
    }
})

const sizeClasses = computed(() => {
    const size = props.widget.size as WidgetSize
    switch (size) {
        case 'sm': return 'col-span-1'
        case 'md': return 'col-span-1 md:col-span-2'
        case 'lg': return 'col-span-1 md:col-span-2 lg:col-span-4'
        case 'wide': return 'col-span-1 md:col-span-2 lg:col-span-4'
        default: return 'col-span-1'
    }
})

const heightClasses = computed(() => {
    const size = props.widget.size as WidgetSize
    switch (size) {
        case 'sm': return 'min-h-[100px]'
        case 'md': return 'min-h-[250px]'
        case 'lg': return 'min-h-[300px]'
        case 'wide': return 'min-h-[200px]'
        default: return 'min-h-[150px]'
    }
})

const handleRefresh = () => {
    loading.value = true
    emit('refresh', props.widget)
    // Simulate loading for mockup
    setTimeout(() => {
        loading.value = false
    }, 1000)
}
</script>

<template>
    <div
        :class="cn(
            'rounded-lg border border-border bg-card shadow-sm transition-all duration-200',
            sizeClasses,
            editMode && 'ring-2 ring-primary/50 cursor-move'
        )"
    >
        <!-- Header -->
        <div class="flex items-center justify-between px-4 py-3 border-b border-border">
            <h3 class="text-sm font-medium text-foreground truncate">
                {{ widget.name }}
            </h3>
            <div class="flex items-center gap-1">
                <button
                    v-if="loading"
                    class="p-1.5 text-muted-foreground"
                    disabled
                >
                    <Loader2 class="h-4 w-4 animate-spin" />
                </button>
                <button
                    v-else
                    @click="handleRefresh"
                    class="p-1.5 text-muted-foreground hover:text-foreground rounded transition-colors"
                    title="Refresh"
                >
                    <RefreshCw class="h-4 w-4" />
                </button>

                <!-- Dropdown Menu -->
                <div class="relative">
                    <button
                        @click="showMenu = !showMenu"
                        class="p-1.5 text-muted-foreground hover:text-foreground rounded transition-colors"
                    >
                        <MoreVertical class="h-4 w-4" />
                    </button>

                    <div
                        v-if="showMenu"
                        @click="showMenu = false"
                        class="fixed inset-0 z-40"
                    />

                    <div
                        v-if="showMenu"
                        class="absolute right-0 top-full mt-1 w-40 rounded-md border border-border bg-popover shadow-lg z-50"
                    >
                        <div class="py-1">
                            <button
                                @click="emit('maximize', widget); showMenu = false"
                                class="flex items-center gap-2 w-full px-3 py-2 text-sm text-foreground hover:bg-muted transition-colors"
                            >
                                <Maximize2 class="h-4 w-4" />
                                Maximize
                            </button>
                            <button
                                v-if="editMode"
                                @click="emit('edit', widget); showMenu = false"
                                class="flex items-center gap-2 w-full px-3 py-2 text-sm text-foreground hover:bg-muted transition-colors"
                            >
                                <Settings class="h-4 w-4" />
                                Edit
                            </button>
                            <button
                                v-if="editMode"
                                @click="emit('delete', widget); showMenu = false"
                                class="flex items-center gap-2 w-full px-3 py-2 text-sm text-red-500 hover:bg-muted transition-colors"
                            >
                                <Trash2 class="h-4 w-4" />
                                Delete
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Content -->
        <div :class="cn('p-4', heightClasses)">
            <component
                v-if="widgetComponent"
                :is="widgetComponent"
                :data="widget"
            />
            <div
                v-else
                class="flex items-center justify-center h-full text-muted-foreground"
            >
                Unknown widget type: {{ widget.type }}
            </div>
        </div>
    </div>
</template>
