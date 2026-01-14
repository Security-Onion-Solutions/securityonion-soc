<script setup lang="ts">
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

import { computed } from 'vue'
import { TrendingUp, TrendingDown, Minus } from 'lucide-vue-next'
import { cn } from '../../../lib/utils'
import type { CountWidgetData } from '../../../types/dashboard'

const props = defineProps<{
    data: CountWidgetData
}>()

const formattedValue = computed(() => {
    const val = props.data.value
    if (typeof val === 'number') {
        return val.toLocaleString()
    }
    return val
})

const trendIcon = computed(() => {
    switch (props.data.trend) {
        case 'up': return TrendingUp
        case 'down': return TrendingDown
        default: return Minus
    }
})

const trendClass = computed(() => {
    switch (props.data.trend) {
        case 'up': return 'text-green-500'
        case 'down': return 'text-red-500'
        default: return 'text-muted-foreground'
    }
})

const valueColorClass = computed(() => {
    switch (props.data.color) {
        case 'success': return 'text-green-500'
        case 'warning': return 'text-amber-500'
        case 'danger': return 'text-red-500'
        case 'info': return 'text-blue-500'
        default: return 'text-foreground'
    }
})
</script>

<template>
    <div class="flex flex-col justify-center h-full">
        <div :class="cn('text-3xl font-bold tracking-tight', valueColorClass)">
            {{ formattedValue }}
        </div>
        <div v-if="data.trend && data.trendPercent !== undefined" class="flex items-center gap-1 mt-1">
            <component :is="trendIcon" :class="cn('h-4 w-4', trendClass)" />
            <span :class="cn('text-sm', trendClass)">
                {{ data.trendPercent }}%
            </span>
            <span class="text-xs text-muted-foreground ml-1">vs last period</span>
        </div>
    </div>
</template>
