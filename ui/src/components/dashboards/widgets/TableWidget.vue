<script setup lang="ts">
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

import { computed } from 'vue'
import { cn } from '../../../lib/utils'
import type { TableWidgetData } from '../../../types/dashboard'

const props = defineProps<{
    data: TableWidgetData
}>()

const displayRows = computed(() => {
    const maxRows = props.data.maxRows || 10
    return props.data.rows.slice(0, maxRows)
})

const formatCellValue = (value: any): string => {
    if (value === null || value === undefined) return '-'
    if (typeof value === 'number') return value.toLocaleString()
    if (typeof value === 'boolean') return value ? 'Yes' : 'No'
    return String(value)
}
</script>

<template>
    <div class="h-full w-full overflow-auto">
        <table class="w-full text-sm">
            <thead>
                <tr class="border-b border-border">
                    <th
                        v-for="col in data.columns"
                        :key="col.key"
                        :style="col.width ? { width: col.width } : {}"
                        class="px-3 py-2 text-left font-medium text-muted-foreground"
                    >
                        {{ col.label }}
                    </th>
                </tr>
            </thead>
            <tbody>
                <tr
                    v-for="(row, idx) in displayRows"
                    :key="idx"
                    :class="cn(
                        'border-b border-border/50 hover:bg-muted/50 transition-colors',
                        idx % 2 === 0 ? 'bg-transparent' : 'bg-muted/20'
                    )"
                >
                    <td
                        v-for="col in data.columns"
                        :key="col.key"
                        class="px-3 py-2 text-foreground"
                    >
                        {{ formatCellValue(row[col.key]) }}
                    </td>
                </tr>
                <tr v-if="displayRows.length === 0">
                    <td
                        :colspan="data.columns.length"
                        class="px-3 py-4 text-center text-muted-foreground"
                    >
                        No data available
                    </td>
                </tr>
            </tbody>
        </table>
        <div
            v-if="data.rows.length > (data.maxRows || 10)"
            class="px-3 py-2 text-xs text-muted-foreground border-t border-border"
        >
            Showing {{ displayRows.length }} of {{ data.rows.length }} rows
        </div>
    </div>
</template>
