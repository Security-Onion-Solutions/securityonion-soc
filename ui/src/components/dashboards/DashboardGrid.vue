<script setup lang="ts">
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

import { cn } from '../../lib/utils'
import type { WidgetData } from '../../types/dashboard'
import DashboardWidget from './DashboardWidget.vue'

defineProps<{
    widgets: WidgetData[]
    editMode?: boolean
}>()

const emit = defineEmits<{
    'edit-widget': [widget: WidgetData]
    'delete-widget': [widget: WidgetData]
    'maximize-widget': [widget: WidgetData]
    'refresh-widget': [widget: WidgetData]
}>()
</script>

<template>
    <div
        :class="cn(
            'grid gap-4',
            'grid-cols-1 md:grid-cols-2 lg:grid-cols-4'
        )"
    >
        <DashboardWidget
            v-for="widget in widgets"
            :key="widget.id"
            :widget="widget"
            :edit-mode="editMode"
            @edit="emit('edit-widget', $event)"
            @delete="emit('delete-widget', $event)"
            @maximize="emit('maximize-widget', $event)"
            @refresh="emit('refresh-widget', $event)"
        />

        <!-- Empty State -->
        <div
            v-if="widgets.length === 0"
            class="col-span-full flex flex-col items-center justify-center py-16 text-muted-foreground"
        >
            <div class="text-lg font-medium mb-2">No widgets yet</div>
            <div class="text-sm">Click "Add Widget" to get started</div>
        </div>
    </div>
</template>
