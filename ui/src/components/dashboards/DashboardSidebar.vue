<script setup lang="ts">
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

import { LayoutDashboard, Users, Plus, Star } from 'lucide-vue-next'
import { cn } from '../../lib/utils'
import type { DashboardListItem } from '../../types/dashboard'

const props = defineProps<{
    dashboards: DashboardListItem[]
    selectedId: string | null
}>()

const emit = defineEmits<{
    'select': [id: string]
    'create': []
}>()

const myDashboards = props.dashboards.filter(d => !d.isShared)
const sharedDashboards = props.dashboards.filter(d => d.isShared)
</script>

<template>
    <div class="w-64 border-r border-border bg-card/50 flex flex-col h-full">
        <!-- Header -->
        <div class="p-4 border-b border-border">
            <div class="flex items-center gap-2 text-lg font-semibold">
                <LayoutDashboard class="h-5 w-5 text-primary" />
                Dashboards
            </div>
        </div>

        <!-- Dashboard List -->
        <div class="flex-1 overflow-y-auto p-2">
            <!-- My Dashboards -->
            <div class="mb-4">
                <div class="px-2 py-1 text-xs font-medium text-muted-foreground uppercase tracking-wider">
                    My Dashboards
                </div>
                <div class="space-y-1 mt-1">
                    <button
                        v-for="dashboard in myDashboards"
                        :key="dashboard.id"
                        @click="emit('select', dashboard.id)"
                        :class="cn(
                            'w-full flex items-center gap-2 px-3 py-2 rounded-md text-sm transition-colors text-left',
                            selectedId === dashboard.id
                                ? 'bg-primary text-primary-foreground'
                                : 'text-foreground hover:bg-muted'
                        )"
                    >
                        <Star
                            v-if="dashboard.isDefault"
                            class="h-4 w-4 flex-shrink-0"
                            :class="selectedId === dashboard.id ? 'text-primary-foreground' : 'text-amber-500'"
                        />
                        <span class="truncate">{{ dashboard.name }}</span>
                        <span
                            :class="cn(
                                'ml-auto text-xs',
                                selectedId === dashboard.id ? 'text-primary-foreground/70' : 'text-muted-foreground'
                            )"
                        >
                            {{ dashboard.widgetCount }}
                        </span>
                    </button>
                </div>
            </div>

            <!-- Shared Dashboards -->
            <div v-if="sharedDashboards.length > 0" class="mb-4">
                <div class="px-2 py-1 text-xs font-medium text-muted-foreground uppercase tracking-wider flex items-center gap-1">
                    <Users class="h-3 w-3" />
                    Shared
                </div>
                <div class="space-y-1 mt-1">
                    <button
                        v-for="dashboard in sharedDashboards"
                        :key="dashboard.id"
                        @click="emit('select', dashboard.id)"
                        :class="cn(
                            'w-full flex items-center gap-2 px-3 py-2 rounded-md text-sm transition-colors text-left',
                            selectedId === dashboard.id
                                ? 'bg-primary text-primary-foreground'
                                : 'text-foreground hover:bg-muted'
                        )"
                    >
                        <span class="truncate">{{ dashboard.name }}</span>
                        <span
                            :class="cn(
                                'ml-auto text-xs',
                                selectedId === dashboard.id ? 'text-primary-foreground/70' : 'text-muted-foreground'
                            )"
                        >
                            {{ dashboard.widgetCount }}
                        </span>
                    </button>
                </div>
            </div>
        </div>

        <!-- Create Button -->
        <div class="p-3 border-t border-border">
            <button
                @click="emit('create')"
                class="w-full flex items-center justify-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90 transition-colors"
            >
                <Plus class="h-4 w-4" />
                New Dashboard
            </button>
        </div>
    </div>
</template>
