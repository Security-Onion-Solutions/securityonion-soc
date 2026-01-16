<script setup lang="ts">
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

import { computed } from 'vue'
import { Pie, Doughnut } from 'vue-chartjs'
import {
    Chart as ChartJS,
    ArcElement,
    Tooltip,
    Legend
} from 'chart.js'
import type { PieWidgetData } from '../../../types/dashboard'
import { CHART_COLORS } from '../../../types/dashboard'
import { useTheme } from '../../../composables/useTheme'

ChartJS.register(ArcElement, Tooltip, Legend)

const { isDarkMode } = useTheme()

const props = defineProps<{
    data: PieWidgetData
}>()

const chartData = computed(() => ({
    labels: props.data.data.map(d => d.label),
    datasets: [{
        data: props.data.data.map(d => d.value),
        backgroundColor: props.data.data.map((d, i) => d.color || CHART_COLORS[i % CHART_COLORS.length]),
        borderWidth: 0,
        hoverOffset: 4
    }]
}))

const chartOptions = computed(() => {
    const textColor = isDarkMode.value ? '#e5e7eb' : '#374151'

    return {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                display: true,
                position: 'right' as const,
                labels: {
                    boxWidth: 12,
                    padding: 8,
                    font: {
                        size: 11
                    },
                    color: textColor
                }
            },
            tooltip: {
                callbacks: {
                    label: (context: any) => {
                        const value = context.raw as number
                        const total = context.dataset.data.reduce((a: number, b: number) => a + b, 0)
                        const percentage = ((value / total) * 100).toFixed(1)
                        return `${context.label}: ${value.toLocaleString()} (${percentage}%)`
                    }
                }
            }
        }
    }
})

const ChartComponent = computed(() => props.data.type === 'donut' ? Doughnut : Pie)
</script>

<template>
    <div class="h-full w-full min-h-[180px]">
        <component
            :is="ChartComponent"
            :data="chartData"
            :options="chartOptions"
        />
    </div>
</template>
