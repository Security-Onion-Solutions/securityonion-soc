<script setup lang="ts">
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

import { computed } from 'vue'
import { Line } from 'vue-chartjs'
import {
    Chart as ChartJS,
    CategoryScale,
    LinearScale,
    PointElement,
    LineElement,
    Filler,
    Tooltip,
    Legend
} from 'chart.js'
import type { LineWidgetData } from '../../../types/dashboard'
import { CHART_COLORS } from '../../../types/dashboard'
import { useTheme } from '../../../composables/useTheme'

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Filler, Tooltip, Legend)

const { isDarkMode } = useTheme()

const props = defineProps<{
    data: LineWidgetData
}>()

const chartData = computed(() => ({
    labels: props.data.data.map(d => {
        // Format timestamp for display
        const date = new Date(d.timestamp)
        return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    }),
    datasets: [{
        data: props.data.data.map(d => d.value),
        borderColor: CHART_COLORS[0],
        backgroundColor: props.data.showArea !== false
            ? 'hsla(207, 90%, 54%, 0.1)'
            : 'transparent',
        fill: props.data.showArea !== false,
        tension: 0.3,
        pointRadius: 0,
        pointHoverRadius: 4,
        borderWidth: 2
    }]
}))

const chartOptions = computed(() => {
    const mutedTextColor = isDarkMode.value ? '#9ca3af' : '#6b7280'
    const gridColor = isDarkMode.value ? 'rgba(75, 85, 99, 0.3)' : 'rgba(209, 213, 219, 0.5)'

    return {
        responsive: true,
        maintainAspectRatio: false,
        interaction: {
            mode: 'index' as const,
            intersect: false
        },
        plugins: {
            legend: {
                display: false
            },
            tooltip: {
                callbacks: {
                    label: (context: any) => {
                        return context.raw.toLocaleString()
                    }
                }
            }
        },
        scales: {
            x: {
                display: true,
                grid: {
                    display: false
                },
                ticks: {
                    color: mutedTextColor,
                    font: {
                        size: 10
                    },
                    maxTicksLimit: 6
                }
            },
            y: {
                display: true,
                beginAtZero: true,
                grid: {
                    color: gridColor
                },
                ticks: {
                    color: mutedTextColor,
                    font: {
                        size: 10
                    },
                    callback: (value: number) => {
                        if (value >= 1000000) return (value / 1000000).toFixed(1) + 'M'
                        if (value >= 1000) return (value / 1000).toFixed(1) + 'K'
                        return value
                    }
                }
            }
        }
    }
})
</script>

<template>
    <div class="h-full w-full min-h-[180px]">
        <Line
            :data="chartData"
            :options="chartOptions"
        />
    </div>
</template>
