<script setup lang="ts">
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

import { computed } from 'vue'
import { Bar } from 'vue-chartjs'
import {
    Chart as ChartJS,
    CategoryScale,
    LinearScale,
    BarElement,
    Tooltip,
    Legend
} from 'chart.js'
import type { BarWidgetData } from '../../../types/dashboard'
import { CHART_COLORS } from '../../../types/dashboard'

ChartJS.register(CategoryScale, LinearScale, BarElement, Tooltip, Legend)

const props = defineProps<{
    data: BarWidgetData
}>()

const isHorizontal = computed(() => props.data.orientation !== 'vertical')

const chartData = computed(() => ({
    labels: props.data.data.map(d => d.label),
    datasets: [{
        data: props.data.data.map(d => d.value),
        backgroundColor: props.data.data.map((d, i) => d.color || CHART_COLORS[i % CHART_COLORS.length]),
        borderWidth: 0,
        borderRadius: 4,
        barThickness: 20
    }]
}))

const chartOptions = computed(() => ({
    responsive: true,
    maintainAspectRatio: false,
    indexAxis: isHorizontal.value ? 'y' as const : 'x' as const,
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
            display: !isHorizontal.value,
            grid: {
                display: false
            },
            ticks: {
                color: 'hsl(var(--muted-foreground))',
                font: {
                    size: 10
                }
            }
        },
        y: {
            display: isHorizontal.value,
            grid: {
                display: false
            },
            ticks: {
                color: 'hsl(var(--muted-foreground))',
                font: {
                    size: 10
                }
            }
        }
    }
}))
</script>

<template>
    <div class="h-full w-full min-h-[180px]">
        <Bar
            :data="chartData"
            :options="chartOptions"
        />
    </div>
</template>
