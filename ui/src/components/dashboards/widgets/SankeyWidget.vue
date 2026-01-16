<script setup lang="ts">
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

import { computed, ref, onMounted, onUnmounted, watch } from 'vue'
import type { SankeyWidgetData, SankeyLink } from '../../../types/dashboard'
import { CHART_COLORS } from '../../../types/dashboard'

const props = defineProps<{
    data: SankeyWidgetData
}>()

const containerRef = ref<HTMLDivElement | null>(null)
const width = ref(400)
const height = ref(250)
let resizeObserver: ResizeObserver | null = null

function updateDimensions() {
    if (containerRef.value) {
        const rect = containerRef.value.getBoundingClientRect()
        if (rect.width > 0) width.value = rect.width
        if (rect.height > 0) height.value = rect.height
    }
}

onMounted(() => {
    updateDimensions()

    // Use ResizeObserver to handle dynamic container sizing
    if (containerRef.value && typeof ResizeObserver !== 'undefined') {
        resizeObserver = new ResizeObserver(() => {
            updateDimensions()
        })
        resizeObserver.observe(containerRef.value)
    }
})

onUnmounted(() => {
    if (resizeObserver) {
        resizeObserver.disconnect()
        resizeObserver = null
    }
})

// Check if we have valid data
const hasData = computed(() => {
    return props.data?.links && Array.isArray(props.data.links) && props.data.links.length > 0
})

// Layout calculations
const layout = computed(() => {
    // Return empty layout if no data
    if (!hasData.value) {
        return {
            sourceNodes: [],
            targetNodes: [],
            links: [],
            nodeWidth: 20
        }
    }

    const links = props.data.links
    const nodeWidth = 16
    const nodePadding = 4
    const marginX = 50
    const marginY = 10

    // Extract unique source and target nodes
    const sourceNodes = [...new Set(links.map(l => l.source))]
    const targetNodes = [...new Set(links.map(l => l.target))]

    // Calculate totals for each node
    const sourceTotals: Record<string, number> = {}
    const targetTotals: Record<string, number> = {}

    links.forEach(link => {
        sourceTotals[link.source] = (sourceTotals[link.source] || 0) + link.value
        targetTotals[link.target] = (targetTotals[link.target] || 0) + link.value
    })

    const totalSourceValue = Object.values(sourceTotals).reduce((a, b) => a + b, 0) || 1
    const totalTargetValue = Object.values(targetTotals).reduce((a, b) => a + b, 0) || 1

    // Available height for nodes (accounting for margins)
    const availableHeight = height.value - marginY * 2
    const sourceNodeCount = sourceNodes.length
    const targetNodeCount = targetNodes.length

    // Calculate total padding space needed
    const sourcePaddingTotal = Math.max(0, sourceNodeCount - 1) * nodePadding
    const targetPaddingTotal = Math.max(0, targetNodeCount - 1) * nodePadding

    // Height available for actual node bars (after padding)
    const sourceBarHeight = Math.max(0, availableHeight - sourcePaddingTotal)
    const targetBarHeight = Math.max(0, availableHeight - targetPaddingTotal)

    // Calculate source node positions - strictly fit within available space
    const sourceNodePositions: Record<string, { y: number; height: number; color: string }> = {}
    let sourceY = marginY

    sourceNodes.forEach((node, idx) => {
        // Proportional height that sums exactly to sourceBarHeight
        const nodeHeight = (sourceTotals[node] / totalSourceValue) * sourceBarHeight
        sourceNodePositions[node] = {
            y: sourceY,
            height: Math.max(2, nodeHeight), // minimum 2px for visibility
            color: CHART_COLORS[idx % CHART_COLORS.length]
        }
        sourceY += Math.max(2, nodeHeight) + nodePadding
    })

    // Calculate target node positions - strictly fit within available space
    const targetNodePositions: Record<string, { y: number; height: number; color: string }> = {}
    let targetY = marginY

    targetNodes.forEach((node, idx) => {
        const nodeHeight = (targetTotals[node] / totalTargetValue) * targetBarHeight
        targetNodePositions[node] = {
            y: targetY,
            height: Math.max(2, nodeHeight),
            color: CHART_COLORS[(idx + sourceNodes.length) % CHART_COLORS.length]
        }
        targetY += Math.max(2, nodeHeight) + nodePadding
    })

    // Build link paths
    const sourceOffsets: Record<string, number> = {}
    const targetOffsets: Record<string, number> = {}

    sourceNodes.forEach(node => { sourceOffsets[node] = 0 })
    targetNodes.forEach(node => { targetOffsets[node] = 0 })

    const linkPaths = links.map((link, idx) => {
        const sourcePos = sourceNodePositions[link.source]
        const targetPos = targetNodePositions[link.target]

        // Calculate link thickness proportional to the source node's height
        const sourceTotal = sourceTotals[link.source] || 1
        const linkRatio = link.value / sourceTotal
        const linkHeight = Math.max(3, sourcePos.height * linkRatio)

        const x1 = marginX + nodeWidth
        const y1 = sourcePos.y + sourceOffsets[link.source] + linkHeight / 2
        const x2 = width.value - marginX - nodeWidth
        const y2 = targetPos.y + targetOffsets[link.target] + linkHeight / 2

        // Update offsets for next link
        sourceOffsets[link.source] += linkHeight
        targetOffsets[link.target] += linkHeight

        // Create curved path
        const midX = (x1 + x2) / 2
        const path = `M ${x1} ${y1 - linkHeight/2}
                      C ${midX} ${y1 - linkHeight/2}, ${midX} ${y2 - linkHeight/2}, ${x2} ${y2 - linkHeight/2}
                      L ${x2} ${y2 + linkHeight/2}
                      C ${midX} ${y2 + linkHeight/2}, ${midX} ${y1 + linkHeight/2}, ${x1} ${y1 + linkHeight/2}
                      Z`

        return {
            path,
            color: link.color || sourcePos.color,
            value: link.value,
            source: link.source,
            target: link.target,
            opacity: 0.6
        }
    })

    return {
        sourceNodes: sourceNodes.map(node => ({
            name: node,
            x: marginX,
            ...sourceNodePositions[node],
            total: sourceTotals[node]
        })),
        targetNodes: targetNodes.map(node => ({
            name: node,
            x: width.value - marginX,
            ...targetNodePositions[node],
            total: targetTotals[node]
        })),
        links: linkPaths,
        nodeWidth
    }
})

const formatValue = (value: number): string => {
    if (value >= 1000000) return (value / 1000000).toFixed(1) + 'M'
    if (value >= 1000) return (value / 1000).toFixed(1) + 'K'
    return value.toString()
}

const hoveredLink = ref<number | null>(null)
</script>

<template>
    <div ref="containerRef" class="h-full w-full min-h-[200px] relative overflow-hidden">
        <!-- No data message -->
        <div v-if="!hasData" class="flex items-center justify-center h-full text-muted-foreground text-sm">
            No flow data available
        </div>

        <svg v-else :viewBox="`0 0 ${width} ${height}`" class="w-full h-full overflow-hidden" preserveAspectRatio="xMidYMid meet">
            <!-- Links -->
            <g class="links">
                <path
                    v-for="(link, idx) in layout.links"
                    :key="`link-${idx}`"
                    :d="link.path"
                    :fill="link.color"
                    :opacity="hoveredLink === null ? link.opacity : (hoveredLink === idx ? 0.8 : 0.3)"
                    class="transition-opacity duration-200 cursor-pointer"
                    @mouseenter="hoveredLink = idx"
                    @mouseleave="hoveredLink = null"
                >
                    <title>{{ link.source }} → {{ link.target }}: {{ formatValue(link.value) }}</title>
                </path>
            </g>

            <!-- Source Nodes -->
            <g class="source-nodes">
                <g v-for="node in layout.sourceNodes" :key="`source-${node.name}`">
                    <rect
                        :x="node.x - layout.nodeWidth"
                        :y="node.y"
                        :width="layout.nodeWidth"
                        :height="node.height"
                        :fill="node.color"
                        rx="2"
                    />
                    <text
                        :x="node.x - layout.nodeWidth - 6"
                        :y="node.y + node.height / 2"
                        text-anchor="end"
                        dominant-baseline="middle"
                        class="text-[10px] fill-foreground"
                    >
                        {{ node.name }}
                    </text>
                </g>
            </g>

            <!-- Target Nodes -->
            <g class="target-nodes">
                <g v-for="node in layout.targetNodes" :key="`target-${node.name}`">
                    <rect
                        :x="node.x"
                        :y="node.y"
                        :width="layout.nodeWidth"
                        :height="node.height"
                        :fill="node.color"
                        rx="2"
                    />
                    <text
                        :x="node.x + layout.nodeWidth + 6"
                        :y="node.y + node.height / 2"
                        text-anchor="start"
                        dominant-baseline="middle"
                        class="text-[10px] fill-foreground"
                    >
                        {{ node.name }}
                    </text>
                </g>
            </g>
        </svg>

        <!-- Tooltip -->
        <div
            v-if="hoveredLink !== null && layout.links[hoveredLink]"
            class="absolute top-2 right-2 bg-popover border border-border rounded px-2 py-1 text-xs shadow-lg"
        >
            <div class="font-medium">
                {{ layout.links[hoveredLink].source }} → {{ layout.links[hoveredLink].target }}
            </div>
            <div class="text-muted-foreground">
                {{ formatValue(layout.links[hoveredLink].value) }} events
            </div>
        </div>
    </div>
</template>
