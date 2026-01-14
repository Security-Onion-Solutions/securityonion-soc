<script setup lang="ts">
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

import { computed, ref, onMounted } from 'vue'
import type { SankeyWidgetData, SankeyLink } from '../../../types/dashboard'
import { CHART_COLORS } from '../../../types/dashboard'

const props = defineProps<{
    data: SankeyWidgetData
}>()

const containerRef = ref<HTMLDivElement | null>(null)
const width = ref(400)
const height = ref(250)

onMounted(() => {
    if (containerRef.value) {
        const rect = containerRef.value.getBoundingClientRect()
        width.value = rect.width || 400
        height.value = rect.height || 250
    }
})

// Layout calculations
const layout = computed(() => {
    const links = props.data.links
    const nodeWidth = 20
    const nodePadding = 8
    const marginX = 60
    const marginY = 15

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

    const totalSourceValue = Object.values(sourceTotals).reduce((a, b) => a + b, 0)
    const totalTargetValue = Object.values(targetTotals).reduce((a, b) => a + b, 0)

    // Available height for nodes (accounting for padding between nodes)
    const availableHeight = height.value - marginY * 2
    const sourceNodeCount = sourceNodes.length
    const targetNodeCount = targetNodes.length

    // Calculate total padding space needed
    const sourcePaddingTotal = (sourceNodeCount - 1) * nodePadding
    const targetPaddingTotal = (targetNodeCount - 1) * nodePadding

    // Available height for actual node bars
    const sourceBarHeight = availableHeight - sourcePaddingTotal
    const targetBarHeight = availableHeight - targetPaddingTotal

    // Calculate source node positions - scale to fit available space
    const sourceNodePositions: Record<string, { y: number; height: number; color: string }> = {}
    let sourceY = marginY

    sourceNodes.forEach((node, idx) => {
        // Proportional height based on value, scaled to fit
        const nodeHeight = Math.max(15, (sourceTotals[node] / totalSourceValue) * sourceBarHeight)
        sourceNodePositions[node] = {
            y: sourceY,
            height: nodeHeight,
            color: CHART_COLORS[idx % CHART_COLORS.length]
        }
        sourceY += nodeHeight + nodePadding
    })

    // Calculate target node positions - scale to fit available space
    const targetNodePositions: Record<string, { y: number; height: number; color: string }> = {}
    let targetY = marginY

    targetNodes.forEach((node, idx) => {
        const nodeHeight = Math.max(15, (targetTotals[node] / totalTargetValue) * targetBarHeight)
        targetNodePositions[node] = {
            y: targetY,
            height: nodeHeight,
            color: CHART_COLORS[(idx + sourceNodes.length) % CHART_COLORS.length]
        }
        targetY += nodeHeight + nodePadding
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
        const linkRatio = link.value / sourceTotals[link.source]
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
        <svg :width="width" :height="height" class="overflow-hidden">
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
