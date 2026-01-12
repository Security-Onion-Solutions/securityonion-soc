<script setup lang="ts">
import { computed } from 'vue'
import { Coins, FileText, AlertTriangle, Minimize2 } from 'lucide-vue-next'

const props = defineProps<{
    creditsRemaining: number
    creditsUsed: number
    contextLength: number
    contextLimit: number
    lowBalanceThreshold?: number
    thresholdColorRatioLow?: number
    thresholdColorRatioMed?: number
}>()

const emit = defineEmits<{
    compressContext: []
}>()

const formatNumber = (num: number): string => {
    if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M'
    if (num >= 1000) return (num / 1000).toFixed(1) + 'K'
    return num.toString()
}

const contextPercentage = computed(() => {
    if (props.contextLimit === 0) return 0
    return Math.round((props.contextLength / props.contextLimit) * 100)
})

const isLowBalance = computed(() => {
    return props.creditsRemaining <= (props.lowBalanceThreshold ?? 100)
})

const contextColorClass = computed(() => {
    const ratioLow = props.thresholdColorRatioLow ?? 0.5
    const ratioMed = props.thresholdColorRatioMed ?? 0.75
    const ratio = props.contextLength / props.contextLimit

    if (ratio >= 1) return 'text-red-500'
    if (ratio >= ratioMed) return 'text-amber-500'
    if (ratio >= ratioLow) return 'text-amber-400'
    return 'text-green-500'
})

const showCompressButton = computed(() => {
    return props.contextLength > props.contextLimit * 0.5
})
</script>

<template>
    <div class="flex items-center gap-4 text-xs text-muted-foreground">
        <!-- Credits -->
        <div class="flex items-center gap-1.5" :class="isLowBalance ? 'text-amber-500' : ''">
            <Coins class="h-3.5 w-3.5" />
            <span class="font-medium">{{ formatNumber(creditsRemaining) }}</span>
            <span class="hidden sm:inline">credits</span>
            <AlertTriangle v-if="isLowBalance" class="h-3 w-3 text-amber-500" />
        </div>

        <!-- Credits Used (this session) -->
        <div v-if="creditsUsed > 0" class="flex items-center gap-1.5 text-muted-foreground/70">
            <span>-{{ formatNumber(creditsUsed) }}</span>
            <span class="hidden sm:inline">used</span>
        </div>

        <!-- Divider -->
        <div class="h-3 w-px bg-border" />

        <!-- Context Length -->
        <div class="flex items-center gap-1.5" :class="contextColorClass">
            <FileText class="h-3.5 w-3.5" />
            <span class="font-medium">{{ formatNumber(contextLength) }}</span>
            <span class="text-muted-foreground">/</span>
            <span class="text-muted-foreground">{{ formatNumber(contextLimit) }}</span>
            <span class="hidden sm:inline text-muted-foreground">tokens</span>
            <span class="text-muted-foreground">({{ contextPercentage }}%)</span>
        </div>

        <!-- Compress Button -->
        <button
            v-if="showCompressButton"
            class="flex items-center gap-1 px-2 py-0.5 rounded text-xs hover:bg-muted transition-colors"
            :class="contextPercentage >= 75 ? 'text-amber-500 hover:text-amber-400' : 'text-muted-foreground hover:text-foreground'"
            title="Compress context to free up space"
            @click="emit('compressContext')"
        >
            <Minimize2 class="h-3 w-3" />
            <span class="hidden sm:inline">Compress</span>
        </button>
    </div>
</template>
