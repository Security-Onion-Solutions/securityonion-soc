<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import { Settings, X, ChevronDown } from 'lucide-vue-next'
import type { ModelConfig } from '@/composables/useAssistant'

const props = defineProps<{
    modelValue: boolean
    currentModel: string
    availableModels: ModelConfig[]
    increaseContextLimit: boolean
    restoreLastActive: boolean
    alwaysApproveReadRequests: boolean
}>()

const emit = defineEmits<{
    'update:modelValue': [value: boolean]
    'update:currentModel': [value: string]
    'update:increaseContextLimit': [value: boolean]
    'update:restoreLastActive': [value: boolean]
    'update:alwaysApproveReadRequests': [value: boolean]
}>()

const isOpen = computed({
    get: () => props.modelValue,
    set: (value) => emit('update:modelValue', value)
})

const selectedModel = computed({
    get: () => props.currentModel,
    set: (value) => emit('update:currentModel', value)
})

const extendedContext = computed({
    get: () => props.increaseContextLimit,
    set: (value) => emit('update:increaseContextLimit', value)
})

const restoreLast = computed({
    get: () => props.restoreLastActive,
    set: (value) => emit('update:restoreLastActive', value)
})

const autoApprove = computed({
    get: () => props.alwaysApproveReadRequests,
    set: (value) => emit('update:alwaysApproveReadRequests', value)
})

const currentModelConfig = computed(() => {
    return props.availableModels.find(m => m.id === props.currentModel)
})
</script>

<template>
    <div v-if="isOpen" class="absolute bottom-full left-0 right-0 mb-2 mx-4 z-10">
        <div class="bg-card border border-border rounded-xl shadow-lg overflow-hidden">
            <!-- Header -->
            <div class="flex items-center justify-between px-4 py-3 border-b border-border bg-muted/30">
                <div class="flex items-center gap-2">
                    <Settings class="h-4 w-4 text-muted-foreground" />
                    <h3 class="text-sm font-semibold text-foreground">Settings</h3>
                </div>
                <button
                    class="p-1 rounded hover:bg-muted transition-colors text-muted-foreground hover:text-foreground"
                    @click="isOpen = false"
                >
                    <X class="h-4 w-4" />
                </button>
            </div>

            <!-- Settings Content -->
            <div class="p-4 space-y-4">
                <!-- Model Selection -->
                <div class="space-y-2">
                    <label class="text-sm font-medium text-foreground">Model</label>
                    <div class="relative">
                        <select
                            v-model="selectedModel"
                            class="w-full px-3 py-2 bg-background border border-border rounded-lg text-sm appearance-none cursor-pointer focus:outline-none focus:ring-2 focus:ring-primary/50"
                        >
                            <option
                                v-for="model in availableModels"
                                :key="model.id"
                                :value="model.id"
                            >
                                {{ model.name || model.id }}
                            </option>
                        </select>
                        <ChevronDown class="absolute right-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground pointer-events-none" />
                    </div>
                    <p v-if="currentModelConfig" class="text-xs text-muted-foreground">
                        Context: {{ currentModelConfig.contextLimitSmall.toLocaleString() }}
                        <span v-if="currentModelConfig.contextLimitLarge > currentModelConfig.contextLimitSmall">
                            / {{ currentModelConfig.contextLimitLarge.toLocaleString() }} tokens
                        </span>
                    </p>
                </div>

                <!-- Toggle Options -->
                <div class="space-y-3">
                    <!-- Extended Context -->
                    <label class="flex items-center justify-between gap-3 cursor-pointer">
                        <div>
                            <p class="text-sm font-medium text-foreground">Extended Context</p>
                            <p class="text-xs text-muted-foreground">Allow larger context window (uses more credits)</p>
                        </div>
                        <button
                            type="button"
                            role="switch"
                            :aria-checked="extendedContext"
                            class="relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-primary/50"
                            :class="extendedContext ? 'bg-primary' : 'bg-muted'"
                            @click="extendedContext = !extendedContext"
                        >
                            <span
                                class="pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out"
                                :class="extendedContext ? 'translate-x-5' : 'translate-x-0'"
                            />
                        </button>
                    </label>

                    <!-- Restore Last Active -->
                    <label class="flex items-center justify-between gap-3 cursor-pointer">
                        <div>
                            <p class="text-sm font-medium text-foreground">Restore Last Chat</p>
                            <p class="text-xs text-muted-foreground">Automatically load the last active chat on start</p>
                        </div>
                        <button
                            type="button"
                            role="switch"
                            :aria-checked="restoreLast"
                            class="relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-primary/50"
                            :class="restoreLast ? 'bg-primary' : 'bg-muted'"
                            @click="restoreLast = !restoreLast"
                        >
                            <span
                                class="pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out"
                                :class="restoreLast ? 'translate-x-5' : 'translate-x-0'"
                            />
                        </button>
                    </label>

                    <!-- Auto-Approve Read Requests -->
                    <label class="flex items-center justify-between gap-3 cursor-pointer">
                        <div>
                            <p class="text-sm font-medium text-foreground">Auto-Approve Read Tools</p>
                            <p class="text-xs text-muted-foreground">Automatically approve query tools (events, cases, detections)</p>
                        </div>
                        <button
                            type="button"
                            role="switch"
                            :aria-checked="autoApprove"
                            class="relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-primary/50"
                            :class="autoApprove ? 'bg-primary' : 'bg-muted'"
                            @click="autoApprove = !autoApprove"
                        >
                            <span
                                class="pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out"
                                :class="autoApprove ? 'translate-x-5' : 'translate-x-0'"
                            />
                        </button>
                    </label>
                </div>
            </div>
        </div>
    </div>
</template>
