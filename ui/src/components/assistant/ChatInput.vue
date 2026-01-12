<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import { Send, Loader2 } from 'lucide-vue-next'

const props = defineProps<{
    disabled?: boolean
    loading?: boolean
    placeholder?: string
}>()

const emit = defineEmits<{
    send: [message: string]
}>()

const inputText = ref('')
const textareaRef = ref<HTMLTextAreaElement | null>(null)

const canSend = computed(() => {
    return inputText.value.trim().length > 0 && !props.disabled && !props.loading
})

function handleSend() {
    if (!canSend.value) return
    emit('send', inputText.value.trim())
    inputText.value = ''
    resizeTextarea()
}

function handleKeydown(event: KeyboardEvent) {
    if (event.key === 'Enter' && !event.shiftKey) {
        event.preventDefault()
        handleSend()
    }
}

function resizeTextarea() {
    if (!textareaRef.value) return
    textareaRef.value.style.height = 'auto'
    textareaRef.value.style.height = Math.min(textareaRef.value.scrollHeight, 200) + 'px'
}

watch(inputText, () => {
    resizeTextarea()
})

function focus() {
    textareaRef.value?.focus()
}

defineExpose({ focus })
</script>

<template>
    <div class="flex items-end gap-3 p-4 bg-card border-t border-border">
        <div class="flex-1 relative">
            <textarea
                ref="textareaRef"
                v-model="inputText"
                :placeholder="placeholder || 'Type a message...'"
                :disabled="disabled || loading"
                rows="1"
                class="w-full px-4 py-3 bg-background border border-border rounded-xl text-sm text-foreground placeholder:text-muted-foreground resize-none focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary disabled:opacity-50 disabled:cursor-not-allowed"
                @keydown="handleKeydown"
            />
        </div>
        <button
            :disabled="!canSend"
            class="flex items-center justify-center h-11 w-11 rounded-xl bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed transition-colors shrink-0"
            @click="handleSend"
        >
            <Loader2 v-if="loading" class="h-5 w-5 animate-spin" />
            <Send v-else class="h-5 w-5" />
        </button>
    </div>
</template>
