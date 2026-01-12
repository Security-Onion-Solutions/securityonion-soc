<script setup lang="ts">
import { computed } from 'vue'
import { User, Bot, Loader2 } from 'lucide-vue-next'
import { marked } from 'marked'
import DOMPurify from 'dompurify'
import { formatRelativeTime } from '@/composables/useFormatters'
import type { Message, ToolUse } from '@/composables/useAssistant'
import ToolUseCard from './ToolUseCard.vue'

const props = defineProps<{
    message: Message
    isStreaming?: boolean
}>()

const emit = defineEmits<{
    approveTool: [toolUse: ToolUse]
    rejectTool: [toolUse: ToolUse]
    choiceClick: [choice: string]
}>()

const isUser = computed(() => props.message.role === 'user')
const isAssistant = computed(() => props.message.role === 'assistant')

// Choice button regex
const CHOICE_MARKER_REGEX = /\[\[CHOICE\]\]([\s\S]*?)\[\[\/CHOICE\]\]/g

function escapeHtml(str: string): string {
    return String(str).replace(/[&<>"']/g, (char) => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;',
    }[char] || char))
}

function stripNewlines(text: string): string {
    if (typeof text !== 'string') return text
    return text.replace(/^\s*\n+/, '').replace(/\n+\s*$/, '')
}

function applyChoiceButtons(text: string): string {
    if (!text || typeof text !== 'string') return text

    return text.replace(CHOICE_MARKER_REGEX, (_fullMatch, rawLabel) => {
        const label = stripNewlines(rawLabel).trim()
        if (!label) return ''

        const safeChoiceAttr = escapeHtml(label)
        return `<button type="button" class="assistant-choice-btn inline-flex items-center px-3 py-1.5 m-1 text-sm font-medium rounded-lg bg-primary/10 text-primary border border-primary/20 hover:bg-primary/20 transition-colors cursor-pointer" data-choice="${safeChoiceAttr}">${label}</button>`
    })
}

const formattedContent = computed(() => {
    let content = props.message.content || ''

    // Apply choice buttons before markdown
    content = applyChoiceButtons(content)

    // Configure marked for security
    marked.setOptions({
        breaks: true,
        gfm: true,
    })

    // Parse markdown
    const html = marked.parse(content) as string

    // Sanitize HTML
    return DOMPurify.sanitize(html, {
        ADD_ATTR: ['data-choice'],
        ADD_TAGS: ['button'],
    })
})

const relativeTime = computed(() => formatRelativeTime(props.message.timestamp))

const toolUses = computed(() => props.message.toolUses || [])

function handleContentClick(event: MouseEvent) {
    const target = event.target as HTMLElement
    const btn = target.closest('button[data-choice]')
    if (btn) {
        event.preventDefault()
        const choice = btn.getAttribute('data-choice') || ''
        if (choice.trim()) {
            emit('choiceClick', choice)
        }
    }
}
</script>

<template>
    <div
        class="flex gap-3 px-4 py-3"
        :class="isUser ? 'flex-row-reverse' : ''"
    >
        <!-- Avatar -->
        <div
            class="flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center"
            :class="isUser ? 'bg-primary/10 text-primary' : 'bg-muted text-muted-foreground'"
        >
            <User v-if="isUser" class="h-4 w-4" />
            <Bot v-else class="h-4 w-4" />
        </div>

        <!-- Message Content -->
        <div
            class="flex flex-col max-w-[80%] min-w-0"
            :class="isUser ? 'items-end' : 'items-start'"
        >
            <!-- Message Bubble -->
            <div
                class="rounded-2xl px-4 py-2.5"
                :class="isUser
                    ? 'bg-primary text-primary-foreground rounded-br-md'
                    : 'bg-muted text-foreground rounded-bl-md'"
            >
                <!-- Content -->
                <div
                    v-if="message.content"
                    class="prose prose-sm dark:prose-invert max-w-none break-words"
                    :class="isUser ? 'prose-invert' : ''"
                    @click="handleContentClick"
                    v-html="formattedContent"
                />

                <!-- Streaming indicator -->
                <div v-if="isStreaming && isAssistant && !message.content" class="flex items-center gap-2 text-muted-foreground">
                    <Loader2 class="h-4 w-4 animate-spin" />
                    <span class="text-sm">Thinking...</span>
                </div>

                <!-- Streaming cursor -->
                <span
                    v-if="isStreaming && isAssistant && message.content"
                    class="inline-block w-2 h-4 ml-0.5 bg-current animate-pulse"
                />
            </div>

            <!-- Tool Uses -->
            <div v-if="toolUses.length > 0" class="w-full mt-2 space-y-2">
                <ToolUseCard
                    v-for="toolUse in toolUses"
                    :key="toolUse.id"
                    :tool-use="toolUse"
                    @approve="emit('approveTool', toolUse)"
                    @reject="emit('rejectTool', toolUse)"
                />
            </div>

            <!-- Timestamp and usage -->
            <div class="flex items-center gap-2 mt-1 text-xs text-muted-foreground">
                <span>{{ relativeTime }}</span>
                <span v-if="message.usage" class="text-muted-foreground/70">
                    {{ message.usage.input_tokens + message.usage.output_tokens }} tokens
                </span>
            </div>
        </div>
    </div>
</template>

<style scoped>
/* Markdown content styling */
:deep(.prose) {
    font-size: 0.875rem;
    line-height: 1.5;
}

:deep(.prose p) {
    margin-top: 0.5em;
    margin-bottom: 0.5em;
}

:deep(.prose p:first-child) {
    margin-top: 0;
}

:deep(.prose p:last-child) {
    margin-bottom: 0;
}

:deep(.prose pre) {
    background-color: rgb(0 0 0 / 0.1);
    border-radius: 0.375rem;
    padding: 0.75rem;
    overflow-x: auto;
    margin: 0.5em 0;
}

:deep(.prose code) {
    font-size: 0.8125rem;
    background-color: rgb(0 0 0 / 0.1);
    padding: 0.125rem 0.25rem;
    border-radius: 0.25rem;
}

:deep(.prose pre code) {
    background-color: transparent;
    padding: 0;
}

:deep(.prose ul),
:deep(.prose ol) {
    margin: 0.5em 0;
    padding-left: 1.5em;
}

:deep(.prose li) {
    margin: 0.25em 0;
}

:deep(.prose a) {
    color: inherit;
    text-decoration: underline;
    text-underline-offset: 2px;
}

:deep(.prose blockquote) {
    border-left: 3px solid currentColor;
    padding-left: 0.75em;
    margin: 0.5em 0;
    opacity: 0.8;
}

:deep(.prose table) {
    width: 100%;
    border-collapse: collapse;
    margin: 0.5em 0;
}

:deep(.prose th),
:deep(.prose td) {
    border: 1px solid rgb(255 255 255 / 0.2);
    padding: 0.5em;
    text-align: left;
}

:deep(.prose th) {
    background-color: rgb(0 0 0 / 0.1);
}
</style>
