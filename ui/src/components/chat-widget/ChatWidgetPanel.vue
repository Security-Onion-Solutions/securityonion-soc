<script setup lang="ts">
import { ref, computed, watch, nextTick, onMounted } from 'vue'
import { Bot, AlertCircle, X, GripVertical } from 'lucide-vue-next'
import { useAssistant } from '@/composables/useAssistant'
import { useChatWidget } from '@/composables/useChatWidget'
import ChatWidgetHeader from './ChatWidgetHeader.vue'
import SessionSidebar from '@/components/assistant/SessionSidebar.vue'
import ChatMessage from '@/components/assistant/ChatMessage.vue'
import ChatInput from '@/components/assistant/ChatInput.vue'
import CreditsDisplay from '@/components/assistant/CreditsDisplay.vue'

const emit = defineEmits<{
    close: []
    openFull: []
    navigateToEvent: [eventId: string, query?: string]
}>()

const {
    // State
    sessions,
    messages,
    currentSessionId,
    settings,
    assistantParams,

    // Loading states
    loadingSessions,
    loadingMessages,
    isStreaming,
    isTyping,

    // Computed
    creditsRemaining,
    isHealthy,
    canChat,
    contextLength,
    creditsUsed,
    maxContextLimit,
    lowBalanceColorAlert,

    // Functions
    fetchSessions,
    fetchBalance,
    loadSession,
    startNewChat,
    sendMessage,
    deleteSession,
    approveTool,
    rejectTool,
    compressCurrentSession,
    checkContextLimitReached,
    initializeParams,
    setSrvToken,
} = useAssistant()

const {
    showSidebar,
    panelWidth,
    pendingPrompt,
    shouldStartNewChat,
    toggleSidebar,
    resize,
    clearPendingPrompt,
    MIN_WIDTH,
    MAX_WIDTH,
} = useChatWidget()

// Local state
const chatInputRef = ref<InstanceType<typeof ChatInput> | null>(null)
const messagesContainerRef = ref<HTMLDivElement | null>(null)
const isPinnedToBottom = ref(true)
const error = ref<string | null>(null)
const initialized = ref(false)

// Resize state
const isResizing = ref(false)

// Welcome message
const welcomeMessage = computed(() => ({
    role: 'assistant' as const,
    content: 'Hello! I\'m your AI Security Assistant. How can I help you today?',
    timestamp: new Date().toISOString(),
}))

const displayMessages = computed(() => {
    if (messages.value.length === 0 && !currentSessionId.value) {
        return [welcomeMessage.value]
    }
    return messages.value
})

// Scroll handling
function isNearBottom(threshold = 48): boolean {
    if (!messagesContainerRef.value) return true
    const { scrollHeight, clientHeight, scrollTop } = messagesContainerRef.value
    return scrollHeight - clientHeight - scrollTop <= threshold
}

function scrollToBottom(): void {
    nextTick(() => {
        if (messagesContainerRef.value) {
            messagesContainerRef.value.scrollTop = messagesContainerRef.value.scrollHeight
        }
    })
}

function onChatScroll(): void {
    isPinnedToBottom.value = isNearBottom(4)
}

function scrollIfPinned(): void {
    if (isPinnedToBottom.value) {
        scrollToBottom()
    }
}

// Watch messages for auto-scroll
watch(messages, () => {
    scrollIfPinned()
}, { deep: true })

// Handle sending messages
async function handleSendMessage(text: string): Promise<void> {
    if (!text.trim() || !canChat.value) return

    error.value = null

    try {
        await sendMessage(text, null, {
            onMessageStart: () => {
                scrollToBottom()
            },
            onTextDelta: () => {
                scrollIfPinned()
            },
            onToolUse: () => {
                scrollIfPinned()
            },
            onError: (err) => {
                error.value = err
            },
        })
    } catch (err) {
        error.value = err instanceof Error ? err.message : 'An error occurred'
    }
}

// Handle choice button clicks
function handleChoiceClick(choice: string): void {
    if (!canChat.value) return
    handleSendMessage(choice)
}

// Handle session selection
async function handleSelectSession(sessionId: string): Promise<void> {
    if (sessionId === currentSessionId.value) return
    await loadSession(sessionId)
    scrollToBottom()
    chatInputRef.value?.focus()
}

// Handle new chat
function handleNewChat(): void {
    startNewChat()
    chatInputRef.value?.focus()
}

// Handle session deletion
async function handleDeleteSession(sessionId: string): Promise<void> {
    await deleteSession(sessionId)
    if (currentSessionId.value === sessionId) {
        handleNewChat()
    }
}

// Handle tool approval
async function handleApproveTool(toolUse: any): Promise<void> {
    if (checkContextLimitReached()) {
        error.value = 'Context limit reached. Please compress the context or start a new chat.'
        return
    }
    await approveTool(toolUse)
}

// Handle tool rejection
async function handleRejectTool(toolUse: any): Promise<void> {
    await rejectTool(toolUse)
}

// Handle context compression
async function handleCompressContext(): Promise<void> {
    await compressCurrentSession()
    scrollToBottom()
}

// Resize handling
function startResize(event: MouseEvent): void {
    event.preventDefault()
    isResizing.value = true

    const startX = event.clientX
    const startWidth = panelWidth.value

    function onMouseMove(e: MouseEvent): void {
        if (!isResizing.value) return
        // Resize from left edge - moving left increases width
        const newWidth = startWidth + (startX - e.clientX)
        resize(newWidth)
    }

    function onMouseUp(): void {
        isResizing.value = false
        document.removeEventListener('mousemove', onMouseMove)
        document.removeEventListener('mouseup', onMouseUp)
    }

    document.addEventListener('mousemove', onMouseMove)
    document.addEventListener('mouseup', onMouseUp)
}

// Initialize
onMounted(async () => {
    try {
        // Load assistant parameters if not already loaded
        if (!assistantParams.value) {
            const response = await fetch('/api/info')
            if (response.ok) {
                const data = await response.json()
                if (data.srvToken) {
                    setSrvToken(data.srvToken)
                }
                initializeParams(data.parameters?.assistant || null)
            }
        }

        // Refresh sessions and balance
        await Promise.all([
            fetchSessions(),
            fetchBalance(),
        ])

        initialized.value = true
        scrollToBottom()
        chatInputRef.value?.focus()

        // Check for pending prompt after initialization
        if (pendingPrompt.value) {
            const prompt = pendingPrompt.value
            const startNew = shouldStartNewChat.value
            clearPendingPrompt()
            if (startNew) {
                startNewChat()
            }
            await nextTick()
            await sendMessage(prompt)
        }
    } catch (err) {
        console.error('Failed to initialize chat widget:', err)
        error.value = 'Failed to initialize'
        initialized.value = true
    }
})

// Watch for pending prompts (when widget is already open)
watch(pendingPrompt, async (newPrompt) => {
    if (newPrompt && initialized.value && canChat.value) {
        const prompt = newPrompt
        const startNew = shouldStartNewChat.value
        clearPendingPrompt()
        if (startNew) {
            startNewChat()
        }
        await nextTick()
        await sendMessage(prompt)
    }
})

async function handleRefresh(): Promise<void> {
    await Promise.all([
        fetchSessions(),
        fetchBalance(),
    ])
}
</script>

<template>
    <div
        class="relative flex flex-col h-full bg-card border-l border-border"
        :style="{ width: `${panelWidth}px` }"
    >
        <!-- Resize Handle -->
        <div
            class="absolute left-0 top-0 bottom-0 w-1 cursor-ew-resize hover:bg-primary/50 transition-colors z-10 group"
            @mousedown="startResize"
        >
            <div class="absolute left-0 top-1/2 -translate-y-1/2 -translate-x-1/2 opacity-0 group-hover:opacity-100 transition-opacity">
                <GripVertical class="h-6 w-6 text-muted-foreground" />
            </div>
        </div>

        <!-- Header -->
        <ChatWidgetHeader
            :is-healthy="isHealthy"
            :show-sidebar="showSidebar"
            :loading="loadingSessions"
            @toggle-sidebar="toggleSidebar"
            @open-full="emit('openFull')"
            @minimize="emit('close')"
            @refresh="handleRefresh"
        />

        <!-- Error Alert -->
        <div v-if="error" class="px-3 py-1.5 bg-red-500/10 border-b border-red-500/20 shrink-0">
            <div class="flex items-center gap-2 text-xs text-red-500">
                <AlertCircle class="h-3.5 w-3.5 shrink-0" />
                <span class="truncate">{{ error }}</span>
                <button class="ml-auto text-xs underline shrink-0" @click="error = null">Dismiss</button>
            </div>
        </div>

        <!-- Main Content Area -->
        <div class="flex flex-1 overflow-hidden min-h-0">
            <!-- Session Sidebar (collapsible) -->
            <SessionSidebar
                v-if="showSidebar"
                :sessions="sessions"
                :current-session-id="currentSessionId"
                :collapsed="false"
                :loading="loadingSessions"
                class="shrink-0 border-r border-border"
                @select="handleSelectSession"
                @delete="handleDeleteSession"
                @new-chat="handleNewChat"
                @toggle="toggleSidebar"
            />

            <!-- Chat Area -->
            <div class="flex-1 flex flex-col min-w-0 overflow-hidden">
                <!-- Messages -->
                <div
                    ref="messagesContainerRef"
                    class="flex-1 overflow-y-auto"
                    @scroll="onChatScroll"
                >
                    <!-- Loading state -->
                    <div v-if="loadingMessages" class="flex items-center justify-center py-8">
                        <div class="animate-spin rounded-full h-6 w-6 border-2 border-primary border-t-transparent" />
                    </div>

                    <!-- Messages -->
                    <template v-else>
                        <ChatMessage
                            v-for="(message, index) in displayMessages"
                            :key="`${currentSessionId}-${index}`"
                            :message="message"
                            :is-streaming="isStreaming && index === displayMessages.length - 1 && message.role === 'assistant'"
                            @approve-tool="handleApproveTool"
                            @reject-tool="handleRejectTool"
                            @choice-click="handleChoiceClick"
                        />

                        <!-- Typing indicator -->
                        <div v-if="isTyping" class="flex gap-3 px-4 py-3">
                            <div class="w-8 h-8 rounded-full bg-muted flex items-center justify-center">
                                <Bot class="h-4 w-4 text-muted-foreground" />
                            </div>
                            <div class="bg-muted rounded-2xl rounded-bl-md px-4 py-2.5">
                                <div class="flex items-center gap-1">
                                    <span class="w-2 h-2 bg-muted-foreground rounded-full animate-bounce" style="animation-delay: 0ms" />
                                    <span class="w-2 h-2 bg-muted-foreground rounded-full animate-bounce" style="animation-delay: 150ms" />
                                    <span class="w-2 h-2 bg-muted-foreground rounded-full animate-bounce" style="animation-delay: 300ms" />
                                </div>
                            </div>
                        </div>
                    </template>
                </div>

                <!-- Credits Display (compact) -->
                <div class="px-3 py-1.5 border-t border-border bg-muted/30 shrink-0">
                    <CreditsDisplay
                        :credits-remaining="creditsRemaining"
                        :credits-used="creditsUsed"
                        :context-length="contextLength"
                        :context-limit="maxContextLimit"
                        :low-balance-threshold="lowBalanceColorAlert"
                        :threshold-color-ratio-low="assistantParams?.thresholdColorRatioLow"
                        :threshold-color-ratio-med="assistantParams?.thresholdColorRatioMed"
                        @compress-context="handleCompressContext"
                    />
                </div>

                <!-- Chat Input -->
                <ChatInput
                    ref="chatInputRef"
                    :disabled="!canChat"
                    :loading="isStreaming || isTyping"
                    :placeholder="!isHealthy ? 'Assistant offline...' : creditsRemaining <= 0 ? 'No credits...' : 'Type a message...'"
                    @send="handleSendMessage"
                />
            </div>
        </div>
    </div>
</template>
