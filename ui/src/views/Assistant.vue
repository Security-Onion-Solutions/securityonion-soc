<script setup lang="ts">
import { ref, computed, onMounted, watch, nextTick } from 'vue'
import { Bot, Settings, RefreshCw, AlertCircle } from 'lucide-vue-next'
import { useAssistant } from '@/composables/useAssistant'
import SessionSidebar from '@/components/assistant/SessionSidebar.vue'
import ChatMessage from '@/components/assistant/ChatMessage.vue'
import ChatInput from '@/components/assistant/ChatInput.vue'
import CreditsDisplay from '@/components/assistant/CreditsDisplay.vue'
import AssistantSettings from '@/components/assistant/AssistantSettings.vue'

const props = defineProps<{
    sessionId?: string | null
    investigationParams?: Record<string, string>
}>()

const emit = defineEmits<{
    navigateToSession: [sessionId: string]
}>()

const {
    // State
    sessions,
    messages,
    currentSessionId,
    balance,
    settings,
    availableModels,
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
    saveSettings,
    initializeParams,
    setSrvToken,
    generateInvestigationPrompt,
} = useAssistant()

// Local state
const chatInputRef = ref<InstanceType<typeof ChatInput> | null>(null)
const messagesContainerRef = ref<HTMLDivElement | null>(null)
const showSettings = ref(false)
const isPinnedToBottom = ref(true)
const initialized = ref(false)
const error = ref<string | null>(null)

// Welcome message
const welcomeMessage = computed(() => ({
    role: 'assistant' as const,
    content: 'Hello! I\'m your AI Security Assistant. I can help you investigate alerts, query events, analyze detections, and more. How can I assist you today?',
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

// Handle choice button clicks from messages
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
    emit('navigateToSession', sessionId)
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

// Sidebar toggle
function toggleSidebar(): void {
    settings.showChatHistory = !settings.showChatHistory
    saveSettings()
}

// Settings change handlers
function handleModelChange(model: string): void {
    settings.currentModel = model
    saveSettings()
}

function handleExtendedContextChange(value: boolean): void {
    settings.increaseContextLimit = value
    saveSettings()
}

function handleRestoreLastActiveChange(value: boolean): void {
    settings.restoreLastActive = value
    saveSettings()
}

function handleAutoApproveChange(value: boolean): void {
    settings.alwaysApproveReadRequests = value
    saveSettings()
}

// Initialize
onMounted(async () => {
    try {
        // Load assistant parameters and srvToken from API
        const response = await fetch('/api/info')
        if (response.ok) {
            const data = await response.json()
            // Store the srvToken for authenticated API calls
            if (data.srvToken) {
                setSrvToken(data.srvToken)
            }
            // Assistant params are nested under parameters.assistant
            initializeParams(data.parameters?.assistant || null)
        }

        // Load sessions and balance in parallel
        await Promise.all([
            fetchSessions(),
            fetchBalance(),
        ])

        // Handle investigation mode
        if (props.investigationParams) {
            const prompt = generateInvestigationPrompt(props.investigationParams)
            if (prompt) {
                startNewChat()
                setTimeout(() => {
                    handleSendMessage(prompt)
                }, 500)
            }
        }
        // Handle session ID from props
        else if (props.sessionId) {
            await loadSession(props.sessionId)
        }
        // Restore last active chat if enabled
        else if (settings.restoreLastActive) {
            const lastId = localStorage.getItem('settings.assistant.currentChatId')
            if (lastId && sessions.value.some(s => s.sessionId === lastId)) {
                await loadSession(lastId)
            }
        }

        initialized.value = true
        scrollToBottom()
        chatInputRef.value?.focus()
    } catch (err) {
        console.error('Failed to initialize assistant:', err)
        error.value = 'Failed to initialize assistant'
        initialized.value = true
    }
})

// Watch for external session ID changes
watch(() => props.sessionId, async (newId) => {
    if (newId && newId !== currentSessionId.value) {
        await loadSession(newId)
        scrollToBottom()
    }
})
</script>

<template>
    <div class="flex h-full bg-background">
        <!-- Main Chat Area -->
        <div class="flex-1 flex flex-col min-w-0">
            <!-- Header -->
            <div class="flex items-center justify-between px-4 py-3 border-b border-border bg-card">
                <div class="flex items-center gap-3">
                    <div class="flex items-center justify-center w-10 h-10 rounded-xl bg-primary/10">
                        <Bot class="h-5 w-5 text-primary" />
                    </div>
                    <div>
                        <h1 class="text-lg font-semibold text-foreground">AI Assistant</h1>
                        <p class="text-xs text-muted-foreground">
                            <span v-if="isHealthy" class="text-green-500">Online</span>
                            <span v-else class="text-red-500">Offline</span>
                            <span v-if="currentSessionId" class="ml-2">
                                Session: {{ currentSessionId.substring(0, 12) }}...
                            </span>
                        </p>
                    </div>
                </div>
                <div class="flex items-center gap-2">
                    <!-- Refresh button -->
                    <button
                        class="p-2 rounded-lg hover:bg-muted transition-colors text-muted-foreground hover:text-foreground"
                        title="Refresh sessions"
                        :disabled="loadingSessions"
                        @click="fetchSessions"
                    >
                        <RefreshCw class="h-4 w-4" :class="{ 'animate-spin': loadingSessions }" />
                    </button>
                    <!-- Settings button -->
                    <button
                        class="p-2 rounded-lg hover:bg-muted transition-colors"
                        :class="showSettings ? 'bg-muted text-foreground' : 'text-muted-foreground hover:text-foreground'"
                        title="Settings"
                        @click="showSettings = !showSettings"
                    >
                        <Settings class="h-4 w-4" />
                    </button>
                </div>
            </div>

            <!-- Error Alert -->
            <div v-if="error" class="px-4 py-2 bg-red-500/10 border-b border-red-500/20">
                <div class="flex items-center gap-2 text-sm text-red-500">
                    <AlertCircle class="h-4 w-4" />
                    {{ error }}
                    <button class="ml-auto text-xs underline" @click="error = null">Dismiss</button>
                </div>
            </div>

            <!-- Messages Area -->
            <div
                ref="messagesContainerRef"
                class="flex-1 overflow-y-auto"
                @scroll="onChatScroll"
            >
                <div class="max-w-4xl mx-auto py-4">
                    <!-- Loading state -->
                    <div v-if="loadingMessages" class="flex items-center justify-center py-12">
                        <div class="animate-spin rounded-full h-8 w-8 border-2 border-primary border-t-transparent" />
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
            </div>

            <!-- Footer with Credits and Input -->
            <div class="relative border-t border-border bg-card">
                <!-- Credits Display -->
                <div class="px-4 py-2 border-b border-border bg-muted/30">
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

                <!-- Settings Panel (positioned above input) -->
                <AssistantSettings
                    v-model="showSettings"
                    :current-model="settings.currentModel"
                    :available-models="availableModels"
                    :increase-context-limit="settings.increaseContextLimit"
                    :restore-last-active="settings.restoreLastActive"
                    :always-approve-read-requests="settings.alwaysApproveReadRequests"
                    @update:current-model="handleModelChange"
                    @update:increase-context-limit="handleExtendedContextChange"
                    @update:restore-last-active="handleRestoreLastActiveChange"
                    @update:always-approve-read-requests="handleAutoApproveChange"
                />

                <!-- Chat Input -->
                <ChatInput
                    ref="chatInputRef"
                    :disabled="!canChat"
                    :loading="isStreaming || isTyping"
                    :placeholder="!isHealthy ? 'Assistant is offline...' : creditsRemaining <= 0 ? 'No credits remaining...' : 'Type a message...'"
                    @send="handleSendMessage"
                />
            </div>
        </div>

        <!-- Sidebar (right side) -->
        <SessionSidebar
            :sessions="sessions"
            :current-session-id="currentSessionId"
            :collapsed="!settings.showChatHistory"
            :loading="loadingSessions"
            @select="handleSelectSession"
            @delete="handleDeleteSession"
            @new-chat="handleNewChat"
            @toggle="toggleSidebar"
        />
    </div>
</template>
