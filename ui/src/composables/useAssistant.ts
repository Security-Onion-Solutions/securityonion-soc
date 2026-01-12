/**
 * Composable for AI Assistant functionality.
 * Handles sessions, messages, streaming, tool execution, and settings.
 */
import { ref, reactive, computed, shallowRef } from 'vue'

// ============================================================================
// Types
// ============================================================================

export interface Usage {
    input_tokens: number
    output_tokens: number
    credits: number
}

export interface ToolResultContent {
    json?: any
    text?: string
}

export interface ToolResult {
    toolUseId: string
    content: ToolResultContent[]
    status?: string
    isError?: boolean
}

export interface ContentBlock {
    type: string
    id?: string
    name?: string
    input?: any
    json?: any
    content?: any
    text?: string
    toolResult?: ToolResult
}

export interface StoredMessage {
    id?: string
    createTime?: string
    userId?: string
    sessionId: string
    tags?: string[]
    message: {
        id: string
        role: 'user' | 'assistant'
        contentStr?: string
        contentBlocks?: ContentBlock[]
        stopReason?: string
        stopSequence?: string
        usage?: Usage
    }
}

export interface SessionUsage {
    totalInputTokens: number
    totalOutputTokens: number
    totalCredits: number
    totalMessages: number
}

export interface AssistantSession {
    id?: string
    createTime?: string
    userId?: string
    sessionId: string
    title: string
    deleteTime?: string | null
    tags?: string[]
    usage?: SessionUsage
}

export interface AssistantSessionDetails {
    session: AssistantSession
    history: StoredMessage[]
}

export interface BalanceResponse {
    api_key_prefix: string
    company_id: string
    status: string
    credit_balance: number
    health_status: string
}

export interface ModelConfig {
    id: string
    name: string
    enabled: boolean
    contextLimitSmall: number
    contextLimitLarge: number
    lowBalanceColorAlert: number
}

export interface AssistantParams {
    enabled: boolean
    investigationPrompt: string
    compressContextPrompt: string
    thresholdColorRatioLow: number
    thresholdColorRatioMed: number
    thresholdColorRatioMax: number
    availableModels: ModelConfig[]
}

export type ToolStatus = 'preparing' | 'queued' | 'pending_approval' | 'executing' | 'completed' | 'error' | 'rejected' | 'skipped'

export interface ToolUse {
    id: string
    name: string
    input: Record<string, any>
    inputJson: string
    status: ToolStatus
    result: any
    error: string | null
    rawResult: any
    timestamp: string
    completedAt?: string
    blockIndex?: number
    approved: boolean | null
    sessionId: string
}

export interface Message {
    role: 'user' | 'assistant'
    content: string
    timestamp: string
    tags?: string[]
    usage?: Usage | null
    toolUses?: ToolUse[]
    isToolResult?: boolean
    toolName?: string
    toolId?: string
}

// SSE Event Types
export interface SSEMessageStart {
    type: 'message_start'
    message?: {
        usage?: Usage
    }
}

export interface SSEContentBlockStart {
    type: 'content_block_start'
    index: number
    content_block?: {
        type: string
        id?: string
        name?: string
        input?: any
    }
}

export interface SSEContentBlockDelta {
    type: 'content_block_delta'
    index: number
    delta: {
        type: string
        text?: string
        partial_json?: string
    }
}

export interface SSEContentBlockStop {
    type: 'content_block_stop'
    index: number
    usage?: Usage
}

export interface SSEMessageDelta {
    type: 'message_delta'
    usage?: Usage
}

export interface SSEMessageStop {
    type: 'message_stop'
}

export interface SSEError {
    type: 'error'
    error: {
        type: string
        message: string
    }
}

export type SSEEvent = SSEMessageStart | SSEContentBlockStart | SSEContentBlockDelta | SSEContentBlockStop | SSEMessageDelta | SSEMessageStop | SSEError

// ============================================================================
// Constants
// ============================================================================

const MSGTAG_CONTEXTCOMPRESSION = 'context_compression'
const SESTAG_SHARED = 'shared'
const STORAGE_PREFIX = 'settings.assistant'

// Tools that can be auto-approved
const AUTO_APPROVE_TOOLS = ['query_events', 'get_playbooks', 'query_cases', 'query_detections']

// ============================================================================
// Module-level State (shared across all component instances)
// ============================================================================

const sessions = ref<AssistantSession[]>([])
const sessionsById = ref<Record<string, AssistantSession>>({})
// Use shallowRef for messages so we can manually trigger updates during streaming
const messages = shallowRef<Message[]>([])
const currentSessionId = ref<string | null>(null)
const balance = ref<BalanceResponse | null>(null)

// Server token for API authentication
let srvToken: string | null = null

// Loading states
const loadingSessions = ref(false)
const loadingMessages = ref(false)
const loadingBalance = ref(false)
const isStreaming = ref(false)
const isTyping = ref(false)

// Context and credits tracking
const contextLength = ref(0)
const creditsUsed = ref(0)
const contextStartMessageIndex = ref(-1)

// Settings (loaded from localStorage)
const settings = reactive({
    currentModel: '',
    increaseContextLimit: false,
    restoreLastActive: false,
    alwaysApproveReadRequests: false,
    showChatHistory: true,
})

// Model configuration
const availableModels = ref<ModelConfig[]>([])
const modelsMap = ref<Map<string, ModelConfig>>(new Map())
const assistantParams = ref<AssistantParams | null>(null)

// Tool execution state
const executingToolsBySession = new Map<string, Map<string, ToolUse>>()
const toolIndexToIdBySession = new Map<string, Map<number, string>>()
const toolQueues = new Map<string, string[]>()
const toolRunnerBusy = new Set<string>()
const mostRecentFloatingTool = new Map<string, ToolUse>()
const activeStreamingSessionId = ref<string | null>(null)

// ============================================================================
// Computed Properties
// ============================================================================

const currentModel = computed(() => {
    if (settings.currentModel && modelsMap.value.has(settings.currentModel)) {
        return modelsMap.value.get(settings.currentModel)!
    }
    return availableModels.value[0] || null
})

const contextLimitSmall = computed(() => currentModel.value?.contextLimitSmall ?? 0)
const contextLimitLarge = computed(() => currentModel.value?.contextLimitLarge ?? 0)
const maxContextLimit = computed(() => settings.increaseContextLimit ? contextLimitLarge.value : contextLimitSmall.value)
const lowBalanceColorAlert = computed(() => currentModel.value?.lowBalanceColorAlert ?? 0)
const creditsRemaining = computed(() => balance.value?.credit_balance ?? 0)
const isHealthy = computed(() => balance.value?.health_status === 'healthy')
const canChat = computed(() => !isStreaming.value && !isTyping.value && creditsRemaining.value > 0 && isHealthy.value)

// ============================================================================
// localStorage Helpers
// ============================================================================

function loadSettings(): void {
    const prefix = STORAGE_PREFIX
    const stored = {
        increaseContextLimit: localStorage.getItem(`${prefix}.increaseContextLimit`),
        restoreLastActive: localStorage.getItem(`${prefix}.restoreLastActive`),
        alwaysApproveReadRequests: localStorage.getItem(`${prefix}.alwaysApproveReadRequests`),
        showChatHistory: localStorage.getItem(`${prefix}.showChatHistory`),
        currentModel: localStorage.getItem(`${prefix}.currentModel`),
    }

    if (stored.increaseContextLimit) settings.increaseContextLimit = stored.increaseContextLimit === 'true'
    if (stored.restoreLastActive) settings.restoreLastActive = stored.restoreLastActive === 'true'
    if (stored.alwaysApproveReadRequests) settings.alwaysApproveReadRequests = stored.alwaysApproveReadRequests === 'true'
    if (stored.showChatHistory !== null) settings.showChatHistory = stored.showChatHistory === 'true'
    if (stored.currentModel) settings.currentModel = stored.currentModel
}

function saveSettings(): void {
    const prefix = STORAGE_PREFIX
    localStorage.setItem(`${prefix}.increaseContextLimit`, String(settings.increaseContextLimit))
    localStorage.setItem(`${prefix}.restoreLastActive`, String(settings.restoreLastActive))
    localStorage.setItem(`${prefix}.alwaysApproveReadRequests`, String(settings.alwaysApproveReadRequests))
    localStorage.setItem(`${prefix}.showChatHistory`, String(settings.showChatHistory))
    localStorage.setItem(`${prefix}.currentModel`, settings.currentModel)
}

function saveCurrentSessionId(): void {
    if (currentSessionId.value) {
        localStorage.setItem(`${STORAGE_PREFIX}.currentChatId`, currentSessionId.value)
    } else {
        localStorage.removeItem(`${STORAGE_PREFIX}.currentChatId`)
    }
}

function loadCurrentSessionId(): string | null {
    return localStorage.getItem(`${STORAGE_PREFIX}.currentChatId`)
}

// ============================================================================
// Helper Functions
// ============================================================================

function generateSessionId(): string {
    return 'chat_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9)
}

function getApiHeaders(contentType = true, streaming = false): Record<string, string> {
    const headers: Record<string, string> = {}
    if (contentType) {
        headers['Content-Type'] = 'application/json'
    }
    if (streaming) {
        headers['Accept'] = 'text/event-stream'
    }
    if (srvToken) {
        headers['X-Srv-Token'] = srvToken
    }
    return headers
}

function setSrvToken(token: string | null): void {
    srvToken = token
}

function shouldAutoApproveTool(toolName: string): boolean {
    return AUTO_APPROVE_TOOLS.includes(toolName) && settings.alwaysApproveReadRequests
}

function getSessionToolMap(sessionId: string): Map<string, ToolUse> {
    let m = executingToolsBySession.get(sessionId)
    if (!m) {
        m = new Map()
        executingToolsBySession.set(sessionId, m)
    }
    return m
}

function getIndexMap(sessionId: string): Map<number, string> {
    let m = toolIndexToIdBySession.get(sessionId)
    if (!m) {
        m = new Map()
        toolIndexToIdBySession.set(sessionId, m)
    }
    return m
}

function updateContextLength(usage: Usage | null | undefined): void {
    if (usage) {
        contextLength.value += (usage.input_tokens || 0) + (usage.output_tokens || 0)
    }
}

function updateCreditsUsed(usage: Usage | null | undefined): void {
    if (usage) {
        creditsUsed.value += usage.credits || 0
    }
}

function checkContextLimitReached(): boolean {
    return contextLength.value >= maxContextLimit.value
}

function clearStreamingStates(): void {
    activeStreamingSessionId.value = null
    isTyping.value = false
    isStreaming.value = false
}

function nbspRegexOp(text: string): string {
    return text.replace(/^(&nbsp;?[\n]*)/, '')
}

// ============================================================================
// SSE Parsing Helpers
// ============================================================================

interface ParseResult {
    success: boolean
    data: any
    isPartial: string | null
}

function parseJsonChunk(chunk: string): ParseResult {
    try {
        return { success: true, data: JSON.parse(chunk), isPartial: null }
    } catch {
        const splitChunks: string[] = []
        let currentChunk = ''
        let braceCount = 0
        let inString = false
        let escaped = false

        for (let j = 0; j < chunk.length; j++) {
            const char = chunk[j]
            currentChunk += char

            if (escaped) {
                escaped = false
                continue
            }

            if (char === '\\') {
                escaped = true
                continue
            }

            if (char === '"') {
                inString = !inString
                continue
            }

            if (!inString) {
                if (char === '{') {
                    braceCount++
                } else if (char === '}') {
                    braceCount--
                    if (braceCount === 0) {
                        splitChunks.push(currentChunk)
                        currentChunk = ''
                    }
                }
            }
        }

        if (splitChunks.length > 0) {
            return {
                success: true,
                data: splitChunks,
                isPartial: currentChunk.trim() ? currentChunk : null
            }
        } else if (currentChunk.trim()) {
            return { success: false, data: null, isPartial: currentChunk }
        } else {
            return { success: false, data: null, isPartial: chunk }
        }
    }
}

function processStreamingChunks(value: string, chunks: string[], partial: boolean): { chunks: string[], partial: boolean } {
    const newChunks = value.split('\n\n').filter(d => d.trim()).map(d => (d.startsWith("data: ") ? d.slice(6) : d))

    if (partial && chunks.length > 0) {
        newChunks[0] = chunks[0] + newChunks[0]
    }

    return { chunks: newChunks, partial: false }
}

// ============================================================================
// API Functions
// ============================================================================

async function fetchSessions(): Promise<void> {
    loadingSessions.value = true
    try {
        const response = await fetch('/api/assistant/sessions', {
            headers: getApiHeaders(false),
        })
        if (response.ok) {
            const data: AssistantSession[] = await response.json()
            sessions.value = data || []
            sessionsById.value = {}
            for (const session of sessions.value) {
                sessionsById.value[session.sessionId] = session
            }
        }
    } catch (e) {
        console.error('Error fetching sessions:', e)
    } finally {
        loadingSessions.value = false
    }
}

async function fetchSessionDetails(sessionId: string): Promise<AssistantSessionDetails | null> {
    loadingMessages.value = true
    try {
        const response = await fetch(`/api/assistant/sessions/${sessionId}`, {
            headers: getApiHeaders(false),
        })
        if (response.ok) {
            return await response.json()
        }
        return null
    } catch (e) {
        console.error('Error fetching session details:', e)
        return null
    } finally {
        loadingMessages.value = false
    }
}

async function deleteSession(sessionId: string): Promise<boolean> {
    try {
        const response = await fetch(`/api/assistant/sessions/${sessionId}`, {
            method: 'DELETE',
            headers: getApiHeaders(false),
        })
        if (response.ok) {
            sessions.value = sessions.value.filter(s => s.sessionId !== sessionId)
            delete sessionsById.value[sessionId]
            if (currentSessionId.value === sessionId) {
                currentSessionId.value = null
                saveCurrentSessionId()
                messages.value = []
            }
            return true
        }
        return false
    } catch (e) {
        console.error('Error deleting session:', e)
        return false
    }
}

async function fetchBalance(): Promise<void> {
    loadingBalance.value = true
    try {
        const response = await fetch('/api/assistant/balance', {
            headers: getApiHeaders(false),
        })
        if (response.ok) {
            balance.value = await response.json()
        }
    } catch (e) {
        console.error('Error fetching balance:', e)
    } finally {
        loadingBalance.value = false
    }
}

async function updateSessionTag(sessionId: string, action: 'add' | 'remove', tag: string): Promise<boolean> {
    try {
        const response = await fetch(`/api/assistant/sessions/${sessionId}`, {
            method: 'PUT',
            headers: getApiHeaders(),
            body: JSON.stringify({ action, tag })
        })
        return response.ok
    } catch (e) {
        console.error('Error updating session tag:', e)
        return false
    }
}

// ============================================================================
// Message Conversion
// ============================================================================

function convertBackendMessagesToFrontend(backendMessages: StoredMessage[]): Message[] {
    const processedMessages: Message[] = []
    contextLength.value = 0
    creditsUsed.value = 0
    contextStartMessageIndex.value = -1
    let skipNext = false

    for (let i = 0; i < backendMessages.length; i++) {
        if (skipNext) {
            skipNext = false
            continue
        }

        const msg = backendMessages[i]

        // Check if this is a tool result message (new format with tags)
        if (msg.tags && msg.tags.includes('tool_result')) {
            processToolResultMessage(msg, processedMessages)
            continue
        }

        // Check if this is a tool result message (old format)
        if (msg.message.role === 'user' && msg.message.contentStr && !msg.message.contentBlocks) {
            processOldFormatToolResult(msg, processedMessages)
            continue
        }

        const frontendMsg: Message = {
            role: msg.message.role,
            content: '',
            timestamp: msg.createTime || new Date().toISOString(),
            tags: msg.tags || [],
        }

        // Extract content
        if (msg.message.contentStr) {
            frontendMsg.content = msg.message.contentStr
        } else if (msg.message.contentBlocks && msg.message.contentBlocks.length > 0) {
            const textBlocks = msg.message.contentBlocks.filter(block => block.type === 'text')
            frontendMsg.content = textBlocks.map(block => nbspRegexOp(block.text || '')).join('\n')
        }

        // Process tool use blocks
        if (msg.message.contentBlocks && msg.message.contentBlocks.length > 0) {
            const result = processToolUseBlocks(msg, frontendMsg, backendMessages, i)
            if (result.skipNext) skipNext = true
            if (result.toolUses) frontendMsg.toolUses = result.toolUses
        }

        // Handle usage information
        if (msg.message.usage) {
            frontendMsg.usage = msg.message.usage
            updateContextLength(msg.message.usage)
            updateCreditsUsed(msg.message.usage)
        }

        processedMessages.push(frontendMsg)

        if (msg.tags && msg.tags.includes(MSGTAG_CONTEXTCOMPRESSION)) {
            contextLength.value = 0
            contextStartMessageIndex.value = processedMessages.length - 1
        }
    }

    return processedMessages
}

function processToolResultMessage(msg: StoredMessage, processedMessages: Message[]): void {
    let rawResult: any = null
    let toolUseId: string | null = null
    let toolError: string | null = null

    if (msg.message.contentBlocks && msg.message.contentBlocks.length > 0) {
        const toolResultBlock = msg.message.contentBlocks.find(block => block.toolResult)
        if (toolResultBlock && toolResultBlock.toolResult?.content?.length) {
            const cb = toolResultBlock.toolResult.content[0]
            if (toolResultBlock.toolResult.isError || toolResultBlock.toolResult.status === 'error') {
                toolError = cb.text || 'Unknown error'
                rawResult = null
            } else {
                rawResult = cb.json
                toolError = null
            }
            toolUseId = toolResultBlock.toolResult.toolUseId
        }
    }

    if (toolUseId && (rawResult !== null || toolError !== null)) {
        for (let j = processedMessages.length - 1; j >= 0; j--) {
            const processedMsg = processedMessages[j]
            if (processedMsg.role === 'assistant' && processedMsg.toolUses) {
                const matchingToolUse = processedMsg.toolUses.find(tool => tool.id === toolUseId)
                if (matchingToolUse) {
                    matchingToolUse.rawResult = rawResult
                    matchingToolUse.completedAt = msg.createTime
                    if (toolError) {
                        matchingToolUse.error = toolError
                        matchingToolUse.status = 'error'
                    }
                    break
                }
            }
        }
    }
}

function processOldFormatToolResult(msg: StoredMessage, processedMessages: Message[]): void {
    const prevMessage = processedMessages[processedMessages.length - 1]
    if (prevMessage && prevMessage.role === 'assistant' && prevMessage.toolUses) {
        if (prevMessage.toolUses.length > 0) {
            const lastToolUse = prevMessage.toolUses[prevMessage.toolUses.length - 1]
            lastToolUse.rawResult = msg.message.contentStr
        }
    }
}

function processToolUseBlocks(
    msg: StoredMessage,
    _frontendMsg: Message,
    backendMessages: StoredMessage[],
    i: number
): { skipNext: boolean; toolUses?: ToolUse[] } {
    const toolBlocks = msg.message.contentBlocks?.filter(block => block.type === 'tool_use') || []
    let skipNext = false
    let toolUses: ToolUse[] | undefined

    if (toolBlocks.length > 0) {
        const sessionId = currentSessionId.value || ''

        if (i < backendMessages.length - 1 && (!backendMessages[i + 1].tags || !backendMessages[i + 1].tags?.includes('tool_result'))) {
            const nextMessage = backendMessages[i + 1]
            const nextContentBlocks = nextMessage.message.contentBlocks
            if (nextContentBlocks?.[0]?.text?.includes('rejected by the user')) {
                toolUses = toolBlocks.map(block => ({
                    id: block.id || 'unknown',
                    name: block.name || 'unknown',
                    input: block.input || {},
                    inputJson: '',
                    status: 'rejected' as ToolStatus,
                    result: null,
                    error: 'Tool use rejected by the user',
                    rawResult: null,
                    timestamp: msg.createTime || new Date().toISOString(),
                    approved: false,
                    sessionId,
                }))
                skipNext = true
            } else if (nextMessage.message.role === 'user') {
                toolUses = toolBlocks.map(block => ({
                    id: block.id || 'unknown',
                    name: block.name || 'unknown',
                    input: block.input || {},
                    inputJson: '',
                    status: 'skipped' as ToolStatus,
                    result: null,
                    error: null,
                    rawResult: null,
                    timestamp: msg.createTime || new Date().toISOString(),
                    approved: false,
                    sessionId,
                }))
            }
        } else if (i < backendMessages.length - 1) {
            toolUses = toolBlocks.map(block => ({
                id: block.id || 'unknown',
                name: block.name || 'unknown',
                input: block.input || {},
                inputJson: '',
                status: 'completed' as ToolStatus,
                result: null,
                error: null,
                rawResult: null,
                timestamp: msg.createTime || new Date().toISOString(),
                approved: true,
                sessionId,
            }))
        } else {
            // End of session - tool use pending
            toolUses = toolBlocks.map(block => {
                const toolUse: ToolUse = {
                    id: block.id || 'unknown',
                    name: block.name || 'unknown',
                    input: block.input || {},
                    inputJson: '',
                    status: 'pending_approval',
                    result: null,
                    error: null,
                    rawResult: null,
                    timestamp: msg.createTime || new Date().toISOString(),
                    approved: null,
                    sessionId,
                }
                getSessionToolMap(sessionId).set(toolUse.id, toolUse)
                mostRecentFloatingTool.set(sessionId, toolUse)
                return toolUse
            })
        }
    }

    return { skipNext, toolUses }
}

// ============================================================================
// Chat Functions
// ============================================================================

async function loadSession(sessionId: string): Promise<boolean> {
    clearStreamingStates()
    const details = await fetchSessionDetails(sessionId)
    if (details && details.history && details.history.length > 0) {
        currentSessionId.value = sessionId
        messages.value = convertBackendMessagesToFrontend(details.history)
        saveCurrentSessionId()
        if (details.session) {
            sessionsById.value[sessionId] = details.session
        }
        return true
    }
    return false
}

function startNewChat(): void {
    clearStreamingStates()
    currentSessionId.value = null
    saveCurrentSessionId()
    messages.value = []
    contextLength.value = 0
    creditsUsed.value = 0
}

interface StreamCallbacks {
    onMessageStart?: () => void
    onTextDelta?: (text: string) => void
    onToolUse?: (toolUse: ToolUse) => void
    onMessageStop?: (usage: Usage | null) => void
    onError?: (error: string) => void
}

async function sendMessage(
    text: string,
    tags: string[] | null = null,
    callbacks?: StreamCallbacks
): Promise<void> {
    if (!text.trim() || isStreaming.value || isTyping.value) return

    // Generate session ID if needed
    if (!currentSessionId.value) {
        currentSessionId.value = generateSessionId()
        saveCurrentSessionId()
    }

    const sessionId = currentSessionId.value
    activeStreamingSessionId.value = sessionId

    // Add user message
    const userMessage: Message = {
        role: 'user',
        content: text.trim(),
        timestamp: new Date().toISOString(),
    }
    messages.value.push(userMessage)
    isTyping.value = true

    try {
        // Build request body, omitting null/undefined values
        const requestBody: Record<string, any> = {
            msg: text.trim(),
            sessionId,
        }
        if (settings.currentModel) {
            requestBody.model = settings.currentModel
        }
        if (tags && tags.length > 0) {
            requestBody.tags = tags
        }

        const response = await fetch('/api/assistant/chat', {
            method: 'POST',
            headers: getApiHeaders(true, true),
            body: JSON.stringify(requestBody),
        })

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`)
        }

        const reader = response.body?.getReader()
        if (!reader) throw new Error('No response body')

        const decoder = new TextDecoder()
        isStreaming.value = true
        isTyping.value = false

        let assistantMessage: Message | null = null
        let chunks: string[] = []
        let partial = false
        let messageUsage: Usage | null = null

        while (true) {
            const { done, value } = await reader.read()
            if (done) break

            const isCurrentSession = activeStreamingSessionId.value === sessionId && currentSessionId.value === sessionId

            const chunkResult = processStreamingChunks(decoder.decode(value), chunks, partial)
            chunks = chunkResult.chunks
            partial = chunkResult.partial

            for (let i = 0; i < chunks.length; i++) {
                if (chunks[i] === '[DONE]') {
                    assistantMessage = null
                    continue
                }

                const parseResult = parseJsonChunk(chunks[i])

                if (!parseResult.success) {
                    if (parseResult.isPartial) {
                        partial = true
                        chunks = [parseResult.isPartial]
                        break
                    }
                    continue
                }

                if (Array.isArray(parseResult.data)) {
                    chunks.splice(i, 1, ...parseResult.data)
                    i--
                    if (parseResult.isPartial) {
                        partial = true
                        chunks.push(parseResult.isPartial)
                    }
                    continue
                }

                const event = parseResult.data as SSEEvent

                switch (event.type) {
                    case 'message_start':
                        if (isCurrentSession) {
                            assistantMessage = {
                                role: 'assistant',
                                content: '',
                                timestamp: new Date().toISOString(),
                                usage: null,
                                toolUses: [],
                            }
                            // Replace array to trigger reactivity
                            messages.value = [...messages.value, assistantMessage]
                            callbacks?.onMessageStart?.()
                            if ((event as SSEMessageStart).message?.usage) {
                                messageUsage = (event as SSEMessageStart).message!.usage!
                            }
                        }
                        break

                    case 'content_block_start': {
                        const startEvent = event as SSEContentBlockStart
                        if (startEvent.content_block?.type === 'tool_use') {
                            const toolUse: ToolUse = {
                                id: startEvent.content_block.id || '',
                                name: startEvent.content_block.name || '',
                                input: startEvent.content_block.input || {},
                                inputJson: '',
                                status: 'preparing',
                                result: null,
                                error: null,
                                rawResult: null,
                                timestamp: new Date().toISOString(),
                                blockIndex: startEvent.index,
                                approved: null,
                                sessionId,
                            }
                            getSessionToolMap(sessionId).set(toolUse.id, toolUse)
                            getIndexMap(sessionId).set(startEvent.index, toolUse.id)
                            if (isCurrentSession && assistantMessage) {
                                // Update toolUses and replace message in array
                                const newToolUses = [...(assistantMessage.toolUses || []), toolUse]
                                assistantMessage.toolUses = newToolUses
                                const idx = messages.value.length - 1
                                const updatedMessage = { ...assistantMessage }
                                messages.value = [...messages.value.slice(0, idx), updatedMessage, ...messages.value.slice(idx + 1)]
                                assistantMessage = updatedMessage
                            }
                        }
                        break
                    }

                    case 'content_block_delta': {
                        const deltaEvent = event as SSEContentBlockDelta
                        if (deltaEvent.delta.type === 'text_delta' && isCurrentSession && assistantMessage) {
                            // Update content and replace message in array to trigger reactivity
                            assistantMessage.content += nbspRegexOp(deltaEvent.delta.text || '')
                            const idx = messages.value.length - 1
                            const updatedMessage = { ...assistantMessage }
                            messages.value = [...messages.value.slice(0, idx), updatedMessage, ...messages.value.slice(idx + 1)]
                            // Update reference so next delta uses the new object
                            assistantMessage = updatedMessage
                            callbacks?.onTextDelta?.(deltaEvent.delta.text || '')
                        } else if (deltaEvent.delta.type === 'input_json_delta') {
                            const idMap = getIndexMap(sessionId)
                            const toolId = idMap.get(deltaEvent.index)
                            const toolUse = toolId ? getSessionToolMap(sessionId).get(toolId) : undefined
                            if (toolUse) {
                                toolUse.inputJson += deltaEvent.delta.partial_json || ''
                            }
                        }
                        break
                    }

                    case 'content_block_stop': {
                        const stopEvent = event as SSEContentBlockStop
                        const idMap = getIndexMap(sessionId)
                        const toolId = idMap.get(stopEvent.index)
                        const toolUse = toolId ? getSessionToolMap(sessionId).get(toolId) : undefined
                        if (toolUse && toolUse.status === 'preparing') {
                            try {
                                if (toolUse.inputJson) {
                                    toolUse.input = JSON.parse(toolUse.inputJson)
                                }
                                if (shouldAutoApproveTool(toolUse.name) && !checkContextLimitReached()) {
                                    toolUse.approved = true
                                    queueTool(sessionId, toolUse.id)
                                } else {
                                    toolUse.status = 'pending_approval'
                                    toolUse.approved = null
                                    mostRecentFloatingTool.set(sessionId, toolUse)
                                }
                                callbacks?.onToolUse?.(toolUse)
                            } catch (err) {
                                toolUse.status = 'error'
                                toolUse.error = 'Failed to parse tool input'
                            }
                        }
                        if (stopEvent.usage) {
                            messageUsage = stopEvent.usage
                        }
                        break
                    }

                    case 'message_delta': {
                        const deltaEvent = event as SSEMessageDelta
                        if (deltaEvent.usage && isCurrentSession) {
                            messageUsage = deltaEvent.usage
                        }
                        break
                    }

                    case 'message_stop':
                        if (isCurrentSession && assistantMessage && messageUsage) {
                            assistantMessage.usage = messageUsage
                            updateContextLength(messageUsage)
                            updateCreditsUsed(messageUsage)
                            // Replace message in array for final update
                            const idx = messages.value.length - 1
                            messages.value = [...messages.value.slice(0, idx), { ...assistantMessage }, ...messages.value.slice(idx + 1)]
                            callbacks?.onMessageStop?.(messageUsage)
                        }
                        assistantMessage = null
                        messageUsage = null
                        break

                    case 'error': {
                        const errorEvent = event as SSEError
                        callbacks?.onError?.(errorEvent.error.message)
                        break
                    }
                }
            }
        }

        isStreaming.value = false
        await fetchBalance()
        await fetchSessions()

    } catch (error) {
        isTyping.value = false
        isStreaming.value = false

        const errorMessage: Message = {
            role: 'assistant',
            content: 'An error occurred while processing your request.',
            timestamp: new Date().toISOString(),
        }
        messages.value.push(errorMessage)
        callbacks?.onError?.(error instanceof Error ? error.message : 'Unknown error')
    }

    if (activeStreamingSessionId.value === sessionId) {
        activeStreamingSessionId.value = null
    }
}

// ============================================================================
// Tool Execution
// ============================================================================

function queueTool(sessionId: string, toolUseId: string): void {
    const q = toolQueues.get(sessionId) || []
    q.push(toolUseId)
    toolQueues.set(sessionId, q)
    runToolQueue(sessionId)
}

async function runToolQueue(sessionId: string): Promise<void> {
    if (toolRunnerBusy.has(sessionId)) return
    toolRunnerBusy.add(sessionId)

    try {
        let q = toolQueues.get(sessionId) || []
        const toolMap = getSessionToolMap(sessionId)

        while (q.length) {
            const toolUseId = q[0]
            const toolUse = toolMap.get(toolUseId)

            if (!toolUse || ['completed', 'error', 'rejected'].includes(toolUse.status)) {
                q.shift()
                continue
            }

            toolUse.status = 'executing'
            await executeTool(toolUse)
            q.shift()
            q = toolQueues.get(sessionId) || []
        }
    } finally {
        toolRunnerBusy.delete(sessionId)
    }
}

async function executeTool(toolUse: ToolUse): Promise<void> {
    const sessionId = toolUse.sessionId || currentSessionId.value || ''

    try {
        const toolRequest = {
            sessionId,
            toolUseId: toolUse.id,
            params: toolUse.input,
            model: settings.currentModel,
            auxData: undefined as any,
        }

        // Apply tool-specific changes
        if (toolUse.name === 'query_cases') {
            const rawMRU = localStorage.getItem('settings.case.mruCases')
            if (rawMRU) {
                toolRequest.auxData = JSON.parse(rawMRU)
            }
        }

        const response = await fetch(`/api/assistant/tool/${toolUse.name}`, {
            method: 'POST',
            headers: getApiHeaders(true, true),
            body: JSON.stringify(toolRequest),
        })

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`)
        }

        const reader = response.body?.getReader()
        if (!reader) throw new Error('No response body')

        const decoder = new TextDecoder()
        const isCurrentSession = currentSessionId.value === sessionId

        if (isCurrentSession) {
            isStreaming.value = true
        }

        let assistantMessage: Message | null = null
        let chunks: string[] = []
        let partial = false
        let messageUsage: Usage | null = null

        while (true) {
            const { done, value } = await reader.read()
            if (done) break

            const chunkResult = processStreamingChunks(decoder.decode(value), chunks, partial)
            chunks = chunkResult.chunks
            partial = chunkResult.partial

            for (let i = 0; i < chunks.length; i++) {
                if (chunks[i] === '[DONE]') {
                    assistantMessage = null
                    continue
                }

                const parseResult = parseJsonChunk(chunks[i])

                if (!parseResult.success) {
                    if (parseResult.isPartial) {
                        partial = true
                        chunks = [parseResult.isPartial]
                        break
                    }
                    continue
                }

                if (Array.isArray(parseResult.data)) {
                    chunks.splice(i, 1, ...parseResult.data)
                    i--
                    if (parseResult.isPartial) {
                        partial = true
                        chunks.push(parseResult.isPartial)
                    }
                    continue
                }

                const event = parseResult.data as SSEEvent

                switch (event.type) {
                    case 'error': {
                        const errorEvent = event as SSEError
                        throw new Error(errorEvent.error.message)
                    }

                    case 'message_start':
                        if (isCurrentSession) {
                            // Capture raw tool result after a delay
                            setTimeout(() => captureRawToolResult(toolUse, sessionId), 1000)

                            assistantMessage = {
                                role: 'assistant',
                                content: '',
                                timestamp: new Date().toISOString(),
                                usage: null,
                                toolUses: [],
                                isToolResult: true,
                                toolName: toolUse.name,
                                toolId: toolUse.id,
                            }
                            // Replace array to trigger reactivity
                            messages.value = [...messages.value, assistantMessage]
                            if ((event as SSEMessageStart).message?.usage) {
                                messageUsage = (event as SSEMessageStart).message!.usage!
                            }
                        }
                        break

                    case 'content_block_start': {
                        const startEvent = event as SSEContentBlockStart
                        if (startEvent.content_block?.type === 'tool_use') {
                            const newToolUse: ToolUse = {
                                id: startEvent.content_block.id || '',
                                name: startEvent.content_block.name || '',
                                input: startEvent.content_block.input || {},
                                inputJson: '',
                                status: 'preparing',
                                result: null,
                                error: null,
                                rawResult: null,
                                timestamp: new Date().toISOString(),
                                blockIndex: startEvent.index,
                                approved: null,
                                sessionId,
                            }
                            getSessionToolMap(sessionId).set(newToolUse.id, newToolUse)
                            getIndexMap(sessionId).set(startEvent.index, newToolUse.id)
                            if (isCurrentSession && assistantMessage) {
                                // Update toolUses and replace message in array
                                const newToolUses = [...(assistantMessage.toolUses || []), newToolUse]
                                assistantMessage.toolUses = newToolUses
                                const idx = messages.value.length - 1
                                const updatedMessage = { ...assistantMessage }
                                messages.value = [...messages.value.slice(0, idx), updatedMessage, ...messages.value.slice(idx + 1)]
                                assistantMessage = updatedMessage
                            }
                        }
                        break
                    }

                    case 'content_block_delta': {
                        const deltaEvent = event as SSEContentBlockDelta
                        if (deltaEvent.delta.type === 'text_delta' && isCurrentSession && assistantMessage) {
                            // Update content and replace message in array to trigger reactivity
                            assistantMessage.content += nbspRegexOp(deltaEvent.delta.text || '')
                            const idx = messages.value.length - 1
                            const updatedMessage = { ...assistantMessage }
                            messages.value = [...messages.value.slice(0, idx), updatedMessage, ...messages.value.slice(idx + 1)]
                            // Update reference so next delta uses the new object
                            assistantMessage = updatedMessage
                        } else if (deltaEvent.delta.type === 'input_json_delta') {
                            const idMap = getIndexMap(sessionId)
                            const toolId = idMap.get(deltaEvent.index)
                            const chainedToolUse = toolId ? getSessionToolMap(sessionId).get(toolId) : undefined
                            if (chainedToolUse) {
                                chainedToolUse.inputJson += deltaEvent.delta.partial_json || ''
                            }
                        }
                        break
                    }

                    case 'content_block_stop': {
                        const stopEvent = event as SSEContentBlockStop
                        const idMap = getIndexMap(sessionId)
                        const toolId = idMap.get(stopEvent.index)
                        const chainedToolUse = toolId ? getSessionToolMap(sessionId).get(toolId) : undefined
                        if (chainedToolUse && chainedToolUse.status === 'preparing') {
                            try {
                                if (chainedToolUse.inputJson) {
                                    chainedToolUse.input = JSON.parse(chainedToolUse.inputJson)
                                }
                                if (shouldAutoApproveTool(chainedToolUse.name) && !checkContextLimitReached()) {
                                    chainedToolUse.approved = true
                                    queueTool(sessionId, chainedToolUse.id)
                                } else {
                                    chainedToolUse.status = 'pending_approval'
                                    chainedToolUse.approved = null
                                    mostRecentFloatingTool.set(sessionId, chainedToolUse)
                                }
                            } catch (err) {
                                chainedToolUse.status = 'error'
                                chainedToolUse.error = 'Failed to parse tool input'
                            }
                        }
                        if (stopEvent.usage) {
                            messageUsage = stopEvent.usage
                        }
                        break
                    }

                    case 'message_delta': {
                        const deltaEvent = event as SSEMessageDelta
                        if (deltaEvent.usage && isCurrentSession) {
                            messageUsage = deltaEvent.usage
                        }
                        break
                    }

                    case 'message_stop':
                        if (isCurrentSession && assistantMessage && messageUsage) {
                            assistantMessage.usage = messageUsage
                            updateContextLength(messageUsage)
                            updateCreditsUsed(messageUsage)
                            // Replace message in array for final update
                            const idx = messages.value.length - 1
                            messages.value = [...messages.value.slice(0, idx), { ...assistantMessage }, ...messages.value.slice(idx + 1)]
                        }
                        assistantMessage = null
                        messageUsage = null
                        break
                }
            }
        }

        if (isCurrentSession) {
            isStreaming.value = false
            await fetchBalance()
        }

    } catch (error) {
        toolUse.status = 'error'
        toolUse.error = error instanceof Error ? error.message : 'Unknown error'

        if (currentSessionId.value === sessionId) {
            isStreaming.value = false

            const errorMessage: Message = {
                role: 'assistant',
                content: `Error executing tool "${toolUse.name}": ${toolUse.error}`,
                timestamp: new Date().toISOString(),
                isToolResult: true,
                toolName: toolUse.name,
                toolId: toolUse.id,
            }
            messages.value.push(errorMessage)
        }
    }
}

async function captureRawToolResult(toolUse: ToolUse, sessionId: string): Promise<void> {
    try {
        const details = await fetchSessionDetails(sessionId)
        if (details?.history) {
            for (let i = details.history.length - 1; i >= 0; i--) {
                const msg = details.history[i]
                if (msg.tags && msg.tags.includes('tool_result')) {
                    const resultBlock = msg.message.contentBlocks?.find(block => block.toolResult)
                    if (resultBlock?.toolResult?.content?.length) {
                        const cb = resultBlock.toolResult.content[0]
                        if (resultBlock.toolResult.isError || resultBlock.toolResult.status === 'error') {
                            toolUse.error = cb.text || 'Unknown error'
                            toolUse.status = 'error'
                        } else {
                            toolUse.rawResult = cb.json
                            toolUse.status = 'completed'
                        }
                        toolUse.completedAt = msg.createTime
                        break
                    }
                }
            }
        }
    } catch (error) {
        console.error('Error capturing raw tool result:', error)
    }
}

async function approveTool(toolUse: ToolUse): Promise<void> {
    if (checkContextLimitReached()) return
    toolUse.approved = true
    toolUse.status = 'preparing'
    mostRecentFloatingTool.delete(toolUse.sessionId || currentSessionId.value || '')
    queueTool(toolUse.sessionId || currentSessionId.value || '', toolUse.id)
}

async function rejectTool(toolUse: ToolUse): Promise<void> {
    if (checkContextLimitReached()) return
    toolUse.approved = false
    toolUse.status = 'rejected'
    toolUse.error = 'Tool use rejected by the user'
    mostRecentFloatingTool.delete(toolUse.sessionId || currentSessionId.value || '')

    // Send rejection message to AI
    const rejectionMessage = `The tool "${toolUse.name}" was rejected by the user.`
    await sendMessage(rejectionMessage)
}

// ============================================================================
// Investigation Mode
// ============================================================================

function generateInvestigationPrompt(fields: Record<string, string>): string {
    if (!assistantParams.value?.investigationPrompt) return ''

    let prompt = assistantParams.value.investigationPrompt
    const alertData = {
        socId: fields.socId || 'Unknown',
        ruleUuid: fields.ruleUuid || 'Unknown',
        ruleName: fields.ruleName || 'Unknown',
        severity: fields.severity || 'Unknown',
        timestamp: fields.timestamp || 'Unknown',
        sourceIp: fields.sourceIp || 'Unknown',
        destIp: fields.destIp || 'Unknown',
        eventModule: fields.eventModule || 'Unknown',
        eventDataset: fields.eventDataset || 'Unknown',
        message: fields.message || 'Unknown',
        alertRule: fields.alertRule || 'Unknown',
    }

    for (const [key, value] of Object.entries(alertData)) {
        prompt = prompt.replace(new RegExp(`{${key}}`, 'g'), value)
    }

    return prompt
}

// ============================================================================
// Context Compression
// ============================================================================

async function compressCurrentSession(): Promise<void> {
    if (!assistantParams.value?.compressContextPrompt || !currentSessionId.value) return

    contextLength.value = 0
    await sendMessage(assistantParams.value.compressContextPrompt, [MSGTAG_CONTEXTCOMPRESSION])
    await loadSession(currentSessionId.value)
}

// ============================================================================
// Initialize
// ============================================================================

function initializeParams(params: Partial<AssistantParams> | null): void {
    if (!params) {
        console.warn('No assistant params provided')
        return
    }

    assistantParams.value = {
        enabled: params.enabled ?? false,
        investigationPrompt: params.investigationPrompt ?? '',
        compressContextPrompt: params.compressContextPrompt ?? '',
        thresholdColorRatioLow: params.thresholdColorRatioLow ?? 0.5,
        thresholdColorRatioMed: params.thresholdColorRatioMed ?? 0.75,
        thresholdColorRatioMax: params.thresholdColorRatioMax ?? 1,
        availableModels: params.availableModels ?? [],
    }

    const models = assistantParams.value.availableModels || []
    availableModels.value = models.filter(m => m.enabled)
    modelsMap.value = new Map(availableModels.value.map(m => [m.id, m]))

    // Set default model if not set
    if (!settings.currentModel || !modelsMap.value.has(settings.currentModel)) {
        if (availableModels.value.length > 0) {
            settings.currentModel = availableModels.value[0].id
        }
    }
}

// Load settings on module initialization
loadSettings()

// ============================================================================
// Export Composable
// ============================================================================

export function useAssistant() {
    return {
        // State
        sessions,
        sessionsById,
        messages,
        currentSessionId,
        balance,
        settings,
        availableModels,
        assistantParams,

        // Loading states
        loadingSessions,
        loadingMessages,
        loadingBalance,
        isStreaming,
        isTyping,

        // Computed
        currentModel,
        contextLimitSmall,
        contextLimitLarge,
        maxContextLimit,
        lowBalanceColorAlert,
        creditsRemaining,
        isHealthy,
        canChat,
        contextLength,
        creditsUsed,
        contextStartMessageIndex,

        // API functions
        fetchSessions,
        fetchSessionDetails,
        deleteSession,
        fetchBalance,
        updateSessionTag,

        // Chat functions
        loadSession,
        startNewChat,
        sendMessage,

        // Tool functions
        approveTool,
        rejectTool,
        getSessionToolMap,
        mostRecentFloatingTool,

        // Investigation
        generateInvestigationPrompt,

        // Context compression
        compressCurrentSession,
        checkContextLimitReached,

        // Settings
        loadSettings,
        saveSettings,
        saveCurrentSessionId,
        loadCurrentSessionId,

        // Initialization
        initializeParams,
        setSrvToken,

        // Constants
        MSGTAG_CONTEXTCOMPRESSION,
        SESTAG_SHARED,
    }
}
