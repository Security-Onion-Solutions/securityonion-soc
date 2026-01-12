/**
 * Composable for Chat Widget state management.
 * Handles widget-specific state separate from the assistant state.
 */
import { ref, watch } from 'vue'

const STORAGE_KEY = 'settings.chatWidget'

// ============================================================================
// Module-level State (shared across all component instances)
// ============================================================================

const isOpen = ref(false)
const showSidebar = ref(false)
const panelWidth = ref(420)
const pendingPrompt = ref<string | null>(null) // Prompt to send when widget opens
const shouldStartNewChat = ref(false) // Whether to start a new chat before sending

// Constraints
const MIN_WIDTH = 360
const MAX_WIDTH = 1200
const DEFAULT_WIDTH = 420

// ============================================================================
// localStorage Persistence
// ============================================================================

function loadSettings(): void {
    try {
        const stored = localStorage.getItem(STORAGE_KEY)
        if (stored) {
            const settings = JSON.parse(stored)
            isOpen.value = settings.isOpen ?? false
            showSidebar.value = settings.showSidebar ?? false
            panelWidth.value = settings.panelWidth ?? DEFAULT_WIDTH
        }
    } catch (e) {
        console.error('Error loading chat widget settings:', e)
    }
}

function saveSettings(): void {
    try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify({
            isOpen: isOpen.value,
            showSidebar: showSidebar.value,
            panelWidth: panelWidth.value,
        }))
    } catch (e) {
        console.error('Error saving chat widget settings:', e)
    }
}

// Auto-save on changes
watch([isOpen, showSidebar, panelWidth], saveSettings, { deep: true })

// Load on module initialization
loadSettings()

// ============================================================================
// Actions
// ============================================================================

function expand(): void {
    isOpen.value = true
}

function collapse(): void {
    isOpen.value = false
}

function toggle(): void {
    isOpen.value = !isOpen.value
}

function toggleSidebar(): void {
    showSidebar.value = !showSidebar.value
}

function resize(width: number): void {
    panelWidth.value = Math.max(MIN_WIDTH, Math.min(width, MAX_WIDTH))
}

function resetSize(): void {
    panelWidth.value = DEFAULT_WIDTH
}

function openWithPrompt(prompt: string): void {
    pendingPrompt.value = prompt
    shouldStartNewChat.value = false
    isOpen.value = true
}

function openNewChatWithPrompt(prompt: string): void {
    pendingPrompt.value = prompt
    shouldStartNewChat.value = true
    isOpen.value = true
}

function clearPendingPrompt(): void {
    pendingPrompt.value = null
    shouldStartNewChat.value = false
}

// ============================================================================
// Export Composable
// ============================================================================

export function useChatWidget() {
    return {
        // State
        isOpen,
        showSidebar,
        panelWidth,
        pendingPrompt,
        shouldStartNewChat,

        // Constants
        MIN_WIDTH,
        MAX_WIDTH,
        DEFAULT_WIDTH,

        // Actions
        expand,
        collapse,
        toggle,
        toggleSidebar,
        resize,
        resetSize,
        openWithPrompt,
        openNewChatWithPrompt,
        clearPendingPrompt,

        // Persistence
        loadSettings,
        saveSettings,
    }
}
