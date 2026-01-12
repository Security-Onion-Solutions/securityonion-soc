<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import {
    Plus,
    Search,
    Trash2,
    MessageSquare,
    PanelRightClose,
    PanelRight,
    MoreVertical
} from 'lucide-vue-next'
import { formatRelativeTime } from '@/composables/useFormatters'
import type { AssistantSession } from '@/composables/useAssistant'

const props = defineProps<{
    sessions: AssistantSession[]
    currentSessionId: string | null
    collapsed: boolean
    loading?: boolean
}>()

const emit = defineEmits<{
    select: [sessionId: string]
    delete: [sessionId: string]
    newChat: []
    toggle: []
}>()

const searchQuery = ref('')
const hoveredSessionId = ref<string | null>(null)
const deleteConfirmId = ref<string | null>(null)

const filteredSessions = computed(() => {
    if (!searchQuery.value.trim()) return props.sessions
    const query = searchQuery.value.toLowerCase()
    return props.sessions.filter(session =>
        session.title?.toLowerCase().includes(query)
    )
})

// Group sessions by date
const groupedSessions = computed(() => {
    const groups: { label: string; sessions: AssistantSession[] }[] = []
    const today = new Date()
    today.setHours(0, 0, 0, 0)
    const yesterday = new Date(today)
    yesterday.setDate(yesterday.getDate() - 1)
    const lastWeek = new Date(today)
    lastWeek.setDate(lastWeek.getDate() - 7)
    const lastMonth = new Date(today)
    lastMonth.setMonth(lastMonth.getMonth() - 1)

    const todaySessions: AssistantSession[] = []
    const yesterdaySessions: AssistantSession[] = []
    const lastWeekSessions: AssistantSession[] = []
    const lastMonthSessions: AssistantSession[] = []
    const olderSessions: AssistantSession[] = []

    for (const session of filteredSessions.value) {
        const sessionDate = new Date(session.createTime || '')
        sessionDate.setHours(0, 0, 0, 0)

        if (sessionDate.getTime() === today.getTime()) {
            todaySessions.push(session)
        } else if (sessionDate.getTime() === yesterday.getTime()) {
            yesterdaySessions.push(session)
        } else if (sessionDate > lastWeek) {
            lastWeekSessions.push(session)
        } else if (sessionDate > lastMonth) {
            lastMonthSessions.push(session)
        } else {
            olderSessions.push(session)
        }
    }

    if (todaySessions.length > 0) groups.push({ label: 'Today', sessions: todaySessions })
    if (yesterdaySessions.length > 0) groups.push({ label: 'Yesterday', sessions: yesterdaySessions })
    if (lastWeekSessions.length > 0) groups.push({ label: 'Last 7 Days', sessions: lastWeekSessions })
    if (lastMonthSessions.length > 0) groups.push({ label: 'Last 30 Days', sessions: lastMonthSessions })
    if (olderSessions.length > 0) groups.push({ label: 'Older', sessions: olderSessions })

    return groups
})

function handleDelete(sessionId: string, event: Event) {
    event.stopPropagation()
    if (deleteConfirmId.value === sessionId) {
        emit('delete', sessionId)
        deleteConfirmId.value = null
    } else {
        deleteConfirmId.value = sessionId
        // Auto-reset after 3 seconds
        setTimeout(() => {
            if (deleteConfirmId.value === sessionId) {
                deleteConfirmId.value = null
            }
        }, 3000)
    }
}

watch(() => props.collapsed, (collapsed) => {
    if (collapsed) {
        searchQuery.value = ''
    }
})
</script>

<template>
    <div
        class="flex flex-col h-full bg-card border-l border-border transition-all duration-300"
        :class="collapsed ? 'w-12' : 'w-72'"
    >
        <!-- Header -->
        <div class="flex items-center justify-between p-3 border-b border-border">
            <template v-if="!collapsed">
                <h3 class="text-sm font-semibold text-foreground">Chat History</h3>
            </template>
            <button
                class="p-1.5 rounded hover:bg-muted transition-colors text-muted-foreground hover:text-foreground"
                :title="collapsed ? 'Expand sidebar' : 'Collapse sidebar'"
                @click="emit('toggle')"
            >
                <PanelRight v-if="collapsed" class="h-4 w-4" />
                <PanelRightClose v-else class="h-4 w-4" />
            </button>
        </div>

        <!-- Collapsed state -->
        <template v-if="collapsed">
            <button
                class="p-3 hover:bg-muted transition-colors"
                title="New Chat"
                @click="emit('newChat')"
            >
                <Plus class="h-5 w-5 text-muted-foreground" />
            </button>
        </template>

        <!-- Expanded state -->
        <template v-else>
            <!-- New Chat Button -->
            <div class="p-3">
                <button
                    class="flex items-center justify-center gap-2 w-full px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition-colors text-sm font-medium"
                    @click="emit('newChat')"
                >
                    <Plus class="h-4 w-4" />
                    New Chat
                </button>
            </div>

            <!-- Search -->
            <div class="px-3 pb-3">
                <div class="relative">
                    <Search class="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                    <input
                        v-model="searchQuery"
                        type="text"
                        placeholder="Search chats..."
                        class="w-full pl-9 pr-4 py-2 bg-muted border border-border rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary/50"
                    />
                </div>
            </div>

            <!-- Sessions List -->
            <div class="flex-1 overflow-y-auto">
                <template v-if="loading">
                    <div class="flex items-center justify-center py-8">
                        <div class="animate-spin rounded-full h-6 w-6 border-2 border-primary border-t-transparent" />
                    </div>
                </template>
                <template v-else-if="groupedSessions.length === 0">
                    <div class="flex flex-col items-center justify-center py-8 px-4 text-center">
                        <MessageSquare class="h-8 w-8 text-muted-foreground mb-2" />
                        <p class="text-sm text-muted-foreground">
                            {{ searchQuery ? 'No chats found' : 'No chat history yet' }}
                        </p>
                        <p class="text-xs text-muted-foreground/70 mt-1">
                            {{ searchQuery ? 'Try a different search' : 'Start a new chat to begin' }}
                        </p>
                    </div>
                </template>
                <template v-else>
                    <div v-for="group in groupedSessions" :key="group.label" class="pb-2">
                        <!-- Group Label -->
                        <div class="px-3 py-1.5 text-xs font-medium text-muted-foreground/70 uppercase tracking-wider">
                            {{ group.label }}
                        </div>
                        <!-- Sessions in Group -->
                        <div class="space-y-0.5 px-2">
                            <div
                                v-for="session in group.sessions"
                                :key="session.sessionId"
                                class="group relative flex items-center gap-2 px-3 py-2 rounded-lg cursor-pointer transition-colors"
                                :class="currentSessionId === session.sessionId
                                    ? 'bg-primary/10 text-primary'
                                    : 'hover:bg-muted text-foreground'"
                                @mouseenter="hoveredSessionId = session.sessionId"
                                @mouseleave="hoveredSessionId = null"
                                @click="emit('select', session.sessionId)"
                            >
                                <MessageSquare class="h-4 w-4 flex-shrink-0" />
                                <div class="flex-1 min-w-0">
                                    <p class="text-sm truncate">
                                        {{ session.title || 'New Chat' }}
                                    </p>
                                    <p class="text-xs text-muted-foreground truncate">
                                        {{ formatRelativeTime(session.createTime) }}
                                    </p>
                                </div>
                                <!-- Delete Button -->
                                <button
                                    v-if="hoveredSessionId === session.sessionId || deleteConfirmId === session.sessionId"
                                    class="p-1 rounded transition-colors"
                                    :class="deleteConfirmId === session.sessionId
                                        ? 'bg-red-500 text-white'
                                        : 'hover:bg-muted text-muted-foreground hover:text-red-500'"
                                    :title="deleteConfirmId === session.sessionId ? 'Click again to confirm' : 'Delete chat'"
                                    @click="handleDelete(session.sessionId, $event)"
                                >
                                    <Trash2 class="h-3.5 w-3.5" />
                                </button>
                            </div>
                        </div>
                    </div>
                </template>
            </div>
        </template>
    </div>
</template>
