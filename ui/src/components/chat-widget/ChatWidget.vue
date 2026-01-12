<script setup lang="ts">
import { useChatWidget } from '@/composables/useChatWidget'
import ChatWidgetPanel from './ChatWidgetPanel.vue'

const emit = defineEmits<{
    openFull: []
    navigateToEvent: [eventId: string, query?: string]
}>()

const { isOpen, collapse } = useChatWidget()

function handleOpenFull(): void {
    collapse()
    emit('openFull')
}

function handleNavigateToEvent(eventId: string, query?: string): void {
    emit('navigateToEvent', eventId, query)
}
</script>

<template>
    <aside
        v-if="isOpen"
        class="h-screen shrink-0 shadow-2xl"
    >
        <ChatWidgetPanel
            @close="collapse"
            @open-full="handleOpenFull"
            @navigate-to-event="handleNavigateToEvent"
        />
    </aside>
</template>
