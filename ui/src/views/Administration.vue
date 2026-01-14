<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import UsersView from './admin/Users.vue'
import GridMembersView from './admin/GridMembers.vue'
import ConfigView from './admin/Config.vue'
import LicenseView from './admin/License.vue'

const route = useRoute()

// Placeholder components for future implementation
const AiMetricsView = { template: '<div class="p-4">AI Metrics View (Pending Implementation)</div>' }
const ClientsView = { template: '<div class="p-4">Clients View (Pending Implementation)</div>' }
const QueriesView = { template: '<div class="p-4">Active Queries View (Pending Implementation)</div>' }

// Get tab from route params (with fallback to props for compatibility)
const props = defineProps<{ tab?: string }>()
const activeTab = computed(() => (route.params.tab as string) || props.tab || 'users')

const components: Record<string, any> = {
  users: UsersView,
  grid: GridMembersView,
  config: ConfigView,
  license: LicenseView,
  aimetrics: AiMetricsView,
  clients: ClientsView,
  queries: QueriesView
}

const currentComponent = computed(() => {
  return components[activeTab.value] || UsersView
})

</script>

<template>
  <div class="flex flex-col h-full bg-background text-foreground">
    <!-- Header -->
    <header class="border-b border-border bg-card px-6 py-4">
      <h1 class="text-2xl font-bold flex items-center gap-2">
        Administration
      </h1>
      <p class="text-muted-foreground text-sm mt-1">
        Manage system settings, users, and grid configuration.
      </p>
    </header>

    <!-- Content -->
    <div class="flex flex-1 overflow-hidden">
      <!-- Main View Area -->
      <main class="flex-1 overflow-y-auto bg-background p-6">
         <Transition name="fade" mode="out-in">
            <component :is="currentComponent" />
         </Transition>
      </main>
    </div>
  </div>
</template>

<style scoped>
.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.2s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>
