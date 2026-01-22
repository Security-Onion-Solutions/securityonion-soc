
<script setup lang="ts">
import { ref, computed, onMounted, nextTick } from 'vue'
import { useRoute, useRouter, onBeforeRouteLeave } from 'vue-router'
import {
  Home,
  Settings,
  LogOut,
  Bell,
  Search,
  LayoutGrid,
  Shield,
  Activity,
  Menu,
  RotateCcw,
  Server,
  ShieldAlert,
  Briefcase,
  Bot,
  Users,
  Key,
  UserCog,
  FileText,
  ChevronDown,
  BookOpen
} from 'lucide-vue-next'
import ChatWidget from './components/chat-widget/ChatWidget.vue'
import UserMenu from './components/common/UserMenu.vue'

import { cn } from './lib/utils'
import { useChatWidget } from './composables/useChatWidget'

const route = useRoute()
const router = useRouter()

const { isOpen: isChatOpen, toggle: toggleChat, collapse: closeChat } = useChatWidget()

const sidebarOpen = ref(true)
const adminExpanded = ref(false)

// Scroll position preservation for keep-alive routes
const mainContentRef = ref<HTMLElement | null>(null)
const scrollPositions = new Map<string, number>()

// Save scroll position before leaving a route
router.beforeEach((to, from) => {
  if (mainContentRef.value && from.name) {
    scrollPositions.set(String(from.name), mainContentRef.value.scrollTop)
  }
})

// Restore scroll position after navigation
router.afterEach((to) => {
  nextTick(() => {
    if (mainContentRef.value && to.name) {
      const savedPosition = scrollPositions.get(String(to.name))
      if (savedPosition !== undefined) {
        mainContentRef.value.scrollTop = savedPosition
      } else {
        mainContentRef.value.scrollTop = 0
      }
    }
  })
})

onMounted(() => {
  // Handle login flow redirect
  const params = new URLSearchParams(window.location.search)
  if (params.get('flow')) {
    router.push({ name: 'login', query: { flow: params.get('flow') } })
  }
})

function toggleSidebar() {
  sidebarOpen.value = !sidebarOpen.value
}

function switchToClassic() {
  localStorage.setItem('preferred_interface', 'classic')
  window.location.href = '/'
}

async function logout() {
  try {
    const response = await fetch('/auth/self-service/logout/browser', {
        headers: {
            'Accept': 'application/json'
        }
    })
    const data = await response.json()
    if (data.logout_url) {
      window.location.href = data.logout_url
    } else {
        console.error("No logout_url found in response")
    }
  } catch (error) {
    console.error('Logout failed:', error)
  }
}

// Current route name for sidebar highlighting
const currentRouteName = computed(() => route.name as string)

// Check if we're on an admin page
const isAdminRoute = computed(() => currentRouteName.value === 'administration')
const currentAdminTab = computed(() => route.params.tab as string || 'users')

// Routes where the chat widget should be visible
const showChatWidget = computed(() => route.meta.showChatWidget === true)

// Page title from route meta
const pageTitle = computed(() => {
  const title = route.meta.title as string
  if (isAdminRoute.value) {
    return `Administration - ${currentAdminTab.value.charAt(0).toUpperCase() + currentAdminTab.value.slice(1)}`
  }
  return title || 'Security Onion'
})

function openAssistantFromWidget() {
  closeChat()
  router.push({ name: 'assistant' })
}

function navigateToEventFromChat(eventId: string, query?: string) {
  const q = query || `_id:"${eventId}"`
  router.push({ name: 'hunt', query: { q } })
}

// Check if sidebar item is active
function isActive(routeName: string | string[]): boolean {
  const names = Array.isArray(routeName) ? routeName : [routeName]
  return names.includes(currentRouteName.value)
}
</script>

<template>
  <div v-if="currentRouteName === 'login'">
    <router-view />
  </div>
  <div v-else class="flex min-h-screen w-full bg-background text-foreground">
    <!-- Sidebar -->
    <aside
      :class="cn(
        'fixed left-0 top-0 z-40 h-screen bg-card border-r border-border transition-all duration-300 overflow-y-auto',
        sidebarOpen ? 'w-64' : 'w-16'
      )"
    >
      <div class="flex h-16 items-center justify-between px-4 border-b border-border sticky top-0 bg-card z-10">
        <div v-if="sidebarOpen" class="flex items-center gap-2 font-bold text-xl text-primary">
          <Shield class="h-6 w-6" />
          <span>Security Onion</span>
        </div>
        <button v-else @click="toggleSidebar" class="mx-auto p-1 hover:bg-muted rounded transition-colors">
          <Menu class="h-6 w-6 text-primary" />
        </button>
        <button v-if="sidebarOpen" @click="toggleSidebar" class="p-1 hover:bg-muted rounded text-muted-foreground">
          <Menu class="h-5 w-5" />
        </button>
      </div>

      <nav class="p-2 space-y-1">
        <router-link to="/" :class="cn('flex items-center gap-3 px-3 py-2 rounded-md transition-colors', isActive('home') ? 'bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-muted hover:text-foreground')">
          <Home class="h-5 w-5" />
          <span v-if="sidebarOpen">Overview</span>
        </router-link>
        <router-link to="/alerts" :class="cn('flex items-center gap-3 px-3 py-2 rounded-md transition-colors', isActive('alerts') ? 'bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-muted hover:text-foreground')">
          <Bell class="h-5 w-5" />
          <span v-if="sidebarOpen">Alerts</span>
        </router-link>
        <router-link to="/hunt" :class="cn('flex items-center gap-3 px-3 py-2 rounded-md transition-colors', isActive('hunt') ? 'bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-muted hover:text-foreground')">
          <Search class="h-5 w-5" />
          <span v-if="sidebarOpen">Hunt</span>
        </router-link>
        <router-link to="/dashboards" :class="cn('flex items-center gap-3 px-3 py-2 rounded-md transition-colors', isActive('dashboards') ? 'bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-muted hover:text-foreground')">
          <LayoutGrid class="h-5 w-5" />
          <span v-if="sidebarOpen">Dashboards</span>
        </router-link>
        <router-link to="/grid" :class="cn('flex items-center gap-3 px-3 py-2 rounded-md transition-colors', isActive('grid') ? 'bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-muted hover:text-foreground')">
          <Server class="h-5 w-5" />
          <span v-if="sidebarOpen">Grid</span>
        </router-link>
        <router-link to="/detections" :class="cn('flex items-center gap-3 px-3 py-2 rounded-md transition-colors', isActive(['detections', 'detection-detail']) ? 'bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-muted hover:text-foreground')">
          <ShieldAlert class="h-5 w-5" />
          <span v-if="sidebarOpen">Detections</span>
        </router-link>
        <router-link to="/jobs" :class="cn('flex items-center gap-3 px-3 py-2 rounded-md transition-colors', isActive(['jobs', 'job-detail']) ? 'bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-muted hover:text-foreground')">
          <FileText class="h-5 w-5" />
          <span v-if="sidebarOpen">PCAP</span>
        </router-link>
        <router-link to="/cases" :class="cn('flex items-center gap-3 px-3 py-2 rounded-md transition-colors', isActive(['cases', 'case-detail']) ? 'bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-muted hover:text-foreground')">
          <Briefcase class="h-5 w-5" />
          <span v-if="sidebarOpen">Cases</span>
        </router-link>
        <router-link to="/playbooks" :class="cn('flex items-center gap-3 px-3 py-2 rounded-md transition-colors', isActive('playbooks') ? 'bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-muted hover:text-foreground')">
          <BookOpen class="h-5 w-5" />
          <span v-if="sidebarOpen">Playbooks</span>
        </router-link>
        <router-link to="/assistant" :class="cn('flex items-center gap-3 px-3 py-2 rounded-md transition-colors', isActive('assistant') ? 'bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-muted hover:text-foreground')">
          <Bot class="h-5 w-5" />
          <span v-if="sidebarOpen">AI Assistant</span>
        </router-link>
        <div class="pt-4 border-t border-border mt-4">
             <button
               @click="adminExpanded = !adminExpanded"
               :class="cn('w-full flex items-center gap-3 px-3 py-2 rounded-md transition-colors text-muted-foreground hover:bg-muted hover:text-foreground', isAdminRoute && 'text-primary')"
             >
                <Settings class="h-5 w-5" />
                <span v-if="sidebarOpen" class="flex-1 text-left text-xs font-semibold uppercase tracking-wider">Administration</span>
                <ChevronDown v-if="sidebarOpen" :class="cn('h-4 w-4 transition-transform', adminExpanded && 'rotate-180')" />
             </button>
             <div v-show="adminExpanded" class="space-y-1 mt-1">
               <router-link to="/admin/users" :class="cn('flex items-center gap-3 px-3 py-2 rounded-md transition-colors', sidebarOpen && 'pl-6', isAdminRoute && currentAdminTab === 'users' ? 'bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-muted hover:text-foreground')">
                  <Users class="h-5 w-5" />
                  <span v-if="sidebarOpen">Users</span>
              </router-link>
              <router-link to="/admin/grid" :class="cn('flex items-center gap-3 px-3 py-2 rounded-md transition-colors', sidebarOpen && 'pl-6', isAdminRoute && currentAdminTab === 'grid' ? 'bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-muted hover:text-foreground')">
                  <Server class="h-5 w-5" />
                  <span v-if="sidebarOpen">Grid Members</span>
              </router-link>
              <router-link to="/admin/config" :class="cn('flex items-center gap-3 px-3 py-2 rounded-md transition-colors', sidebarOpen && 'pl-6', isAdminRoute && currentAdminTab === 'config' ? 'bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-muted hover:text-foreground')">
                  <Settings class="h-5 w-5" />
                  <span v-if="sidebarOpen">Configuration</span>
              </router-link>
               <router-link to="/admin/license" :class="cn('flex items-center gap-3 px-3 py-2 rounded-md transition-colors', sidebarOpen && 'pl-6', isAdminRoute && currentAdminTab === 'license' ? 'bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-muted hover:text-foreground')">
                  <Key class="h-5 w-5" />
                  <span v-if="sidebarOpen">License</span>
              </router-link>
               <router-link to="/admin/aimetrics" :class="cn('flex items-center gap-3 px-3 py-2 rounded-md transition-colors', sidebarOpen && 'pl-6', isAdminRoute && currentAdminTab === 'aimetrics' ? 'bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-muted hover:text-foreground')">
                  <Activity class="h-5 w-5" />
                  <span v-if="sidebarOpen">AI Metrics</span>
              </router-link>
               <router-link to="/admin/clients" :class="cn('flex items-center gap-3 px-3 py-2 rounded-md transition-colors', sidebarOpen && 'pl-6', isAdminRoute && currentAdminTab === 'clients' ? 'bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-muted hover:text-foreground')">
                  <UserCog class="h-5 w-5" />
                  <span v-if="sidebarOpen">Clients</span>
              </router-link>
               <router-link to="/admin/queries" :class="cn('flex items-center gap-3 px-3 py-2 rounded-md transition-colors', sidebarOpen && 'pl-6', isAdminRoute && currentAdminTab === 'queries' ? 'bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-muted hover:text-foreground')">
                  <Search class="h-5 w-5" />
                  <span v-if="sidebarOpen">Active Queries</span>
              </router-link>
             </div>
        </div>
      </nav>

      <div class="px-2 py-4 space-y-1 border-t border-border mt-4">
         <button @click="switchToClassic" class="w-full flex items-center gap-3 px-3 py-2 rounded-md text-amber-500 hover:bg-amber-500/10 transition-colors">
          <RotateCcw class="h-5 w-5" />
          <span v-if="sidebarOpen">Back to Classic</span>
        </button>
         <a href="#" @click.prevent="logout" class="flex items-center gap-3 px-3 py-2 rounded-md text-muted-foreground hover:bg-muted hover:text-foreground transition-colors">
          <LogOut class="h-5 w-5" />
          <span v-if="sidebarOpen">Logout</span>
        </a>
      </div>
    </aside>

    <!-- Main Content Area (includes chat panel when open) -->
    <div
      :class="cn(
        'flex flex-1 transition-all duration-300 h-screen',
        sidebarOpen ? 'ml-64' : 'ml-16'
      )"
    >
    <!-- Main Content -->
    <main class="flex-1 h-screen bg-background min-w-0 flex flex-col">
      <header class="h-16 border-b border-border bg-card flex items-center justify-between px-6 shrink-0 z-30">
        <h1 class="text-xl font-semibold capitalize">{{ pageTitle }}</h1>
        <div class="flex items-center gap-4">
          <div class="bg-muted px-3 py-1 rounded-full text-sm font-medium">
            System Status: <span class="text-green-500">Healthy</span>
          </div>
          <!-- AI Assistant Toggle Button -->
          <button
            v-if="showChatWidget"
            @click="toggleChat"
            :class="cn(
              'flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm font-medium transition-all',
              isChatOpen
                ? 'bg-primary text-primary-foreground'
                : 'bg-primary/10 text-primary hover:bg-primary/20'
            )"
          >
            <Bot class="h-4 w-4" />
            <span class="hidden sm:inline">AI Assistant</span>
          </button>
          <UserMenu />
        </div>
      </header>

      <div ref="mainContentRef" class="flex-1 overflow-auto p-6">
        <router-view v-slot="{ Component }">
          <keep-alive :include="['Alerts', 'AlertGroupDetail', 'Detections', 'Cases', 'Hunt']">
            <component :is="Component" />
          </keep-alive>
        </router-view>
      </div>
    </main>

    <!-- Chat Widget Panel (integrated into layout, pushes content) -->
    <ChatWidget
      v-if="showChatWidget"
      @open-full="openAssistantFromWidget"
      @navigate-to-event="navigateToEventFromChat"
    />
    </div>
  </div>
</template>

<style>
@import './style.css';
</style>
