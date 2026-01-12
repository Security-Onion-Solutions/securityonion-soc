
<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import {
  Home,
  Settings,
  LogOut,
  Bell,
  Search,
  LayoutGrid,
  Shield,
  Activity,
  Database,
  Menu,
  RotateCcw,
  Server,
  ShieldAlert,
  Briefcase,
  Bot,
  Users,
  Key,
  UserCog,
  FileText
} from 'lucide-vue-next'
import Grid from './components/Grid.vue'
import Hunt from './views/Hunt.vue'
import Detections from './views/Detections.vue'
import DetectionDetail from './views/DetectionDetail.vue'
import Jobs from './views/Jobs.vue'
import JobDetail from './views/JobDetail.vue'
import Cases from './views/Cases.vue'
import CaseDetail from './views/CaseDetail.vue'
import Assistant from './views/Assistant.vue'
import Administration from './views/Administration.vue'
import Overview from './views/Overview.vue'
import ChatWidget from './components/chat-widget/ChatWidget.vue'

import Login from './views/Login.vue'
import { cn } from './lib/utils'
import { useChatWidget } from './composables/useChatWidget'

const { isOpen: isChatOpen, toggle: toggleChat, collapse: closeChat } = useChatWidget()

const sidebarOpen = ref(true)

onMounted(() => {
  const params = new URLSearchParams(window.location.search)
  if (params.get('flow')) {
    activeRoute.value = 'login'
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
        // Fallback or error handling?
        console.error("No logout_url found in response")
    }
  } catch (error) {
    console.error('Logout failed:', error)
  }
}

const activeRoute = ref('home')
const activeAdminTab = ref('users')

function navigateToAdmin(tab: string) {
  activeRoute.value = 'administration'
  activeAdminTab.value = tab
}

const selectedDetectionId = ref<string | null>(null)

function navigateToDetection(id: string) {
  selectedDetectionId.value = id
  activeRoute.value = 'detection-detail'
}

const selectedCaseId = ref<string | null>(null)

function navigateToCase(id: string) {
  selectedCaseId.value = id
  activeRoute.value = 'case-detail'
}

const selectedJobId = ref<string | null>(null)

function navigateToJob(id: string) {
  selectedJobId.value = id
  activeRoute.value = 'job-detail'
}

const selectedAssistantSessionId = ref<string | null>(null)

function navigateToAssistantSession(sessionId: string) {
  selectedAssistantSessionId.value = sessionId
}

// Routes where the chat widget should be visible
const chatWidgetRoutes = ['home', 'hunt', 'alerts', 'cases', 'case-detail', 'detections', 'detection-detail']
const showChatWidget = computed(() => chatWidgetRoutes.includes(activeRoute.value))

// Hunt query for event navigation from chat
const huntQuery = ref<string | null>(null)

function openAssistantFromWidget() {
  closeChat()
  activeRoute.value = 'assistant'
}

function navigateToEventFromChat(eventId: string, query?: string) {
  // Navigate to Hunt with the event query
  huntQuery.value = query || `_id:"${eventId}"`
  activeRoute.value = 'hunt'
}
</script>

<template>
  <Login v-if="activeRoute === 'login'" />
  <div v-else class="flex min-h-screen w-full bg-background text-foreground">
    <!-- Sidebar -->
    <aside 
      :class="cn(
        'fixed left-0 top-0 z-40 h-screen bg-card border-r border-border transition-all duration-300',
        sidebarOpen ? 'w-64' : 'w-16'
      )"
    >
      <div class="flex h-16 items-center justify-between px-4 border-b border-border">
        <div v-if="sidebarOpen" class="flex items-center gap-2 font-bold text-xl text-primary">
          <Shield class="h-6 w-6" />
          <span>Security Onion</span>
        </div>
        <div v-else class="mx-auto">
          <Shield class="h-6 w-6 text-primary" />
        </div>
        <button v-if="sidebarOpen" @click="toggleSidebar" class="p-1 hover:bg-muted rounded text-muted-foreground">
          <Menu class="h-5 w-5" />
        </button>
      </div>

      <nav class="p-2 space-y-1">
        <a href="#" @click.prevent="activeRoute = 'home'" :class="cn('flex items-center gap-3 px-3 py-2 rounded-md transition-colors', activeRoute === 'home' ? 'bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-muted hover:text-foreground')">
          <Home class="h-5 w-5" />
          <span v-if="sidebarOpen">Overview</span>
        </a>
        <a href="#" @click.prevent="activeRoute = 'alerts'" :class="cn('flex items-center gap-3 px-3 py-2 rounded-md transition-colors', activeRoute === 'alerts' ? 'bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-muted hover:text-foreground')">
          <Bell class="h-5 w-5" />
          <span v-if="sidebarOpen">Alerts</span>
        </a>
        <a href="#" @click.prevent="activeRoute = 'hunt'" :class="cn('flex items-center gap-3 px-3 py-2 rounded-md transition-colors', activeRoute === 'hunt' ? 'bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-muted hover:text-foreground')">
          <Search class="h-5 w-5" />
          <span v-if="sidebarOpen">Hunt</span>
        </a>
        <a href="#" @click.prevent="activeRoute = 'dashboards'" :class="cn('flex items-center gap-3 px-3 py-2 rounded-md transition-colors', activeRoute === 'dashboards' ? 'bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-muted hover:text-foreground')">
  <LayoutGrid class="h-5 w-5" />
          <span v-if="sidebarOpen">Dashboards</span>
        </a>
        <a href="#" @click.prevent="activeRoute = 'grid'" :class="cn('flex items-center gap-3 px-3 py-2 rounded-md transition-colors', activeRoute === 'grid' ? 'bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-muted hover:text-foreground')">
          <Server class="h-5 w-5" />
          <span v-if="sidebarOpen">Grid</span>
        </a>
        <a href="#" @click.prevent="activeRoute = 'detections'" :class="cn('flex items-center gap-3 px-3 py-2 rounded-md transition-colors', activeRoute === 'detections' ? 'bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-muted hover:text-foreground')">
          <ShieldAlert class="h-5 w-5" />
          <span v-if="sidebarOpen">Detections</span>
        </a>
        <a href="#" @click.prevent="activeRoute = 'jobs'" :class="cn('flex items-center gap-3 px-3 py-2 rounded-md transition-colors', activeRoute === 'jobs' || activeRoute === 'job-detail' ? 'bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-muted hover:text-foreground')">
          <FileText class="h-5 w-5" />
          <span v-if="sidebarOpen">PCAP</span>
        </a>
        <a href="#" @click.prevent="activeRoute = 'cases'" :class="cn('flex items-center gap-3 px-3 py-2 rounded-md transition-colors', activeRoute === 'cases' || activeRoute === 'case-detail' ? 'bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-muted hover:text-foreground')">
          <Briefcase class="h-5 w-5" />
          <span v-if="sidebarOpen">Cases</span>
        </a>
        <a href="#" @click.prevent="activeRoute = 'assistant'" :class="cn('flex items-center gap-3 px-3 py-2 rounded-md transition-colors', activeRoute === 'assistant' ? 'bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-muted hover:text-foreground')">
          <Bot class="h-5 w-5" />
          <span v-if="sidebarOpen">AI Assistant</span>
        </a>
        <div class="pt-4 border-t border-border mt-4">
             <div class="px-3 py-2 text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1" v-if="sidebarOpen">
                Administration
             </div>
             <a href="#" @click.prevent="navigateToAdmin('users')" :class="cn('flex items-center gap-3 px-3 py-2 rounded-md transition-colors', activeRoute === 'administration' && activeAdminTab === 'users' ? 'bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-muted hover:text-foreground')">
                <Users class="h-5 w-5" />
                <span v-if="sidebarOpen">Users</span>
            </a>
            <a href="#" @click.prevent="navigateToAdmin('grid')" :class="cn('flex items-center gap-3 px-3 py-2 rounded-md transition-colors', activeRoute === 'administration' && activeAdminTab === 'grid' ? 'bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-muted hover:text-foreground')">
                <Server class="h-5 w-5" />
                <span v-if="sidebarOpen">Grid Members</span>
            </a>
            <a href="#" @click.prevent="navigateToAdmin('config')" :class="cn('flex items-center gap-3 px-3 py-2 rounded-md transition-colors', activeRoute === 'administration' && activeAdminTab === 'config' ? 'bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-muted hover:text-foreground')">
                <Settings class="h-5 w-5" />
                <span v-if="sidebarOpen">Configuration</span>
            </a>
             <a href="#" @click.prevent="navigateToAdmin('license')" :class="cn('flex items-center gap-3 px-3 py-2 rounded-md transition-colors', activeRoute === 'administration' && activeAdminTab === 'license' ? 'bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-muted hover:text-foreground')">
                <Key class="h-5 w-5" />
                <span v-if="sidebarOpen">License</span>
            </a>
             <a href="#" @click.prevent="navigateToAdmin('aimetrics')" :class="cn('flex items-center gap-3 px-3 py-2 rounded-md transition-colors', activeRoute === 'administration' && activeAdminTab === 'aimetrics' ? 'bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-muted hover:text-foreground')">
                <Activity class="h-5 w-5" />
                <span v-if="sidebarOpen">AI Metrics</span>
            </a>
             <a href="#" @click.prevent="navigateToAdmin('clients')" :class="cn('flex items-center gap-3 px-3 py-2 rounded-md transition-colors', activeRoute === 'administration' && activeAdminTab === 'clients' ? 'bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-muted hover:text-foreground')">
                <UserCog class="h-5 w-5" />
                <span v-if="sidebarOpen">Clients</span>
            </a>
             <a href="#" @click.prevent="navigateToAdmin('queries')" :class="cn('flex items-center gap-3 px-3 py-2 rounded-md transition-colors', activeRoute === 'administration' && activeAdminTab === 'queries' ? 'bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-muted hover:text-foreground')">
                <Search class="h-5 w-5" />
                <span v-if="sidebarOpen">Active Queries</span>
            </a>
        </div>
      </nav>

      <div class="absolute bottom-4 left-0 w-full px-2 space-y-1 border-t border-border pt-2">
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
        'flex flex-1 transition-all duration-300 min-h-screen',
        sidebarOpen ? 'ml-64' : 'ml-16'
      )"
    >
    <!-- Main Content -->
    <main class="flex-1 min-h-screen bg-background min-w-0">
      <header class="h-16 border-b border-border bg-card flex items-center justify-between px-6 sticky top-0 z-30">
        <h1 class="text-xl font-semibold capitalize">{{ activeRoute.replace('-', ' ') }}</h1>
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
          <div class="h-8 w-8 rounded-full bg-primary flex items-center justify-center text-primary-foreground font-bold">
            U
          </div>
        </div>
      </header>

      <div class="p-6">
        <Overview v-if="activeRoute === 'home'" />
        
        <div v-else-if="activeRoute === 'grid'">
            <Grid />
        </div>

        <div v-else-if="activeRoute === 'hunt'">
            <Hunt category="hunt" :initial-query="huntQuery" />
        </div>

        <div v-else-if="activeRoute === 'alerts'">
            <Hunt category="alerts" :initial-query="huntQuery" />
        </div>

        <div v-else-if="activeRoute === 'detections'">
            <Detections @view-detail="navigateToDetection" />
        </div>

        <div v-else-if="activeRoute === 'detection-detail' && selectedDetectionId">
            <DetectionDetail :id="selectedDetectionId" @back="activeRoute = 'detections'" />
        </div>

        <div v-else-if="activeRoute === 'cases'">
            <Cases @view-detail="navigateToCase" />
        </div>

        <div v-else-if="activeRoute === 'case-detail' && selectedCaseId">
            <CaseDetail :id="selectedCaseId" @back="activeRoute = 'cases'" />
        </div>

        <div v-else-if="activeRoute === 'jobs'">
            <Jobs @view-detail="navigateToJob" />
        </div>

        <div v-else-if="activeRoute === 'job-detail' && selectedJobId">
            <JobDetail :id="selectedJobId" @back="activeRoute = 'jobs'" />
        </div>

        <div v-else-if="activeRoute === 'assistant'" class="h-[calc(100vh-theme(spacing.16)-theme(spacing.12))] -m-6">
            <Assistant
              :session-id="selectedAssistantSessionId"
              @navigate-to-session="navigateToAssistantSession"
            />
        </div>

        <div v-else-if="activeRoute === 'administration'" class="h-[calc(100vh-theme(spacing.16)-theme(spacing.12))] -m-6">
            <Administration :active-tab="activeAdminTab" />
        </div>

        <div v-else class="flex flex-col items-center justify-center h-96 text-muted-foreground">
          <Database class="h-16 w-16 mb-4 opacity-20" />
          <h2 class="text-2xl font-semibold">Module Not Implemented</h2>
          <p>This part of the modern interface is coming soon.</p>
        </div>
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
