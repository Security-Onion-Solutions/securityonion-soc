<script setup lang="ts">
import { ShieldAlert, Network, Crosshair, UserCheck, Server, Sparkles } from 'lucide-vue-next'
import { useChatWidget } from '@/composables/useChatWidget'

const { openNewChatWithPrompt } = useChatWidget()

interface PromptButton {
  label: string
  prompt: string
}

interface PromptCategory {
  title: string
  icon: typeof ShieldAlert
  prompts: PromptButton[]
}

const promptCategories: PromptCategory[] = [
  {
    title: 'Alerts & Detections',
    icon: ShieldAlert,
    prompts: [
      { label: 'Top 10 alerts in the last 24 hours', prompt: 'Show me the top 10 alerts for the past 24 hours' },
      { label: 'Critical or high severity alerts today', prompt: 'What critical or high severity alerts fired today?' },
      { label: 'New alert signatures this week', prompt: 'Are there any new alert signatures I haven\'t seen before this week?' },
      { label: 'Hosts with most alerts', prompt: 'Which hosts triggered the most alerts recently?' },
    ]
  },
  {
    title: 'Network Traffic',
    icon: Network,
    prompts: [
      { label: 'Top destination in last 24 hours', prompt: 'What is the top destination in the last 24 hours?' },
      { label: 'Top talkers by bandwidth', prompt: 'Show me the top talkers by bandwidth usage' },
      { label: 'Unusual ports used', prompt: 'What unusual ports have been used in the last 24 hours?' },
      { label: 'Most connected external IPs', prompt: 'Which external IPs have the most connections to internal hosts?' },
    ]
  },
  {
    title: 'Threat Hunting',
    icon: Crosshair,
    prompts: [
      { label: 'Signs of beaconing activity', prompt: 'Are there any signs of beaconing activity?' },
      { label: 'DNS queries to new domains', prompt: 'Show me DNS queries to newly registered domains' },
      { label: 'After-hours connections', prompt: 'What outbound connections occurred outside business hours?' },
      { label: 'Data exfiltration indicators', prompt: 'Are there any potential data exfiltration indicators?' },
    ]
  },
  {
    title: 'User & Authentication',
    icon: UserCheck,
    prompts: [
      { label: 'Failed auth attempts', prompt: 'Show me failed authentication attempts in the last 24 hours' },
      { label: 'Multi-location logins', prompt: 'Which accounts have logged in from multiple locations?' },
      { label: 'Suspicious admin activity', prompt: 'Are there any suspicious admin account activities?' },
    ]
  },
  {
    title: 'System Health',
    icon: Server,
    prompts: [
      { label: 'Sensor health status', prompt: 'What\'s the current health status of my sensors?' },
      { label: 'Low disk space nodes', prompt: 'Are any nodes running low on disk space?' },
      { label: 'Event ingestion rate', prompt: 'Show me the current event ingestion rate' },
    ]
  },
  {
    title: 'Case Management',
    icon: Sparkles,
    prompts: [
      { label: 'My open cases', prompt: 'What open cases are assigned to me?' },
      { label: 'Escalated cases this week', prompt: 'Summarize the cases escalated this week' },
    ]
  },
]

function askQuestion(prompt: string) {
  openNewChatWithPrompt(prompt)
}
</script>

<template>
  <div class="space-y-8 animate-in fade-in duration-500">
    <!-- Welcome Header -->
    <div class="text-center space-y-2">
      <h1 class="text-3xl font-bold tracking-tight">Welcome to Security Onion</h1>
      <p class="text-muted-foreground text-lg">
        Get started by asking your AI Security Assistant a question
      </p>
    </div>

    <!-- Prompt Categories -->
    <div class="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
      <div
        v-for="category in promptCategories"
        :key="category.title"
        class="p-6 rounded-xl border border-border bg-card shadow-sm"
      >
        <!-- Category Header -->
        <div class="flex items-center gap-2 mb-4">
          <component :is="category.icon" class="h-5 w-5 text-primary" />
          <h2 class="font-semibold">{{ category.title }}</h2>
        </div>

        <!-- Prompt Buttons -->
        <div class="space-y-2">
          <button
            v-for="prompt in category.prompts"
            :key="prompt.label"
            @click="askQuestion(prompt.prompt)"
            class="w-full text-left px-3 py-2 text-sm rounded-lg bg-muted/50 hover:bg-muted transition-colors text-foreground/80 hover:text-foreground"
          >
            {{ prompt.label }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>
