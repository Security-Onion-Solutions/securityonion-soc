<script setup lang="ts">
import { computed } from 'vue'
import { Trash2, HelpCircle, Clock, Code, List } from 'lucide-vue-next'
import { cn } from '../../lib/utils'

interface PlaybookQuestion {
  question: string
  context: string
  range?: string
  query: string
  answer_sources?: string[]
}

const props = defineProps<{
  modelValue: PlaybookQuestion
  index: number
}>()

const emit = defineEmits<{
  'update:modelValue': [value: PlaybookQuestion]
  remove: []
}>()

const question = computed({
  get: () => props.modelValue,
  set: (value) => emit('update:modelValue', value)
})

const updateField = (field: keyof PlaybookQuestion, value: any) => {
  emit('update:modelValue', { ...props.modelValue, [field]: value })
}

const answerSourcesText = computed({
  get: () => (props.modelValue.answer_sources || []).join('\n'),
  set: (value: string) => {
    const sources = value.split('\n').map(s => s.trim()).filter(s => s)
    updateField('answer_sources', sources)
  }
})
</script>

<template>
  <div class="border border-border rounded-lg bg-card overflow-hidden">
    <!-- Header -->
    <div class="flex items-center justify-between px-4 py-3 bg-muted/30 border-b border-border">
      <span class="text-sm font-medium text-muted-foreground">Question {{ index + 1 }}</span>
      <button
        @click="emit('remove')"
        class="p-1.5 text-muted-foreground hover:text-red-500 hover:bg-red-500/10 rounded transition-colors"
        title="Remove question"
      >
        <Trash2 class="h-4 w-4" />
      </button>
    </div>

    <div class="p-4 space-y-4">
      <!-- Question Text -->
      <div class="space-y-1.5">
        <label class="flex items-center gap-1.5 text-sm font-medium text-foreground">
          <HelpCircle class="h-4 w-4 text-primary" />
          Question
        </label>
        <input
          :value="question.question"
          @input="updateField('question', ($event.target as HTMLInputElement).value)"
          type="text"
          placeholder="What is the source IP address of the alert?"
          class="w-full px-3 py-2 bg-background border border-border rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-primary/50 transition-all"
        />
      </div>

      <!-- Context -->
      <div class="space-y-1.5">
        <label class="flex items-center gap-1.5 text-sm font-medium text-foreground">
          Context
          <span class="text-xs text-muted-foreground font-normal">(why this matters)</span>
        </label>
        <textarea
          :value="question.context"
          @input="updateField('context', ($event.target as HTMLTextAreaElement).value)"
          rows="2"
          placeholder="Knowing if the attack comes from inside or outside the network can help determine if this is a false positive..."
          class="w-full px-3 py-2 bg-background border border-border rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-primary/50 transition-all resize-none"
        />
      </div>

      <!-- Time Range -->
      <div class="space-y-1.5">
        <label class="flex items-center gap-1.5 text-sm font-medium text-foreground">
          <Clock class="h-4 w-4 text-primary" />
          Time Range
          <span class="text-xs text-muted-foreground font-normal">(optional)</span>
        </label>
        <input
          :value="question.range || ''"
          @input="updateField('range', ($event.target as HTMLInputElement).value || undefined)"
          type="text"
          placeholder="+/-3d"
          class="w-full px-3 py-2 bg-background border border-border rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-primary/50 transition-all"
        />
        <p class="text-xs text-muted-foreground">
          Examples: <code class="bg-muted px-1 rounded">+/-3d</code> (3 days before and after),
          <code class="bg-muted px-1 rounded">-1h</code> (1 hour before),
          <code class="bg-muted px-1 rounded">30m</code> (30 minutes after)
        </p>
      </div>

      <!-- Query (Sigma YAML) -->
      <div class="space-y-1.5">
        <label class="flex items-center gap-1.5 text-sm font-medium text-foreground">
          <Code class="h-4 w-4 text-primary" />
          Query
          <span class="text-xs text-muted-foreground font-normal">(Sigma YAML)</span>
        </label>
        <textarea
          :value="question.query"
          @input="updateField('query', ($event.target as HTMLTextAreaElement).value)"
          rows="8"
          placeholder="logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains: '{source.ip}'
  condition: selection"
          class="w-full px-3 py-2 bg-background border border-border rounded-md text-sm font-mono focus:outline-none focus:ring-2 focus:ring-primary/50 transition-all resize-y"
        />
        <p class="text-xs text-muted-foreground">
          Use <code class="bg-muted px-1 rounded">{`{field_name}`}</code> for event field placeholders
        </p>
      </div>

      <!-- Answer Sources -->
      <div class="space-y-1.5">
        <label class="flex items-center gap-1.5 text-sm font-medium text-foreground">
          <List class="h-4 w-4 text-primary" />
          Answer Sources
          <span class="text-xs text-muted-foreground font-normal">(one per line)</span>
        </label>
        <textarea
          v-model="answerSourcesText"
          rows="3"
          placeholder="source.ip
destination.ip
process.name"
          class="w-full px-3 py-2 bg-background border border-border rounded-md text-sm font-mono focus:outline-none focus:ring-2 focus:ring-primary/50 transition-all resize-none"
        />
      </div>
    </div>
  </div>
</template>
