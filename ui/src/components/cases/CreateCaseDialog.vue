<script setup lang="ts">
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

import { ref, onMounted, onUnmounted, watch } from 'vue'
import { X, Loader2, Briefcase } from 'lucide-vue-next'
import { cn } from '../../lib/utils'
import { useCases, type CaseCreateData } from '../../composables/useCases'
import { useUsers } from '../../composables/useUsers'

const props = defineProps<{
  open: boolean
}>()

const emit = defineEmits<{
  'close': []
  'created': [caseId: string]
}>()

const { createCase, creating } = useCases()
const { users, fetchUsers } = useUsers()

const dialogRef = ref<HTMLElement | null>(null)
const formError = ref<string | null>(null)

// Form state
const form = ref<CaseCreateData>({
  title: '',
  description: '',
  severity: 'medium',
  priority: 3,
  assigneeId: '',
  tlp: 'amber'
})

const severityOptions = [
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' }
]

const tlpOptions = [
  { value: 'red', label: 'TLP:RED', description: 'Not for disclosure' },
  { value: 'amber', label: 'TLP:AMBER', description: 'Limited disclosure' },
  { value: 'green', label: 'TLP:GREEN', description: 'Community-wide' },
  { value: 'white', label: 'TLP:WHITE', description: 'Unlimited' }
]

function resetForm() {
  form.value = {
    title: '',
    description: '',
    severity: 'medium',
    priority: 3,
    assigneeId: '',
    tlp: 'amber'
  }
  formError.value = null
}

async function handleSubmit() {
  if (!form.value.title.trim()) {
    formError.value = 'Title is required'
    return
  }

  formError.value = null

  try {
    const data: CaseCreateData = {
      title: form.value.title.trim(),
      description: form.value.description?.trim() || '',
      severity: form.value.severity,
      priority: form.value.priority,
      tlp: form.value.tlp
    }

    if (form.value.assigneeId) {
      data.assigneeId = form.value.assigneeId
    }

    const result = await createCase(data)
    if (result?.id) {
      emit('created', result.id)
      resetForm()
    }
  } catch (e: any) {
    formError.value = e.message || 'Failed to create case'
  }
}

function handleClose() {
  if (!creating.value) {
    resetForm()
    emit('close')
  }
}

function handleBackdropClick(event: MouseEvent) {
  if (event.target === event.currentTarget) {
    handleClose()
  }
}

function handleEscape(event: KeyboardEvent) {
  if (event.key === 'Escape' && props.open) {
    handleClose()
  }
}

watch(() => props.open, (isOpen) => {
  if (isOpen) {
    fetchUsers()
  }
})

onMounted(() => {
  document.addEventListener('keydown', handleEscape)
})

onUnmounted(() => {
  document.removeEventListener('keydown', handleEscape)
})
</script>

<template>
  <Teleport to="body">
    <Transition
      enter-active-class="duration-200 ease-out"
      enter-from-class="opacity-0"
      enter-to-class="opacity-100"
      leave-active-class="duration-150 ease-in"
      leave-from-class="opacity-100"
      leave-to-class="opacity-0"
    >
      <div
        v-if="open"
        class="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm"
        @click="handleBackdropClick"
      >
        <div
          ref="dialogRef"
          class="w-full max-w-lg bg-card border border-border rounded-xl shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-200"
          @click.stop
        >
          <!-- Header -->
          <div class="flex items-center justify-between px-6 py-4 border-b border-border bg-muted/30">
            <div class="flex items-center gap-3">
              <div class="p-2 rounded-lg bg-primary/10">
                <Briefcase class="h-5 w-5 text-primary" />
              </div>
              <div>
                <h2 class="text-lg font-semibold">Create New Case</h2>
                <p class="text-sm text-muted-foreground">Track and investigate a security incident</p>
              </div>
            </div>
            <button
              @click="handleClose"
              :disabled="creating"
              class="p-2 hover:bg-muted rounded-lg transition-colors disabled:opacity-50"
            >
              <X class="h-5 w-5 text-muted-foreground" />
            </button>
          </div>

          <!-- Form -->
          <form @submit.prevent="handleSubmit" class="p-6 space-y-5">
            <!-- Error Message -->
            <div v-if="formError" class="p-3 rounded-lg bg-destructive/10 border border-destructive/20 text-destructive text-sm">
              {{ formError }}
            </div>

            <!-- Title -->
            <div class="space-y-2">
              <label class="text-sm font-medium">
                Title <span class="text-destructive">*</span>
              </label>
              <input
                v-model="form.title"
                type="text"
                placeholder="Brief description of the incident"
                class="w-full px-3 py-2 bg-background border border-border rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary/50"
                :disabled="creating"
              />
            </div>

            <!-- Description -->
            <div class="space-y-2">
              <label class="text-sm font-medium">Description</label>
              <textarea
                v-model="form.description"
                placeholder="Detailed information about the case..."
                rows="3"
                class="w-full px-3 py-2 bg-background border border-border rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary/50 resize-none"
                :disabled="creating"
              ></textarea>
            </div>

            <!-- Severity & Priority Row -->
            <div class="grid grid-cols-2 gap-4">
              <div class="space-y-2">
                <label class="text-sm font-medium">Severity</label>
                <select
                  v-model="form.severity"
                  class="w-full px-3 py-2 bg-background border border-border rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary/50"
                  :disabled="creating"
                >
                  <option v-for="opt in severityOptions" :key="opt.value" :value="opt.value">
                    {{ opt.label }}
                  </option>
                </select>
              </div>
              <div class="space-y-2">
                <label class="text-sm font-medium">Priority</label>
                <select
                  v-model="form.priority"
                  class="w-full px-3 py-2 bg-background border border-border rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary/50"
                  :disabled="creating"
                >
                  <option :value="1">1 - Highest</option>
                  <option :value="2">2 - High</option>
                  <option :value="3">3 - Medium</option>
                  <option :value="4">4 - Low</option>
                  <option :value="5">5 - Lowest</option>
                </select>
              </div>
            </div>

            <!-- Assignee & TLP Row -->
            <div class="grid grid-cols-2 gap-4">
              <div class="space-y-2">
                <label class="text-sm font-medium">Assignee</label>
                <select
                  v-model="form.assigneeId"
                  class="w-full px-3 py-2 bg-background border border-border rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary/50"
                  :disabled="creating"
                >
                  <option value="">Unassigned</option>
                  <option v-for="user in users" :key="user.id" :value="user.id">
                    {{ user.firstName && user.lastName ? `${user.firstName} ${user.lastName}` : user.email }}
                  </option>
                </select>
              </div>
              <div class="space-y-2">
                <label class="text-sm font-medium">TLP</label>
                <select
                  v-model="form.tlp"
                  class="w-full px-3 py-2 bg-background border border-border rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary/50"
                  :disabled="creating"
                >
                  <option v-for="opt in tlpOptions" :key="opt.value" :value="opt.value">
                    {{ opt.label }}
                  </option>
                </select>
              </div>
            </div>

            <!-- Actions -->
            <div class="flex items-center justify-end gap-3 pt-4 border-t border-border">
              <button
                type="button"
                @click="handleClose"
                :disabled="creating"
                class="px-4 py-2 text-sm font-medium rounded-lg hover:bg-muted transition-colors disabled:opacity-50"
              >
                Cancel
              </button>
              <button
                type="submit"
                :disabled="creating || !form.title.trim()"
                class="inline-flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground text-sm font-medium rounded-lg hover:bg-primary/90 transition-colors disabled:opacity-50"
              >
                <Loader2 v-if="creating" class="h-4 w-4 animate-spin" />
                <span>{{ creating ? 'Creating...' : 'Create Case' }}</span>
              </button>
            </div>
          </form>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>
