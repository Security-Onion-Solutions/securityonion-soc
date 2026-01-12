<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue'
import { useConfig, type ConfigSetting } from '../../composables/useConfig'
import type { GridMember } from '../../composables/useGridMembers'
import {
    X,
    Save,
    RotateCcw,
    Plus,
    Trash2,
    ExternalLink,
    Eye,
    EyeOff,
    AlertCircle,
    Info,
    ChevronDown
} from 'lucide-vue-next'
import { cn } from '../../lib/utils'

const props = defineProps<{
    setting: ConfigSetting & { nodeValues?: Map<string, string> }
    nodes: GridMember[]
}>()

const emit = defineEmits<{
    close: []
}>()

const {
    updateSetting,
    deleteSetting,
    isSettingModified,
    fetchCategorySettings
} = useConfig()

// Local state
const editValue = ref('')
const editNodeId = ref<string | null>(null)
const showPassword = ref(false)
const saving = ref(false)
const deleting = ref(false)
const error = ref<string | null>(null)
const validationError = ref<string | null>(null)
const showNodeSelector = ref(false)
const selectedNewNode = ref<string | null>(null)

// Initialize value
onMounted(() => {
    resetValue()
})

watch(() => props.setting.id, () => {
    resetValue()
})

const resetValue = () => {
    editValue.value = props.setting.value || ''
    editNodeId.value = null
    error.value = null
    validationError.value = null
}

// Computed
const isModified = computed(() => isSettingModified(props.setting))
const isReadonly = computed(() => props.setting.readonly || props.setting.readonlyUi)
const isPendingSave = computed(() => editValue.value !== (props.setting.value || ''))

const inputType = computed(() => {
    if (props.setting.sensitive && !showPassword.value) return 'password'
    return 'text'
})

const isToggle = computed(() => props.setting.forcedType === 'bool')
const isMultiline = computed(() => props.setting.multiline || props.setting.advanced)
const isSelectList = computed(() => props.setting.options && props.setting.options.length > 0)
const hasMultipleValues = computed(() => props.setting.forcedType?.startsWith('[]'))

const nodeValues = computed(() => {
    if (!props.setting.nodeValues) return []
    return Array.from(props.setting.nodeValues.entries())
})

const availableNodes = computed(() => {
    if (!props.setting.node) return []
    const usedNodeIds = new Set(nodeValues.value.map(([id]) => id))
    return props.nodes.filter(n => n.status === 'accepted' && !usedNodeIds.has(n.id))
})

const breadcrumbs = computed(() => {
    const parts = props.setting.id.split('.')
    if (props.setting.title) {
        parts[parts.length - 1] = props.setting.title
    }
    return parts.join(' > ')
})

// Validation
const validate = (value: string): boolean => {
    validationError.value = null

    if (props.setting.required && !value.trim()) {
        validationError.value = 'This field is required'
        return false
    }

    if (props.setting.regex) {
        const lines = props.setting.multiline ? value.split('\n') : [value]
        for (const line of lines) {
            if (line.trim() && !new RegExp(props.setting.regex).test(line)) {
                validationError.value = props.setting.regexFailureMessage || 'Invalid format'
                return false
            }
        }
    }

    return true
}

// Actions
const handleSave = async () => {
    if (!validate(editValue.value)) return

    saving.value = true
    error.value = null

    try {
        await updateSetting(props.setting.id, editValue.value, editNodeId.value || undefined)
        // Refresh the category to get updated values
        const categoryId = props.setting.id.split('.')[0]
        await fetchCategorySettings(categoryId, true)
    } catch (e: any) {
        error.value = e.message || 'Failed to save setting'
    } finally {
        saving.value = false
    }
}

const handleReset = async () => {
    if (!confirm('Reset this setting to its default value?')) return

    deleting.value = true
    error.value = null

    try {
        await deleteSetting(props.setting.id, editNodeId.value || undefined)
        const categoryId = props.setting.id.split('.')[0]
        await fetchCategorySettings(categoryId, true)
        resetValue()
    } catch (e: any) {
        error.value = e.message || 'Failed to reset setting'
    } finally {
        deleting.value = false
    }
}

const handleAddNode = async () => {
    if (!selectedNewNode.value) return

    const nodeId = selectedNewNode.value
    const defaultValue = props.setting.default || ''

    saving.value = true
    error.value = null

    try {
        await updateSetting(props.setting.id, defaultValue, nodeId)
        const categoryId = props.setting.id.split('.')[0]
        await fetchCategorySettings(categoryId, true)
        selectedNewNode.value = null
        showNodeSelector.value = false
    } catch (e: any) {
        error.value = e.message || 'Failed to add node setting'
    } finally {
        saving.value = false
    }
}

const handleDeleteNode = async (nodeId: string) => {
    if (!confirm(`Remove the setting for node ${nodeId}?`)) return

    deleting.value = true
    error.value = null

    try {
        await deleteSetting(props.setting.id, nodeId)
        const categoryId = props.setting.id.split('.')[0]
        await fetchCategorySettings(categoryId, true)
    } catch (e: any) {
        error.value = e.message || 'Failed to remove node setting'
    } finally {
        deleting.value = false
    }
}

const editNodeValue = (nodeId: string, value: string) => {
    editNodeId.value = nodeId
    editValue.value = value
}

const handleToggleChange = async () => {
    const newValue = editValue.value === 'true' ? 'false' : 'true'
    editValue.value = newValue
    await handleSave()
}

const handleMultiSelectChange = (option: string, checked: boolean) => {
    const separator = props.setting.optionSeparator || '\n'
    const current = editValue.value.split(separator).filter(v => v.trim())

    if (checked && !current.includes(option)) {
        current.push(option)
    } else if (!checked) {
        const idx = current.indexOf(option)
        if (idx > -1) current.splice(idx, 1)
    }

    editValue.value = current.join(separator)
}

const isOptionSelected = (option: string) => {
    const separator = props.setting.optionSeparator || '\n'
    return editValue.value.split(separator).includes(option)
}
</script>

<template>
    <div class="rounded-xl border border-border bg-card shadow-lg overflow-hidden">
        <!-- Header -->
        <div class="flex items-center justify-between px-4 py-3 border-b border-border bg-muted/30">
            <div class="flex-1 min-w-0">
                <div class="font-medium truncate">{{ setting.title || setting.id.split('.').pop() }}</div>
                <div class="text-xs text-muted-foreground truncate">{{ breadcrumbs }}</div>
            </div>
            <button
                @click="emit('close')"
                class="p-1.5 rounded-md hover:bg-muted text-muted-foreground hover:text-foreground transition-colors"
            >
                <X class="h-4 w-4" />
            </button>
        </div>

        <!-- Content -->
        <div class="p-4 space-y-4 max-h-[calc(100vh-200px)] overflow-y-auto">
            <!-- Error -->
            <div v-if="error" class="p-3 rounded-md bg-destructive/15 text-destructive flex items-center gap-2 text-sm">
                <AlertCircle class="h-4 w-4 shrink-0" />
                <span>{{ error }}</span>
            </div>

            <!-- Description -->
            <div v-if="setting.description" class="flex items-start gap-2 text-sm text-muted-foreground">
                <Info class="h-4 w-4 shrink-0 mt-0.5" />
                <p>{{ setting.description }}</p>
            </div>

            <!-- Help Link -->
            <a
                v-if="setting.helpLink"
                :href="setting.helpLink"
                target="_blank"
                class="inline-flex items-center gap-1 text-sm text-primary hover:underline"
            >
                View documentation
                <ExternalLink class="h-3 w-3" />
            </a>

            <!-- Global Value Section -->
            <div class="space-y-2">
                <label class="text-sm font-medium flex items-center gap-2">
                    Global Value
                    <span v-if="setting.required" class="text-destructive">*</span>
                    <span v-if="isModified" class="px-1.5 py-0.5 rounded text-xs bg-amber-500/10 text-amber-600">modified</span>
                    <span v-if="isReadonly" class="px-1.5 py-0.5 rounded text-xs bg-muted text-muted-foreground">readonly</span>
                </label>

                <!-- Toggle Switch -->
                <div v-if="isToggle" class="flex items-center gap-3">
                    <button
                        @click="handleToggleChange"
                        :disabled="isReadonly"
                        :class="cn(
                            'relative inline-flex h-6 w-11 shrink-0 cursor-pointer items-center rounded-full transition-colors',
                            'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2',
                            'disabled:cursor-not-allowed disabled:opacity-50',
                            editValue === 'true' ? 'bg-green-500' : 'bg-muted-foreground/30'
                        )"
                    >
                        <span
                            :class="cn(
                                'pointer-events-none block h-5 w-5 rounded-full bg-white shadow-lg ring-0 transition-transform',
                                editValue === 'true' ? 'translate-x-5' : 'translate-x-1'
                            )"
                        />
                    </button>
                    <span class="text-sm">{{ editValue === 'true' ? 'Enabled' : 'Disabled' }}</span>
                </div>

                <!-- Select Dropdown -->
                <select
                    v-else-if="isSelectList && !hasMultipleValues"
                    v-model="editValue"
                    :disabled="isReadonly"
                    class="w-full p-2 bg-background border border-border rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-primary/50"
                >
                    <option v-for="option in setting.options" :key="option" :value="option">
                        {{ option }}
                    </option>
                </select>

                <!-- Multi-Select Checkboxes -->
                <div v-else-if="isSelectList && hasMultipleValues" class="space-y-2">
                    <div
                        v-for="option in setting.options"
                        :key="option"
                        class="flex items-center gap-2"
                    >
                        <input
                            type="checkbox"
                            :id="`option-${option}`"
                            :checked="isOptionSelected(option)"
                            :disabled="isReadonly"
                            @change="(e) => handleMultiSelectChange(option, (e.target as HTMLInputElement).checked)"
                            class="h-4 w-4 rounded border-border text-primary focus:ring-primary"
                        />
                        <label :for="`option-${option}`" class="text-sm">{{ option }}</label>
                    </div>
                </div>

                <!-- Textarea -->
                <div v-else-if="isMultiline" class="relative">
                    <textarea
                        v-model="editValue"
                        :disabled="isReadonly"
                        :placeholder="setting.default || 'Enter value...'"
                        rows="8"
                        class="w-full p-3 bg-background border border-border rounded-md text-sm font-mono focus:outline-none focus:ring-2 focus:ring-primary/50 resize-y disabled:opacity-50 disabled:cursor-not-allowed"
                    />
                </div>

                <!-- Text Input -->
                <div v-else class="relative">
                    <input
                        v-model="editValue"
                        :type="inputType"
                        :disabled="isReadonly"
                        :placeholder="setting.default || 'Enter value...'"
                        class="w-full p-2 bg-background border border-border rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-primary/50 disabled:opacity-50 disabled:cursor-not-allowed pr-10"
                    />
                    <button
                        v-if="setting.sensitive"
                        @click="showPassword = !showPassword"
                        class="absolute right-2 top-1/2 -translate-y-1/2 p-1 text-muted-foreground hover:text-foreground"
                    >
                        <EyeOff v-if="showPassword" class="h-4 w-4" />
                        <Eye v-else class="h-4 w-4" />
                    </button>
                </div>

                <!-- Validation Error -->
                <p v-if="validationError" class="text-sm text-destructive">{{ validationError }}</p>

                <!-- Default Value Display -->
                <div v-if="setting.defaultAvailable && setting.default" class="text-xs text-muted-foreground">
                    <span class="font-medium">Default:</span>
                    <code class="ml-1 px-1 py-0.5 bg-muted rounded">{{ setting.default }}</code>
                </div>
            </div>

            <!-- Per-Node Values -->
            <div v-if="setting.node && nodeValues.length > 0" class="space-y-3 pt-4 border-t border-border">
                <div class="text-sm font-medium">Per-Node Overrides</div>

                <div
                    v-for="[nodeId, nodeValue] in nodeValues"
                    :key="nodeId"
                    class="flex items-center gap-2 p-2 rounded-md bg-muted/30"
                >
                    <span class="text-sm font-mono flex-1 truncate">{{ nodeId }}</span>
                    <code class="text-xs bg-muted px-2 py-1 rounded truncate max-w-[200px]">{{ nodeValue }}</code>
                    <button
                        @click="editNodeValue(nodeId, nodeValue)"
                        class="px-2 py-1 text-xs text-primary hover:underline"
                    >
                        Edit
                    </button>
                    <button
                        @click="handleDeleteNode(nodeId)"
                        class="p-1 text-muted-foreground hover:text-destructive transition-colors"
                    >
                        <Trash2 class="h-3.5 w-3.5" />
                    </button>
                </div>
            </div>

            <!-- Add Node Button -->
            <div v-if="setting.node && availableNodes.length > 0" class="pt-2">
                <div v-if="showNodeSelector" class="flex items-center gap-2">
                    <select
                        v-model="selectedNewNode"
                        class="flex-1 p-2 bg-background border border-border rounded-md text-sm"
                    >
                        <option :value="null" disabled>Select a node...</option>
                        <option v-for="node in availableNodes" :key="node.id" :value="node.id">
                            {{ node.id }}
                        </option>
                    </select>
                    <button
                        @click="handleAddNode"
                        :disabled="!selectedNewNode"
                        class="px-3 py-2 rounded-md text-sm font-medium bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
                    >
                        Add
                    </button>
                    <button
                        @click="showNodeSelector = false; selectedNewNode = null"
                        class="p-2 rounded-md hover:bg-muted"
                    >
                        <X class="h-4 w-4" />
                    </button>
                </div>
                <button
                    v-else
                    @click="showNodeSelector = true"
                    class="flex items-center gap-1 text-sm text-primary hover:underline"
                >
                    <Plus class="h-4 w-4" />
                    Add per-node override
                </button>
            </div>
        </div>

        <!-- Footer -->
        <div class="flex items-center justify-between px-4 py-3 border-t border-border bg-muted/30">
            <button
                v-if="isModified && setting.defaultAvailable"
                @click="handleReset"
                :disabled="deleting || isReadonly"
                class="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm font-medium text-muted-foreground hover:text-foreground hover:bg-muted transition-colors disabled:opacity-50"
            >
                <RotateCcw class="h-4 w-4" />
                Reset to Default
            </button>
            <div v-else />

            <div class="flex items-center gap-2">
                <button
                    @click="resetValue"
                    :disabled="!isPendingSave"
                    class="px-3 py-1.5 rounded-md text-sm font-medium text-muted-foreground hover:text-foreground hover:bg-muted transition-colors disabled:opacity-50"
                >
                    Cancel
                </button>
                <button
                    @click="handleSave"
                    :disabled="!isPendingSave || saving || isReadonly"
                    class="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm font-medium bg-primary text-primary-foreground hover:bg-primary/90 transition-colors disabled:opacity-50"
                >
                    <Save class="h-4 w-4" />
                    {{ saving ? 'Saving...' : 'Save' }}
                </button>
            </div>
        </div>
    </div>
</template>
