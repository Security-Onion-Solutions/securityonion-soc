<script setup lang="ts">
import { ref, computed } from 'vue'
import { useConfig, type TreeNode } from '../../composables/useConfig'
import {
    ChevronRight,
    ChevronDown,
    FileText,
    Folder,
    FolderOpen,
    Circle
} from 'lucide-vue-next'
import { cn } from '../../lib/utils'

const props = defineProps<{
    nodes: TreeNode[]
    depth: number
    searchQuery?: string
}>()

const {
    selectSetting,
    selectedSettingId,
    isSettingModified
} = useConfig()

const expandedNodes = ref<Set<string>>(new Set())

const toggleNode = (nodeId: string) => {
    if (expandedNodes.value.has(nodeId)) {
        expandedNodes.value.delete(nodeId)
    } else {
        expandedNodes.value.add(nodeId)
    }
    expandedNodes.value = new Set(expandedNodes.value)
}

const isExpanded = (nodeId: string) => expandedNodes.value.has(nodeId)

const handleSelectSetting = (node: TreeNode) => {
    if (node.isLeaf && node.setting) {
        selectSetting(node.setting.id)
    }
}

const isSelected = (node: TreeNode) => {
    return node.isLeaf && node.setting?.id === selectedSettingId.value
}

const isModified = (node: TreeNode) => {
    if (node.isLeaf && node.setting) {
        return isSettingModified(node.setting)
    }
    return false
}

// Filter nodes based on search query
const filteredNodes = computed(() => {
    if (!props.searchQuery) return props.nodes

    const query = props.searchQuery.toLowerCase()
    return props.nodes.filter(node => {
        if (node.isLeaf) {
            return node.name.toLowerCase().includes(query) ||
                node.id.toLowerCase().includes(query) ||
                node.setting?.description?.toLowerCase().includes(query) ||
                node.setting?.title?.toLowerCase().includes(query)
        }
        // For branch nodes, check if any children match
        return nodeHasMatch(node, query)
    })
})

const nodeHasMatch = (node: TreeNode, query: string): boolean => {
    if (node.isLeaf) {
        return node.name.toLowerCase().includes(query) ||
            node.id.toLowerCase().includes(query) ||
            node.setting?.description?.toLowerCase().includes(query) ||
            node.setting?.title?.toLowerCase().includes(query)
    }
    if (node.children) {
        return node.children.some(child => nodeHasMatch(child, query))
    }
    return false
}

const paddingLeft = computed(() => `${props.depth * 16 + 8}px`)
</script>

<template>
    <div class="space-y-0.5">
        <div
            v-for="node in filteredNodes"
            :key="node.id"
        >
            <!-- Branch Node -->
            <div
                v-if="!node.isLeaf"
                class="group"
            >
                <div
                    @click="toggleNode(node.id)"
                    :style="{ paddingLeft }"
                    :class="cn(
                        'flex items-center gap-2 px-2 py-1.5 rounded-md cursor-pointer transition-colors',
                        'hover:bg-muted/50 text-sm'
                    )"
                >
                    <ChevronDown v-if="isExpanded(node.id)" class="h-4 w-4 text-muted-foreground shrink-0" />
                    <ChevronRight v-else class="h-4 w-4 text-muted-foreground shrink-0" />
                    <FolderOpen v-if="isExpanded(node.id)" class="h-4 w-4 text-amber-500 shrink-0" />
                    <Folder v-else class="h-4 w-4 text-amber-500 shrink-0" />
                    <span class="font-medium truncate">{{ node.name }}</span>
                </div>

                <!-- Children (Recursive) -->
                <div v-if="isExpanded(node.id) && node.children">
                    <ConfigTree
                        :nodes="node.children"
                        :depth="depth + 1"
                        :search-query="searchQuery"
                    />
                </div>
            </div>

            <!-- Leaf Node (Setting) -->
            <div
                v-else
                @click="handleSelectSetting(node)"
                :style="{ paddingLeft }"
                :class="cn(
                    'flex items-center gap-2 px-2 py-1.5 rounded-md cursor-pointer transition-colors text-sm',
                    'hover:bg-muted/50',
                    isSelected(node) && 'bg-primary/10 text-primary',
                    isModified(node) && !isSelected(node) && 'text-amber-600'
                )"
            >
                <!-- Modified Indicator -->
                <Circle
                    v-if="isModified(node)"
                    class="h-2 w-2 fill-amber-500 text-amber-500 shrink-0"
                />
                <div v-else class="w-2" />

                <FileText class="h-4 w-4 text-muted-foreground shrink-0" />
                <span class="truncate" :title="node.setting?.description || node.name">
                    {{ node.setting?.title || node.name }}
                </span>

                <!-- Required Badge -->
                <span
                    v-if="node.setting?.required"
                    class="text-destructive text-xs"
                >*</span>

                <!-- Readonly Badge -->
                <span
                    v-if="node.setting?.readonly || node.setting?.readonlyUi"
                    class="px-1.5 py-0.5 rounded text-xs bg-muted text-muted-foreground"
                >readonly</span>
            </div>
        </div>

        <!-- Empty State -->
        <div
            v-if="filteredNodes.length === 0"
            class="px-4 py-2 text-sm text-muted-foreground"
        >
            No settings found
        </div>
    </div>
</template>
