import { ref, computed } from 'vue'
import { useApi } from './useApi'

// Types matching Go model/config.go
export interface UiElement {
    field: string
    label: string
    multiline?: boolean
    forcedType?: string
    options?: string[]
    optionSeparator?: string
    default?: any
    required?: boolean
    readonly?: boolean
    regex?: string
    regexFailureMessage?: string
}

export interface ConfigSetting {
    id: string
    title?: string
    description?: string
    global?: boolean
    node?: boolean
    nodeId?: string
    default?: string
    defaultAvailable?: boolean
    value?: string
    multiline?: boolean
    readonly?: boolean
    readonlyUi?: boolean
    sensitive?: boolean
    regex?: string
    regexFailureMessage?: string
    required?: boolean
    file?: boolean
    advanced?: boolean
    helpLink?: string
    syntax?: string
    forcedType?: string
    duplicates?: boolean
    jinjaEscaped?: boolean
    options?: string[]
    optionSeparator?: string
    uiElements?: UiElement[]
    uiElementsDeleteMessage?: string
}

export interface ConfigCategory {
    id: string
    name: string
    settingsCount: number
    customizedCount: number
    advanced: boolean
}

// Internal state for category with loading/settings
interface CategoryState {
    loading: boolean
    error: string | null
    settings: ConfigSetting[]
    hierarchy: TreeNode[]
    lastFetched: number | null
}

export interface TreeNode {
    id: string
    name: string
    setting?: ConfigSetting
    children?: TreeNode[]
    isLeaf: boolean
}

// Module-level state (shared across all component instances)
const categories = ref<ConfigCategory[]>([])
const categoryCache = ref<Record<string, CategoryState>>({})
const changedModules = ref<string[]>([])
const advanced = ref(false)
const selectedSettingId = ref<string | null>(null)
const expandedCategories = ref<Set<string>>(new Set())

// Cache TTL in milliseconds (60 seconds)
const CACHE_TTL = 60000

export function useConfig() {
    const { loading, error, get, put, del } = useApi()

    // Computed properties
    const totalSettings = computed(() => {
        return categories.value.reduce((sum, cat) => sum + cat.settingsCount, 0)
    })

    const totalCustomized = computed(() => {
        return categories.value.reduce((sum, cat) => sum + cat.customizedCount, 0)
    })

    const selectedSetting = computed(() => {
        if (!selectedSettingId.value) return null

        // Find the setting in the cached categories
        for (const categoryId of Object.keys(categoryCache.value)) {
            const state = categoryCache.value[categoryId]
            const found = state.settings.find(s => s.id === selectedSettingId.value)
            if (found) return found
        }
        return null
    })

    // Fetch categories list
    const fetchCategories = async () => {
        try {
            const params: Record<string, string> = {}
            if (advanced.value) params.advanced = 'true'

            const data = await get<ConfigCategory[]>('/api/config/categories', params)
            if (data) {
                categories.value = data
            }
        } catch (e) {
            console.error('Failed to fetch config categories:', e)
        }
    }

    // Fetch settings for a specific category
    const fetchCategorySettings = async (categoryId: string, force = false) => {
        const cached = categoryCache.value[categoryId]
        const now = Date.now()

        // Return cached if valid and not forced
        if (cached && !force && cached.lastFetched && (now - cached.lastFetched) < CACHE_TTL) {
            return cached.settings
        }

        // Set loading state - Vue tracks object property changes
        categoryCache.value[categoryId] = {
            loading: true,
            error: null,
            settings: cached?.settings || [],
            hierarchy: cached?.hierarchy || [],
            lastFetched: cached?.lastFetched || null
        }

        try {
            const params: Record<string, string> = {}
            if (advanced.value) params.advanced = 'true'

            const data = await get<ConfigSetting[]>(`/api/config/category/${categoryId}`, params)
            const settings = data ? mergeSettings(data) : []
            const hierarchy = buildHierarchy(settings, categoryId)

            // Update with loaded data
            categoryCache.value[categoryId] = {
                loading: false,
                error: null,
                settings,
                hierarchy,
                lastFetched: now
            }

            return settings
        } catch (e: any) {
            // Update with error state
            categoryCache.value[categoryId] = {
                loading: false,
                error: e.message || 'Failed to fetch settings',
                settings: [],
                hierarchy: [],
                lastFetched: null
            }
            console.error(`Failed to fetch settings for category ${categoryId}:`, e)
            return []
        }
    }

    // Merge settings with same ID but different nodeIds
    const mergeSettings = (settings: ConfigSetting[]): ConfigSetting[] => {
        const merged = new Map<string, ConfigSetting & { nodeValues?: Map<string, string> }>()

        for (const setting of settings) {
            const existing = merged.get(setting.id)

            if (!existing) {
                // First occurrence - create base setting
                const base = { ...setting, nodeValues: new Map<string, string>() }
                if (setting.nodeId && setting.value) {
                    base.nodeValues.set(setting.nodeId, setting.value)
                    base.nodeId = undefined
                    base.value = undefined
                }
                merged.set(setting.id, base)
            } else {
                // Merge node-specific value
                if (setting.nodeId && setting.value) {
                    existing.nodeValues!.set(setting.nodeId, setting.value)
                } else {
                    // Global value
                    existing.value = setting.value
                    existing.default = setting.default
                    existing.defaultAvailable = setting.defaultAvailable
                }
                // Merge metadata
                if (!existing.description) existing.description = setting.description
                if (!existing.title) existing.title = setting.title
            }
        }

        return Array.from(merged.values())
    }

    // Build hierarchy tree from flat settings
    const buildHierarchy = (settings: ConfigSetting[], categoryId: string): TreeNode[] => {
        const root: TreeNode = { id: '', name: '', children: [], isLeaf: false }

        for (const setting of settings) {
            // Remove category prefix for tree structure
            const relativePath = setting.id.startsWith(categoryId + '.')
                ? setting.id.slice(categoryId.length + 1)
                : setting.id
            const segments = relativePath.split('.')

            addToTree(root, segments, setting)
        }

        return root.children || []
    }

    const addToTree = (node: TreeNode, path: string[], setting: ConfigSetting) => {
        if (!node.children) node.children = []

        const name = path[0]
        if (path.length === 1) {
            // Leaf node - this is a setting
            node.children.push({
                id: setting.id,
                name: setting.title || name,
                setting,
                isLeaf: true
            })
        } else {
            // Branch node
            let child = node.children.find(c => c.name === name && !c.isLeaf)
            if (!child) {
                child = {
                    id: setting.id.split('.').slice(0, -path.length + 1).join('.'),
                    name,
                    children: [],
                    isLeaf: false
                }
                node.children.push(child)
            }
            addToTree(child, path.slice(1), setting)
        }
    }

    // Get category state
    const getCategoryState = (categoryId: string): CategoryState | undefined => {
        return categoryCache.value[categoryId]
    }

    // Update a setting
    const updateSetting = async (settingId: string, value: string, nodeId?: string) => {
        try {
            const payload: any = {
                id: settingId,
                value
            }
            if (nodeId) payload.nodeId = nodeId

            await put('/api/config/', payload)

            // Invalidate cache for the category
            const categoryId = settingId.split('.')[0]
            invalidateCategoryCache(categoryId)

            // Track changed module
            trackChangedModule(settingId)

            return true
        } catch (e) {
            console.error('Failed to update setting:', e)
            throw e
        }
    }

    // Delete/reset a setting
    const deleteSetting = async (settingId: string, nodeId?: string) => {
        try {
            let url = `/api/config/${encodeURIComponent(settingId)}`
            if (nodeId) url += `/${encodeURIComponent(nodeId)}`

            await del(url)

            // Invalidate cache for the category
            const categoryId = settingId.split('.')[0]
            invalidateCategoryCache(categoryId)

            return true
        } catch (e) {
            console.error('Failed to delete setting:', e)
            throw e
        }
    }

    // Invalidate cache for a category
    const invalidateCategoryCache = (categoryId: string) => {
        const state = categoryCache.value[categoryId]
        if (state) {
            categoryCache.value[categoryId] = { ...state, lastFetched: null }
        }
    }

    // Track changed modules for sync
    const trackChangedModule = (settingId: string) => {
        // Special mappings for certain settings
        const moduleStateMap: Record<string, string[]> = {
            'advanced': ['*'], // Full highstate needed
            'global': ['*'],
            'host': ['*'],
            'bpf.zeek': ['zeek'],
            'bpf.pcap': ['pcap'],
            'bpf.suricata': ['suricata'],
            'elastic_fleet_package_registry': ['elastic-fleet-package-registry'],
            'patch': ['patch.os'],
            'vm': ['vm.user']
        }

        let modules: string[] = []

        for (const [prefix, mappedModules] of Object.entries(moduleStateMap)) {
            if (settingId.startsWith(prefix)) {
                modules = mappedModules
                break
            }
        }

        if (modules.length === 0) {
            // Default: use first segment as module
            modules = [settingId.split('.')[0]]
        }

        for (const mod of modules) {
            if (!changedModules.value.includes(mod)) {
                changedModules.value.push(mod)
            }
        }
        changedModules.value = [...new Set(changedModules.value)].sort()
    }

    // Sync all settings
    const syncAll = async () => {
        try {
            await put('/api/config/sync')
            changedModules.value = []
            return true
        } catch (e) {
            console.error('Failed to sync settings:', e)
            throw e
        }
    }

    // Sync specific module
    const syncModule = async (module: string, async_ = false) => {
        try {
            const params: Record<string, string> = {}
            if (async_) params.async = 'true'

            await put(`/api/config/sync/${module}`, undefined)

            // Remove from changed modules
            changedModules.value = changedModules.value.filter(m => m !== module)

            return true
        } catch (e: any) {
            if (e.message?.includes('ERROR_SALT_ALREADY_RUNNING')) {
                throw new Error('A sync operation is already in progress')
            }
            console.error('Failed to sync module:', e)
            throw e
        }
    }

    // Toggle category expansion
    const toggleCategory = async (categoryId: string) => {
        if (expandedCategories.value.has(categoryId)) {
            expandedCategories.value.delete(categoryId)
            expandedCategories.value = new Set(expandedCategories.value)
        } else {
            expandedCategories.value.add(categoryId)
            // Trigger reactivity immediately so UI shows expanded state
            expandedCategories.value = new Set(expandedCategories.value)
            // Fetch settings when expanding
            await fetchCategorySettings(categoryId)
        }
    }

    // Check if category is expanded
    const isCategoryExpanded = (categoryId: string) => {
        return expandedCategories.value.has(categoryId)
    }

    // Select a setting
    const selectSetting = (settingId: string | null) => {
        selectedSettingId.value = settingId
    }

    // Check if setting is modified
    const isSettingModified = (setting: ConfigSetting) => {
        return setting.defaultAvailable && setting.value !== setting.default
    }

    // Toggle advanced mode
    const toggleAdvanced = async () => {
        advanced.value = !advanced.value
        // Clear caches and refetch
        categoryCache.value = {}
        expandedCategories.value = new Set()
        await fetchCategories()
    }

    // Clear all caches
    const clearCache = () => {
        categoryCache.value = {}
        categories.value = []
    }

    // Save advanced preference to localStorage
    const loadLocalSettings = () => {
        const stored = localStorage.getItem('settings.config.advanced')
        if (stored) {
            advanced.value = stored === 'true'
        }
    }

    const saveLocalSettings = () => {
        localStorage.setItem('settings.config.advanced', String(advanced.value))
    }

    return {
        // State
        categories,
        categoryCache,
        changedModules,
        advanced,
        selectedSettingId,
        expandedCategories,
        loading,
        error,

        // Computed
        totalSettings,
        totalCustomized,
        selectedSetting,

        // Methods
        fetchCategories,
        fetchCategorySettings,
        getCategoryState,
        updateSetting,
        deleteSetting,
        syncAll,
        syncModule,
        toggleCategory,
        isCategoryExpanded,
        selectSetting,
        isSettingModified,
        toggleAdvanced,
        clearCache,
        loadLocalSettings,
        saveLocalSettings,
        invalidateCategoryCache
    }
}
