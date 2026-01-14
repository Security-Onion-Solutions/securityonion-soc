import { ref, computed } from 'vue'

interface ClientParameters {
    docsUrl: string
    cheatsheetUrl: string
    releaseNotesUrl: string
}

interface AppInfo {
    userId: string
    srvToken: string
    version: string
    parameters: ClientParameters
}

// Global state - shared across all components
const appInfo = ref<AppInfo | null>(null)
const loading = ref(false)
const error = ref<string | null>(null)
let fetchPromise: Promise<AppInfo | null> | null = null

async function fetchAppInfo(): Promise<AppInfo | null> {
    // Return cached data if available
    if (appInfo.value) {
        return appInfo.value
    }

    // Avoid multiple parallel fetches
    if (fetchPromise) {
        return fetchPromise
    }

    loading.value = true
    error.value = null

    fetchPromise = (async () => {
        try {
            const response = await fetch('/api/info')
            if (!response.ok) {
                throw new Error(`Failed to fetch app info: ${response.status}`)
            }
            const data = await response.json()
            appInfo.value = data
            return data
        } catch (e: any) {
            error.value = e.message || 'Failed to fetch app info'
            console.error('Failed to fetch app info:', e)
            return null
        } finally {
            loading.value = false
            fetchPromise = null
        }
    })()

    return fetchPromise
}

export function useAppInfo() {
    const currentUserId = computed(() => appInfo.value?.userId || '')
    const docsUrl = computed(() => appInfo.value?.parameters?.docsUrl || 'https://docs.securityonion.net/')
    const cheatsheetUrl = computed(() => appInfo.value?.parameters?.cheatsheetUrl || 'https://docs.securityonion.net/en/2.4/cheat-sheet.html')
    const releaseNotesUrl = computed(() => appInfo.value?.parameters?.releaseNotesUrl || 'https://docs.securityonion.net/en/2.4/release-notes.html')
    const settingsUrl = computed(() => '/auth/self-service/settings/browser')

    return {
        appInfo,
        loading,
        error,
        fetchAppInfo,
        currentUserId,
        docsUrl,
        cheatsheetUrl,
        releaseNotesUrl,
        settingsUrl,
    }
}
