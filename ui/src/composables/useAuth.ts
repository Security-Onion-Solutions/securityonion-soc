import { ref, computed } from 'vue'

// License status constants
export const LICENSE_STATUS_ACTIVE = 'active'
export const LICENSE_STATUS_EXCEEDED = 'exceeded'
export const LICENSE_STATUS_EXPIRED = 'expired'
export const LICENSE_STATUS_INVALID = 'invalid'
export const LICENSE_STATUS_PENDING = 'pending'
export const LICENSE_STATUS_UNPROVISIONED = 'unprovisioned'

// Feature constants
export const FEAT_API = 'api'
export const FEAT_OAI = 'oai'
export const FEAT_QRY = 'qry'
export const FEAT_RPT = 'rpt'
export const FEAT_TTR = 'ttr'

export interface LicenseKey {
    effective: string
    expiration: string
    name: string
    id: string
    licensee: string
    features: string[]
    users: number
    nodes: number
    subgrids: number
}

export interface User {
    id: string
    email: string
    firstName?: string
    lastName?: string
    roles: string[]
    status: string
}

// Global state - shared across all components
const currentUser = ref<User | null>(null)
const licenseKey = ref<LicenseKey | null>(null)
const licenseStatus = ref<string | null>(null)
const loading = ref(false)
const error = ref<string | null>(null)
let fetchPromise: Promise<void> | null = null

async function fetchAuth(): Promise<void> {
    // Return if already loaded
    if (currentUser.value && licenseStatus.value !== null) {
        return
    }

    // Avoid multiple parallel fetches
    if (fetchPromise) {
        return fetchPromise
    }

    loading.value = true
    error.value = null

    fetchPromise = (async () => {
        try {
            // Fetch /api/info to get userId, licenseKey, licenseStatus
            const infoResponse = await fetch('/api/info')
            if (!infoResponse.ok) {
                throw new Error(`Failed to fetch info: ${infoResponse.status}`)
            }
            const info = await infoResponse.json()

            licenseKey.value = info.licenseKey || null
            licenseStatus.value = info.licenseStatus || LICENSE_STATUS_UNPROVISIONED

            // Fetch all users and find current user to get roles
            // Note: /api/users/{id} doesn't support GET, so we fetch all users
            if (info.userId) {
                const usersResponse = await fetch('/api/users/')
                if (usersResponse.ok) {
                    const users: User[] = await usersResponse.json()
                    currentUser.value = users.find(u => u.id === info.userId) || null
                }
            }
        } catch (e: any) {
            error.value = e.message || 'Failed to fetch auth info'
            console.error('Failed to fetch auth info:', e)
        } finally {
            loading.value = false
            fetchPromise = null
        }
    })()

    return fetchPromise
}

function isUserAdmin(user: User | null = null): boolean {
    return userHasRole('superuser', user)
}

function userHasRole(role: string, user: User | null = null): boolean {
    const targetUser = user || currentUser.value
    if (!targetUser || !targetUser.roles) return false
    return targetUser.roles.includes(role)
}

function isLicensed(feature?: string): boolean {
    if (!licenseKey.value || licenseStatus.value !== LICENSE_STATUS_ACTIVE) {
        return false
    }

    // If no specific feature requested, just check if license is active
    if (!feature) {
        return true
    }

    // If features array is empty, all features are enabled
    if (!licenseKey.value.features || licenseKey.value.features.length === 0) {
        return true
    }

    return licenseKey.value.features.includes(feature)
}

function isLicenseUnprovisioned(): boolean {
    return licenseStatus.value === null || licenseStatus.value === LICENSE_STATUS_UNPROVISIONED
}

export function useAuth() {
    const isAdmin = computed(() => isUserAdmin())
    const hasActiveLicense = computed(() => licenseStatus.value === LICENSE_STATUS_ACTIVE)

    return {
        // State
        currentUser,
        licenseKey,
        licenseStatus,
        loading,
        error,

        // Computed
        isAdmin,
        hasActiveLicense,

        // Functions
        fetchAuth,
        isUserAdmin,
        userHasRole,
        isLicensed,
        isLicenseUnprovisioned,

        // Constants
        FEAT_API,
        FEAT_OAI,
        FEAT_QRY,
        FEAT_RPT,
        FEAT_TTR,
        LICENSE_STATUS_ACTIVE,
        LICENSE_STATUS_EXCEEDED,
        LICENSE_STATUS_EXPIRED,
        LICENSE_STATUS_INVALID,
        LICENSE_STATUS_PENDING,
        LICENSE_STATUS_UNPROVISIONED,
    }
}
