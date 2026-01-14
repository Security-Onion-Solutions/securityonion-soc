<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import {
    Settings as SettingsIcon,
    User,
    Shield,
    RotateCcw,
    ExternalLink,
    Check,
    AlertTriangle,
    Loader2
} from 'lucide-vue-next'
import { cn } from '../lib/utils'
import { useAppInfo } from '../composables/useAppInfo'
import { useUsers } from '../composables/useUsers'

const { fetchAppInfo, currentUserId } = useAppInfo()
const { users, fetchUsers, updateUserProfile, getUserName } = useUsers()

// State
const activeTab = ref('general')
const loading = ref(true)
const saving = ref(false)
const successMessage = ref<string | null>(null)
const errorMessage = ref<string | null>(null)
const usingDefaults = ref(false)

// Form data
const profileForm = ref({
    firstName: '',
    lastName: '',
    note: ''
})

// Current user data
const currentUser = computed(() => {
    if (!currentUserId.value) return null
    return users.value.find(u => u.id === currentUserId.value)
})

const currentUserEmail = computed(() => currentUser.value?.email || '')

// Load data
async function loadData() {
    loading.value = true
    try {
        await fetchAppInfo()
        await fetchUsers()

        // Populate form with current user data
        if (currentUser.value) {
            profileForm.value.firstName = currentUser.value.firstName || ''
            profileForm.value.lastName = currentUser.value.lastName || ''
            profileForm.value.note = currentUser.value.note || ''
        }
    } catch (err) {
        console.error('Failed to load user data:', err)
    } finally {
        loading.value = false
    }
}

// Reset local storage defaults
function resetDefaults() {
    localStorage.clear()
    usingDefaults.value = true
    showSuccess('Settings reset to defaults')
}

// Save profile
async function saveProfile() {
    if (!currentUserId.value) return

    saving.value = true
    errorMessage.value = null

    try {
        await updateUserProfile(currentUserId.value, {
            firstName: profileForm.value.firstName,
            lastName: profileForm.value.lastName,
            note: profileForm.value.note
        })
        showSuccess('Profile updated successfully')
    } catch (err: any) {
        // Check if it's a permission error
        if (err.message?.includes('403') || err.message?.includes('Unauthorized')) {
            errorMessage.value = 'You do not have permission to update your profile via the API. Please use the link below to update your profile.'
        } else {
            errorMessage.value = err.message || 'Failed to update profile'
        }
    } finally {
        saving.value = false
    }
}

// Open classic settings
function openClassicSettings() {
    window.location.href = '/auth/self-service/settings/browser'
}

// Show success message
function showSuccess(message: string) {
    successMessage.value = message
    setTimeout(() => successMessage.value = null, 3000)
}

// Initialize
onMounted(() => {
    usingDefaults.value = localStorage.length === 0
    loadData()
})
</script>

<template>
    <div class="max-w-4xl mx-auto">
        <!-- Loading State -->
        <div v-if="loading" class="flex items-center justify-center py-12">
            <Loader2 class="h-8 w-8 animate-spin text-primary" />
        </div>

        <div v-else>
            <!-- Success Message -->
            <div v-if="successMessage" class="mb-4 p-4 bg-green-500/10 border border-green-500/20 rounded-lg flex items-center gap-3">
                <Check class="h-5 w-5 text-green-500 shrink-0" />
                <p class="text-sm text-green-500">{{ successMessage }}</p>
            </div>

            <!-- Tabs -->
            <div class="border-b border-border mb-6">
                <nav class="flex gap-4">
                    <button
                        @click="activeTab = 'general'"
                        :class="cn(
                            'flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors',
                            activeTab === 'general'
                                ? 'border-primary text-primary'
                                : 'border-transparent text-muted-foreground hover:text-foreground'
                        )"
                    >
                        <SettingsIcon class="h-4 w-4" />
                        General
                    </button>
                    <button
                        @click="activeTab = 'profile'"
                        :class="cn(
                            'flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors',
                            activeTab === 'profile'
                                ? 'border-primary text-primary'
                                : 'border-transparent text-muted-foreground hover:text-foreground'
                        )"
                    >
                        <User class="h-4 w-4" />
                        Profile
                    </button>
                    <button
                        @click="activeTab = 'security'"
                        :class="cn(
                            'flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors',
                            activeTab === 'security'
                                ? 'border-primary text-primary'
                                : 'border-transparent text-muted-foreground hover:text-foreground'
                        )"
                    >
                        <Shield class="h-4 w-4" />
                        Security
                    </button>
                </nav>
            </div>

            <!-- General Tab -->
            <div v-show="activeTab === 'general'" class="space-y-6">
                <div class="bg-card border border-border rounded-lg p-6">
                    <h3 class="text-lg font-semibold mb-2">Reset Defaults</h3>
                    <p class="text-sm text-muted-foreground mb-4">
                        Clear all locally stored preferences and reset to default settings. This includes table configurations, saved filters, and UI preferences.
                    </p>
                    <button
                        @click="resetDefaults"
                        :disabled="usingDefaults"
                        :class="cn(
                            'flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-colors',
                            usingDefaults
                                ? 'bg-muted text-muted-foreground cursor-not-allowed'
                                : 'bg-primary text-primary-foreground hover:bg-primary/90'
                        )"
                    >
                        <RotateCcw class="h-4 w-4" />
                        Reset Defaults
                    </button>
                    <p v-if="usingDefaults" class="text-sm text-muted-foreground mt-2">
                        Already using default settings.
                    </p>
                </div>
            </div>

            <!-- Profile Tab -->
            <div v-show="activeTab === 'profile'" class="space-y-6">
                <!-- Error Message -->
                <div v-if="errorMessage" class="p-4 bg-amber-500/10 border border-amber-500/20 rounded-lg">
                    <div class="flex items-start gap-3">
                        <AlertTriangle class="h-5 w-5 text-amber-500 shrink-0 mt-0.5" />
                        <div>
                            <p class="text-sm text-amber-600 dark:text-amber-400">{{ errorMessage }}</p>
                            <button
                                @click="openClassicSettings"
                                class="mt-2 text-sm text-primary hover:underline flex items-center gap-1"
                            >
                                Open Profile Settings
                                <ExternalLink class="h-3 w-3" />
                            </button>
                        </div>
                    </div>
                </div>

                <div class="bg-card border border-border rounded-lg p-6 space-y-4">
                    <h3 class="text-lg font-semibold mb-4">Profile Details</h3>

                    <div>
                        <label class="block text-sm font-medium mb-1.5">Email</label>
                        <input
                            type="text"
                            :value="currentUserEmail"
                            disabled
                            class="w-full px-3 py-2 rounded-md border border-border bg-muted text-muted-foreground"
                        />
                        <p class="text-xs text-muted-foreground mt-1">Email cannot be changed</p>
                    </div>

                    <div>
                        <label class="block text-sm font-medium mb-1.5">First Name</label>
                        <input
                            type="text"
                            v-model="profileForm.firstName"
                            maxlength="100"
                            placeholder="Enter your first name"
                            class="w-full px-3 py-2 rounded-md border border-border bg-background focus:outline-none focus:ring-2 focus:ring-primary"
                        />
                    </div>

                    <div>
                        <label class="block text-sm font-medium mb-1.5">Last Name</label>
                        <input
                            type="text"
                            v-model="profileForm.lastName"
                            maxlength="100"
                            placeholder="Enter your last name"
                            class="w-full px-3 py-2 rounded-md border border-border bg-background focus:outline-none focus:ring-2 focus:ring-primary"
                        />
                    </div>

                    <div>
                        <label class="block text-sm font-medium mb-1.5">Note</label>
                        <input
                            type="text"
                            v-model="profileForm.note"
                            maxlength="100"
                            placeholder="Add a note (visible to administrators)"
                            class="w-full px-3 py-2 rounded-md border border-border bg-background focus:outline-none focus:ring-2 focus:ring-primary"
                        />
                    </div>

                    <div class="flex items-center gap-3 pt-2">
                        <button
                            @click="saveProfile"
                            :disabled="saving"
                            class="flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium bg-primary text-primary-foreground hover:bg-primary/90 transition-colors disabled:opacity-50"
                        >
                            <Loader2 v-if="saving" class="h-4 w-4 animate-spin" />
                            Save Profile
                        </button>
                        <button
                            @click="openClassicSettings"
                            class="flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium text-muted-foreground hover:text-foreground hover:bg-muted transition-colors"
                        >
                            Advanced Settings
                            <ExternalLink class="h-3 w-3" />
                        </button>
                    </div>
                </div>
            </div>

            <!-- Security Tab -->
            <div v-show="activeTab === 'security'" class="space-y-6">
                <div class="p-4 bg-muted/50 border border-border rounded-lg">
                    <p class="text-sm text-muted-foreground">
                        Security settings including password changes, two-factor authentication (TOTP), and security keys (WebAuthn) are managed through the authentication system.
                    </p>
                </div>

                <div class="bg-card border border-border rounded-lg p-6">
                    <h3 class="text-lg font-semibold mb-2">Password</h3>
                    <p class="text-sm text-muted-foreground mb-4">
                        Change your account password. You'll need to enter your current password for verification.
                    </p>
                    <button
                        @click="openClassicSettings"
                        class="flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium bg-primary text-primary-foreground hover:bg-primary/90 transition-colors"
                    >
                        Change Password
                        <ExternalLink class="h-4 w-4" />
                    </button>
                </div>

                <div class="bg-card border border-border rounded-lg p-6">
                    <h3 class="text-lg font-semibold mb-2">Two-Factor Authentication (TOTP)</h3>
                    <p class="text-sm text-muted-foreground mb-4">
                        Add an extra layer of security by requiring a code from your authenticator app when signing in.
                    </p>
                    <button
                        @click="openClassicSettings"
                        class="flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium bg-primary text-primary-foreground hover:bg-primary/90 transition-colors"
                    >
                        Manage TOTP
                        <ExternalLink class="h-4 w-4" />
                    </button>
                </div>

                <div class="bg-card border border-border rounded-lg p-6">
                    <h3 class="text-lg font-semibold mb-2">Security Keys (WebAuthn)</h3>
                    <p class="text-sm text-muted-foreground mb-4">
                        Use hardware security keys like YubiKey for passwordless authentication.
                    </p>
                    <button
                        @click="openClassicSettings"
                        class="flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium bg-primary text-primary-foreground hover:bg-primary/90 transition-colors"
                    >
                        Manage Security Keys
                        <ExternalLink class="h-4 w-4" />
                    </button>
                </div>
            </div>
        </div>
    </div>
</template>
