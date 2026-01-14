<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import {
    User,
    Moon,
    Gift,
    HelpCircle,
    FileText,
    Newspaper,
    Star,
    Server,
    Headphones,
    Settings,
    LogOut,
    FlaskConical,
    ChevronDown,
    ExternalLink
} from 'lucide-vue-next'
import { cn } from '../../lib/utils'
import { useAppInfo } from '../../composables/useAppInfo'
import { useUsers } from '../../composables/useUsers'
import { useTheme } from '../../composables/useTheme'

const router = useRouter()
const { fetchAppInfo, currentUserId, docsUrl, cheatsheetUrl, releaseNotesUrl } = useAppInfo()
const { fetchUsers, getUserName } = useUsers()
const { isDarkMode, toggleTheme } = useTheme()

const showDropdown = ref(false)
const dropdownRef = ref<HTMLElement | null>(null)

// Fetch user info on mount
onMounted(async () => {
    await fetchAppInfo()
    await fetchUsers()
})

// Current user display name
const currentUserName = computed(() => {
    if (!currentUserId.value) return 'User'
    const name = getUserName(currentUserId.value)
    return name || 'User'
})

// User initials for avatar
const userInitials = computed(() => {
    const name = currentUserName.value
    if (!name || name === 'User') return 'U'

    // If it's an email, use first letter
    if (name.includes('@')) {
        return name.charAt(0).toUpperCase()
    }

    // Otherwise use first letters of first and last name
    const parts = name.split(' ')
    if (parts.length >= 2) {
        return (parts[0].charAt(0) + parts[parts.length - 1].charAt(0)).toUpperCase()
    }
    return name.charAt(0).toUpperCase()
})

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
            console.error("No logout_url found in response")
        }
    } catch (error) {
        console.error('Logout failed:', error)
    }
}

function openLink(url: string) {
    window.open(url, '_blank', 'noopener,noreferrer')
    showDropdown.value = false
}

function goToSettings() {
    showDropdown.value = false
    router.push({ name: 'settings' })
}

// Close dropdown when clicking outside
function handleClickOutside(e: MouseEvent) {
    if (dropdownRef.value && !dropdownRef.value.contains(e.target as Node)) {
        showDropdown.value = false
    }
}

// Attach/detach click outside listener
watch(showDropdown, (isOpen) => {
    if (isOpen) {
        setTimeout(() => {
            document.addEventListener('click', handleClickOutside)
        }, 0)
    } else {
        document.removeEventListener('click', handleClickOutside)
    }
})
</script>

<template>
    <div ref="dropdownRef" class="relative">
        <!-- User Avatar Button -->
        <button
            @click.stop="showDropdown = !showDropdown"
            class="flex items-center gap-2 rounded-full transition-colors hover:ring-2 hover:ring-primary/20"
        >
            <div class="h-8 w-8 rounded-full bg-primary flex items-center justify-center text-primary-foreground font-bold text-sm">
                {{ userInitials }}
            </div>
        </button>

        <!-- Dropdown Menu -->
        <Transition
            enter-active-class="transition duration-100 ease-out"
            enter-from-class="opacity-0 scale-95"
            enter-to-class="opacity-100 scale-100"
            leave-active-class="transition duration-75 ease-in"
            leave-from-class="opacity-100 scale-100"
            leave-to-class="opacity-0 scale-95"
        >
            <div
                v-if="showDropdown"
                class="absolute right-0 mt-2 z-50 w-64 rounded-lg border border-border bg-card shadow-lg overflow-hidden"
            >
                <!-- User Info Header -->
                <div class="px-4 py-3 border-b border-border bg-muted/30">
                    <div class="flex items-center gap-3">
                        <div class="h-10 w-10 rounded-full bg-primary flex items-center justify-center text-primary-foreground font-bold">
                            {{ userInitials }}
                        </div>
                        <div class="flex-1 min-w-0">
                            <p class="text-sm font-medium truncate">{{ currentUserName }}</p>
                            <p class="text-xs text-muted-foreground">Logged in</p>
                        </div>
                    </div>
                </div>

                <!-- Menu Items -->
                <div class="py-1">
                    <!-- Dark Mode Toggle -->
                    <button
                        @click.stop="toggleTheme"
                        class="w-full flex items-center gap-3 px-4 py-2 text-sm text-foreground hover:bg-muted transition-colors"
                    >
                        <Moon class="h-4 w-4 text-muted-foreground" />
                        <span>Dark Mode</span>
                        <div class="ml-auto">
                            <div :class="cn(
                                'w-8 h-4 rounded-full transition-colors relative',
                                isDarkMode ? 'bg-primary' : 'bg-muted-foreground/30'
                            )">
                                <div :class="cn(
                                    'absolute top-0.5 w-3 h-3 rounded-full bg-white transition-transform',
                                    isDarkMode ? 'translate-x-4' : 'translate-x-0.5'
                                )" />
                            </div>
                        </div>
                    </button>
                </div>

                <div class="border-t border-border py-1">
                    <!-- Release Notes -->
                    <button
                        @click="openLink(releaseNotesUrl)"
                        class="w-full flex items-center gap-3 px-4 py-2 text-sm text-foreground hover:bg-muted transition-colors"
                    >
                        <Gift class="h-4 w-4 text-muted-foreground" />
                        <span>What's New</span>
                        <ExternalLink class="h-3 w-3 ml-auto text-muted-foreground" />
                    </button>

                    <!-- Help/Documentation -->
                    <button
                        @click="openLink(docsUrl)"
                        class="w-full flex items-center gap-3 px-4 py-2 text-sm text-foreground hover:bg-muted transition-colors"
                    >
                        <HelpCircle class="h-4 w-4 text-muted-foreground" />
                        <span>Help</span>
                        <ExternalLink class="h-3 w-3 ml-auto text-muted-foreground" />
                    </button>

                    <!-- Cheatsheet -->
                    <button
                        @click="openLink(cheatsheetUrl)"
                        class="w-full flex items-center gap-3 px-4 py-2 text-sm text-foreground hover:bg-muted transition-colors"
                    >
                        <FileText class="h-4 w-4 text-muted-foreground" />
                        <span>Cheatsheet</span>
                        <ExternalLink class="h-3 w-3 ml-auto text-muted-foreground" />
                    </button>

                    <!-- Blog -->
                    <button
                        @click="openLink('https://blog.securityonion.net/')"
                        class="w-full flex items-center gap-3 px-4 py-2 text-sm text-foreground hover:bg-muted transition-colors"
                    >
                        <Newspaper class="h-4 w-4 text-muted-foreground" />
                        <span>Blog</span>
                        <ExternalLink class="h-3 w-3 ml-auto text-muted-foreground" />
                    </button>
                </div>

                <div class="border-t border-border py-1">
                    <!-- Pro Services -->
                    <button
                        @click="openLink('https://securityonionsolutions.com/pro')"
                        class="w-full flex items-center gap-3 px-4 py-2 text-sm text-foreground hover:bg-muted transition-colors"
                    >
                        <Star class="h-4 w-4 text-muted-foreground" />
                        <span>Pro Services</span>
                        <ExternalLink class="h-3 w-3 ml-auto text-muted-foreground" />
                    </button>

                    <!-- Hardware/Appliances -->
                    <button
                        @click="openLink('https://securityonionsolutions.com/hardware')"
                        class="w-full flex items-center gap-3 px-4 py-2 text-sm text-foreground hover:bg-muted transition-colors"
                    >
                        <Server class="h-4 w-4 text-muted-foreground" />
                        <span>Appliances</span>
                        <ExternalLink class="h-3 w-3 ml-auto text-muted-foreground" />
                    </button>

                    <!-- Premium Support -->
                    <button
                        @click="openLink('https://securityonionsolutions.com/support')"
                        class="w-full flex items-center gap-3 px-4 py-2 text-sm text-foreground hover:bg-muted transition-colors"
                    >
                        <Headphones class="h-4 w-4 text-muted-foreground" />
                        <span>Premium Support</span>
                        <ExternalLink class="h-3 w-3 ml-auto text-muted-foreground" />
                    </button>
                </div>

                <div class="border-t border-border py-1">
                    <!-- Profile Settings -->
                    <button
                        @click="goToSettings"
                        class="w-full flex items-center gap-3 px-4 py-2 text-sm text-foreground hover:bg-muted transition-colors"
                    >
                        <Settings class="h-4 w-4 text-muted-foreground" />
                        <span>Profile Settings</span>
                    </button>

                    <!-- Switch to Classic -->
                    <button
                        @click="switchToClassic"
                        class="w-full flex items-center gap-3 px-4 py-2 text-sm text-amber-500 hover:bg-muted transition-colors"
                    >
                        <FlaskConical class="h-4 w-4" />
                        <span>Switch to Classic</span>
                    </button>

                    <!-- Logout -->
                    <button
                        @click="logout"
                        class="w-full flex items-center gap-3 px-4 py-2 text-sm text-red-500 hover:bg-muted transition-colors"
                    >
                        <LogOut class="h-4 w-4" />
                        <span>Logout</span>
                    </button>
                </div>
            </div>
        </Transition>
    </div>
</template>
