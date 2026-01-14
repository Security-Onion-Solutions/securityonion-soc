import { ref, watch } from 'vue'

type Theme = 'light' | 'dark'

// Global state
const isDarkMode = ref(true) // Default to dark

// Initialize theme from localStorage or system preference
function initializeTheme() {
    const stored = localStorage.getItem('theme')
    if (stored === 'light' || stored === 'dark') {
        isDarkMode.value = stored === 'dark'
    } else {
        // Default to dark for Security Onion
        isDarkMode.value = true
    }
    applyTheme()
}

// Apply theme to DOM
function applyTheme() {
    if (isDarkMode.value) {
        document.documentElement.classList.add('dark')
    } else {
        document.documentElement.classList.remove('dark')
    }
}

// Toggle theme
function toggleTheme() {
    isDarkMode.value = !isDarkMode.value
    localStorage.setItem('theme', isDarkMode.value ? 'dark' : 'light')
    applyTheme()
}

// Set specific theme
function setTheme(theme: Theme) {
    isDarkMode.value = theme === 'dark'
    localStorage.setItem('theme', theme)
    applyTheme()
}

// Watch for changes and apply
watch(isDarkMode, () => {
    applyTheme()
})

export function useTheme() {
    return {
        isDarkMode,
        initializeTheme,
        toggleTheme,
        setTheme,
    }
}
