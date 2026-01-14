import { createApp } from 'vue'
import './style.css'
import App from './App.vue'
import router from './router'
import { useTheme } from './composables/useTheme'

// Initialize theme before mounting to prevent flash
const { initializeTheme } = useTheme()
initializeTheme()

const app = createApp(App)
app.use(router)
app.mount('#app')
