import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { fileURLToPath, URL } from 'node:url'
import path from 'path'

// https://vitejs.dev/config/
export default defineConfig({
    plugins: [vue()],
    resolve: {
        alias: {
            '@': fileURLToPath(new URL('./src', import.meta.url))
        }
    },
    base: '/modern/', // Absolute path for correct server routing
    build: {
        outDir: '../html/modern',
        emptyOutDir: true,
        rollupOptions: {
            input: {
                main: fileURLToPath(new URL('./index.html', import.meta.url)),
            },
        }
    }
})
