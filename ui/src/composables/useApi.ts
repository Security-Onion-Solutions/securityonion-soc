import { ref } from 'vue'

interface FetchOptions extends RequestInit {
    params?: Record<string, string>
}

// Global CSRF token cache
let srvToken: string | null = null
let tokenPromise: Promise<string | null> | null = null

async function ensureSrvToken(): Promise<string | null> {
    if (srvToken) {
        return srvToken
    }

    // Avoid multiple parallel fetches
    if (tokenPromise) {
        return tokenPromise
    }

    tokenPromise = (async () => {
        try {
            const response = await fetch('/api/info')
            if (response.ok) {
                const data = await response.json()
                srvToken = data.srvToken || null
            }
        } catch (e) {
            console.error('Failed to fetch srvToken:', e)
        }
        return srvToken
    })()

    return tokenPromise
}

export function useApi() {
    const loading = ref(false)
    const error = ref<string | null>(null)

    const request = async <T>(url: string, options: FetchOptions = {}): Promise<T | null> => {
        loading.value = true
        error.value = null

        try {
            let finalUrl = url
            if (options.params) {
                const queryParams = new URLSearchParams(options.params)
                finalUrl += `?${queryParams.toString()}`
            }

            const headers: Record<string, string> = {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                ...(options.headers as Record<string, string> || {}),
            }

            // Add CSRF token for mutating requests
            const method = options.method?.toUpperCase()
            if (method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE') {
                const token = await ensureSrvToken()
                if (token) {
                    headers['X-Srv-Token'] = token
                }
            }

            const response = await fetch(finalUrl, {
                ...options,
                headers,
            })

            if (!response.ok) {
                const errorText = await response.text()
                throw new Error(errorText || `API request failed with status ${response.status}`)
            }

            // Handle empty responses (e.g. 204 No Content)
            if (response.status === 204) {
                return null
            }

            const data = await response.json()
            return data as T
        } catch (e: any) {
            error.value = e.message || 'An unknown error occurred'
            console.error('API Error:', e)
            throw e
        } finally {
            loading.value = false
        }
    }

    const get = <T>(url: string, params?: Record<string, string>) => request<T>(url, { method: 'GET', params })
    const post = <T>(url: string, body?: any) => request<T>(url, { method: 'POST', body: JSON.stringify(body) })
    const put = <T>(url: string, body?: any) => request<T>(url, { method: 'PUT', body: JSON.stringify(body) })
    const del = <T>(url: string) => request<T>(url, { method: 'DELETE' })

    return {
        loading,
        error,
        get,
        post,
        put,
        del,
    }
}
