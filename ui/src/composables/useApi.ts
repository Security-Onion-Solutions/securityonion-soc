import { ref } from 'vue'

interface FetchOptions extends RequestInit {
    params?: Record<string, string>
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

            const headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                ...options.headers,
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
