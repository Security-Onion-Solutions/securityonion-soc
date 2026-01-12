import { ref } from 'vue'
import { useApi } from './useApi'

export interface User {
    id: string
    email: string
    firstName?: string
    lastName?: string
    roles: string[]
    status: string
    note?: string
    oidcStatus?: string
    totpStatus?: string
    webauthnStatus?: string
    passwordChanged?: boolean
}

export function useUsers() {
    const { loading, error, get, post, put, del } = useApi()
    const users = ref<User[]>([])
    const roles = ref<string[]>([])

    const fetchUsers = async () => {
        try {
            const data = await get<User[]>('/api/users/')
            if (data) {
                users.value = data
            }
        } catch (e) {
            // Error handled in useApi
        }
    }

    const fetchRoles = async () => {
        try {
            const data = await get<string[]>('/api/roles/')
            if (data) {
                // Filter out 'agent' role as it's for services, not humans
                roles.value = data.filter(role => role !== 'agent')
            }
        } catch (e) {
            // Error handled in useApi
        }
    }

    const addUser = async (user: Partial<User> & { password?: string, role?: string }) => {
        try {
            await post('/api/users/', {
                email: user.email,
                password: user.password, // Only used for creation
                roles: user.role ? [user.role] : [],
                firstName: user.firstName,
                lastName: user.lastName,
                note: user.note,
            })
            await fetchUsers()
        } catch (e) {
            throw e
        }
    }

    const updateUserProfile = async (id: string, updates: { firstName?: string, lastName?: string, note?: string }) => {
        try {
            await put(`/api/users/${id}`, updates)
            await fetchUsers()
        } catch (e) {
            throw e
        }
    }

    const toggleUserStatus = async (id: string, currentStatus: string) => {
        const action = currentStatus === 'locked' ? 'enable' : 'disable'
        try {
            await put(`/api/users/${id}/${action}`)
            await fetchUsers()
        } catch (e) {
            throw e
        }
    }

    const resetPassword = async (id: string, password: string) => {
        try {
            await put(`/api/users/${id}/password`, { password })
        } catch (e) {
            throw e
        }
    }

    const deleteUser = async (id: string) => {
        try {
            await del(`/api/users/${id}`)
            users.value = users.value.filter(u => u.id !== id)
        } catch (e) {
            throw e
        }
    }

    const addRole = async (userId: string, role: string) => {
        try {
            await post(`/api/users/${userId}/role/${role}`)
            await fetchUsers()
        } catch (e) {
            throw e
        }
    }

    const removeRole = async (userId: string, role: string) => {
        try {
            await del(`/api/users/${userId}/role/${role}`)
            await fetchUsers()
        } catch (e) {
            throw e
        }
    }

    const syncUsers = async () => {
        try {
            await put('/api/users/sync')
            await fetchUsers()
        } catch (e) {
            throw e
        }
    }

    const getUserName = (id: string) => {
        if (!id) return undefined
        const user = users.value.find(u => u.id === id || u.email === id)
        if (user) {
            if (user.firstName && user.lastName) return `${user.firstName} ${user.lastName}`
            return user.email
        }
        return undefined
    }


    return {
        users,
        roles,
        loading,
        error,
        fetchUsers,
        fetchRoles,
        addUser,
        updateUserProfile,
        toggleUserStatus,
        resetPassword,
        deleteUser,
        addRole,
        removeRole,
        syncUsers,
        getUserName
    }
}
