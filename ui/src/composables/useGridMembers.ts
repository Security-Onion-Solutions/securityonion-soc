import { ref } from 'vue'
import { useApi } from './useApi'

export interface GridMember {
    id: string
    hostname: string
    status: 'accepted' | 'unaccepted' | 'rejected' | 'denied'
    ip?: string
    os?: string
    version?: string
}

export function useGridMembers() {
    const { loading, error, get, post } = useApi()
    const members = ref<GridMember[]>([])
    const accepted = ref<GridMember[]>([])
    const unaccepted = ref<GridMember[]>([])
    const rejected = ref<GridMember[]>([])
    const denied = ref<GridMember[]>([])

    const fetchMembers = async () => {
        try {
            const data = await get<GridMember[]>('/api/gridmembers/')
            if (data) {
                members.value = data
                accepted.value = data.filter(m => m.status === 'accepted').sort((a, b) => a.id.localeCompare(b.id))
                unaccepted.value = data.filter(m => m.status === 'unaccepted').sort((a, b) => a.id.localeCompare(b.id))
                rejected.value = data.filter(m => m.status === 'rejected').sort((a, b) => a.id.localeCompare(b.id))
                denied.value = data.filter(m => m.status === 'denied').sort((a, b) => a.id.localeCompare(b.id))
            }
        } catch (e) {
            // handled in useApi
        }
    }

    const acceptMember = async (id: string) => {
        try {
            await post(`/api/gridmembers/${id}/add`)
            await fetchMembers()
        } catch (e) {
            throw e
        }
    }

    const rejectMember = async (id: string) => {
        try {
            await post(`/api/gridmembers/${id}/reject`)
            await fetchMembers()
        } catch (e) {
            throw e
        }
    }

    const deleteMember = async (id: string) => {
        try {
            await post(`/api/gridmembers/${id}/delete`)
            await fetchMembers()
        } catch (e) {
            throw e
        }
    }

    return {
        members,
        accepted,
        unaccepted,
        rejected,
        denied,
        loading,
        error,
        fetchMembers,
        acceptMember,
        rejectMember,
        deleteMember,
    }
}
