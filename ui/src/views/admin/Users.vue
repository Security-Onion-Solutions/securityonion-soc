<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { useUsers, type User } from '../../composables/useUsers'
import { 
  Plus, 
  Search, 
  Shield, 
  Ban, 
  Trash2,
  Lock,
  Unlock,
  Pencil,
  AlertCircle
} from 'lucide-vue-next'

const { 
    users, 
    roles, 
    loading, 
    fetchUsers, 
    fetchRoles, 
    addUser, 
    toggleUserStatus, 
    deleteUser,
    updateUserProfile,
    error: usersError
} = useUsers()

onMounted(async () => {
    await Promise.all([fetchUsers(), fetchRoles()])
})

// Local state for UI
const searchQuery = ref('')
const showAddDialog = ref(false)
const selectedUser = ref<User | null>(null)

// Computed
const filteredUsers = computed(() => {
    if (!searchQuery.value) return users.value
    const query = searchQuery.value.toLowerCase()
    return users.value.filter(u => 
        u.email.toLowerCase().includes(query) || 
        (u.firstName?.toLowerCase().includes(query) || '') || 
        (u.lastName?.toLowerCase().includes(query) || '')
    )
})

// Forms
const newUser = ref({
    email: '',
    password: '',
    role: '',
    firstName: '',
    lastName: '',
    note: ''
})

const isEditing = ref(false)

const openAddDialog = () => {
    isEditing.value = false
    newUser.value = { email: '', password: '', role: '', firstName: '', lastName: '', note: '' }
    showAddDialog.value = true
}

const openEditDialog = (user: User) => {
    isEditing.value = true
    selectedUser.value = user
    newUser.value = {
        email: user.email,
        password: '', // Password not editable during simple profile update usually
        role: user.roles[0] || '', // Assuming single role for now or primary
        firstName: user.firstName || '',
        lastName: user.lastName || '',
        note: user.note || ''
    }
    showAddDialog.value = true
}

const handleSubmit = async () => {
    try {
        if (isEditing.value && selectedUser.value) {
            await updateUserProfile(selectedUser.value.id, {
                firstName: newUser.value.firstName,
                lastName: newUser.value.lastName,
                note: newUser.value.note
            })
        } else {
             await addUser(newUser.value)
        }
        showAddDialog.value = false
        newUser.value = { email: '', password: '', role: '', firstName: '', lastName: '', note: '' }
    } catch (e) {
        // Error handled in composable but nice to verify/toast
    }
}

const confirmDelete = async (user: User) => {
    if (confirm(`Are you sure you want to delete ${user.email}?`)) {
        await deleteUser(user.id)
    }
}

const handleToggleStatus = async (user: User) => {
    await toggleUserStatus(user.id, user.status)
}

</script>

<template>
  <div class="space-y-6">
    <!-- Error Alert -->
    <div v-if="usersError" class="p-4 rounded-md bg-destructive/15 text-destructive flex items-center gap-2">
        <AlertCircle class="h-5 w-5" />
        <span class="text-sm font-medium">{{ usersError }}</span>
    </div>

    <!-- Toolbar -->
    <div class="flex items-center justify-between">
      <div class="relative w-64">
        <Search class="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
        <input
          v-model="searchQuery"
          type="text"
          placeholder="Search users..."
          class="pl-8 h-9 w-full rounded-md border border-input bg-background px-3 py-1 text-sm shadow-sm transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
        />
      </div>
      <button
        @click="openAddDialog"
        class="inline-flex items-center justify-center rounded-md text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50 bg-primary text-primary-foreground shadow hover:bg-primary/90 h-9 px-4 py-2"
      >
        <Plus class="mr-2 h-4 w-4" />
        Add User
      </button>
    </div>

    <!-- Data Table -->
    <div class="rounded-md border border-border">
      <table class="w-full text-sm text-left">
        <thead class="bg-muted/50 text-muted-foreground font-medium border-b border-border">
          <tr>
            <th class="h-10 px-4 align-middle">Email</th>
            <th class="h-10 px-4 align-middle">Name</th>
            <th class="h-10 px-4 align-middle">Role</th>
             <th class="h-10 px-4 align-middle">Status</th>
            <th class="h-10 px-4 align-middle text-right">Actions</th>
          </tr>
        </thead>
        <tbody>
            <tr v-if="loading" class="border-b border-border">
                <td colspan="5" class="p-4 text-center text-muted-foreground">Loading...</td>
            </tr>
            <tr v-else-if="filteredUsers.length === 0" class="border-b border-border">
                <td colspan="5" class="p-4 text-center text-muted-foreground">No users found.</td>
            </tr>
            <tr 
                v-else
                v-for="user in filteredUsers" 
                :key="user.id" 
                class="border-b border-border hover:bg-muted/50 transition-colors"
             >
                <td class="p-4 font-medium">{{ user.email }}</td>
                <td class="p-4">
                    {{ user.firstName }} {{ user.lastName }}
                </td>
                <td class="p-4">
                     <span class="inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 border-transparent bg-secondary text-secondary-foreground hover:bg-secondary/80">
                        {{ user.roles.join(', ') }}
                     </span>
                </td>
                <td class="p-4">
                     <span v-if="user.status === 'enabled'" class="inline-flex items-center text-green-500 font-medium text-xs">
                        <Shield class="w-3 h-3 mr-1" /> Active
                     </span>
                      <span v-else class="inline-flex items-center text-red-500 font-medium text-xs">
                        <Ban class="w-3 h-3 mr-1" /> Locked
                     </span>
                </td>
                <td class="p-4 text-right">
                    <div class="flex items-center justify-end gap-2">
                            <button 
                                @click="openEditDialog(user)" 
                                title="Edit User"
                                class="p-2 rounded-md hover:bg-muted text-muted-foreground hover:text-foreground"
                            >
                                <Pencil class="h-4 w-4" />
                            </button>
                            <button 
                                @click="handleToggleStatus(user)"
                                :title="user.status === 'enabled' ? 'Lock User' : 'Unlock User'"
                                class="p-2 rounded-md hover:bg-muted text-muted-foreground hover:text-foreground"
                            >
                                <Lock v-if="user.status === 'enabled'" class="h-4 w-4" />
                                <Unlock v-else class="h-4 w-4" />
                            </button>
                         <button 
                            @click="confirmDelete(user)" 
                            title="Delete User"
                            class="p-2 rounded-md hover:bg-red-500/10 text-muted-foreground hover:text-red-500"
                        >
                            <Trash2 class="h-4 w-4" />
                        </button>
                    </div>
                </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- Add User Dialog (Simple Modal Implementation) -->
    <div v-if="showAddDialog" class="fixed inset-0 z-50 bg-black/50 flex items-center justify-center p-4">
        <div class="bg-card text-card-foreground border border-border rounded-lg shadow-lg w-full max-w-lg p-6 space-y-4">
            <h3 class="text-lg font-semibold">{{ isEditing ? 'Edit User' : 'Add New User' }}</h3>
            <div class="grid gap-4 py-4">
                 <div class="grid grid-cols-4 items-center gap-4">
                    <label class="text-right text-sm font-medium">Email</label>
                    <input v-model="newUser.email" :disabled="isEditing" class="col-span-3 flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm transition-colors file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50" />
                </div>
                 <div v-if="!isEditing" class="grid grid-cols-4 items-center gap-4">
                    <label class="text-right text-sm font-medium">Password</label>
                    <input type="password" v-model="newUser.password" class="col-span-3 flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm transition-colors file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50" />
                </div>
                <div v-if="!isEditing" class="grid grid-cols-4 items-center gap-4">
                    <label class="text-right text-sm font-medium">Role</label>
                    <select v-model="newUser.role" class="col-span-3 flex h-9 w-full rounded-md border border-input bg-card px-3 py-1 text-sm shadow-sm transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring">
                        <option value="" disabled>Select a role</option>
                        <option v-for="role in roles" :key="role" :value="role">{{ role }}</option>
                    </select>
                </div>
                 <div class="grid grid-cols-4 items-center gap-4">
                    <label class="text-right text-sm font-medium">First Name</label>
                    <input v-model="newUser.firstName" class="col-span-3 flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm transition-colors file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50" />
                </div>
                 <div class="grid grid-cols-4 items-center gap-4">
                    <label class="text-right text-sm font-medium">Last Name</label>
                    <input v-model="newUser.lastName" class="col-span-3 flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm transition-colors file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50" />
                </div>
            </div>
            <div class="flex justify-end gap-2">
                <button @click="showAddDialog = false" class="inline-flex items-center justify-center rounded-md text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50 border border-input bg-transparent shadow-sm hover:bg-accent hover:text-accent-foreground h-9 px-4 py-2">
                    Cancel
                </button>
                <button @click="handleSubmit" class="inline-flex items-center justify-center rounded-md text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50 bg-primary text-primary-foreground shadow hover:bg-primary/90 h-9 px-4 py-2">
                    {{ isEditing ? 'Update User' : 'Create User' }}
                </button>
            </div>
        </div>
    </div>

  </div>
</template>
