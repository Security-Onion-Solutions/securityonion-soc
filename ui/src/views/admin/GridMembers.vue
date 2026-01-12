<script setup lang="ts">
import { onMounted } from 'vue'
import { useGridMembers } from '../../composables/useGridMembers'
import { 
  Server, 
  CheckCircle2, 
  XCircle, 
  AlertTriangle, 
  Trash2,
  Cpu
} from 'lucide-vue-next'

const { 
  loading, 
  error, 
  accepted, 
  unaccepted, 
  rejected, 
  denied, 
  fetchMembers, 
  acceptMember, 
  rejectMember, 
  deleteMember 
} = useGridMembers()

onMounted(() => {
  fetchMembers()
})

const handleAccept = async (id: string) => {
    if (confirm(`Are you sure you want to accept node ${id}?`)) {
        await acceptMember(id)
    }
}

const handleReject = async (id: string) => {
  if (confirm(`Are you sure you want to reject node ${id}?`)) {
    await rejectMember(id)
  }
}

const handleDelete = async (id: string) => {
  if (confirm(`Are you sure you want to delete node ${id}? This action cannot be undone.`)) {
    await deleteMember(id)
  }
}
</script>

<template>
  <div class="space-y-8 animate-in fade-in duration-500">
    
    <!-- Error State -->
    <div v-if="error" class="p-4 rounded-md bg-destructive/15 text-destructive flex items-center gap-2">
      <AlertTriangle class="h-5 w-5" />
      <span class="text-sm font-medium">{{ error }}</span>
    </div>

    <!-- Stats / Overview -->
    <div class="grid gap-4 md:grid-cols-4">
      <div class="p-6 rounded-xl border border-border bg-card shadow-sm">
        <div class="flex items-center gap-2 text-sm font-medium text-muted-foreground mb-2">
          <Server class="h-4 w-4" />
          Total Nodes
        </div>
        <div class="text-2xl font-bold">{{ accepted.length + unaccepted.length + rejected.length + denied.length }}</div>
      </div>
      <div class="p-6 rounded-xl border border-border bg-card shadow-sm">
        <div class="flex items-center gap-2 text-sm font-medium text-muted-foreground mb-2">
           <AlertTriangle class="h-4 w-4 text-amber-500" />
           Pending
        </div>
        <div class="text-2xl font-bold">{{ unaccepted.length }}</div>
      </div>
       <div class="p-6 rounded-xl border border-border bg-card shadow-sm">
        <div class="flex items-center gap-2 text-sm font-medium text-muted-foreground mb-2">
          <CheckCircle2 class="h-4 w-4 text-green-500" />
          Active
        </div>
        <div class="text-2xl font-bold">{{ accepted.length }}</div>
      </div>
    </div>

    <!-- Unaccepted (Pending) Nodes -->
    <div v-if="unaccepted.length > 0" class="space-y-4">
      <h3 class="text-lg font-semibold flex items-center gap-2 text-amber-500">
        <AlertTriangle class="h-5 w-5" />
        Pending Approval
      </h3>
      <div class="rounded-xl border border-border bg-card overflow-hidden shadow-sm border-l-4 border-l-amber-500">
        <div class="overflow-x-auto">
          <table class="w-full text-sm text-left">
            <thead class="bg-muted/50 text-muted-foreground font-medium border-b border-border">
              <tr>
                <th class="h-10 px-4 align-middle">Node ID / Hostname</th>
                <th class="h-10 px-4 align-middle">IP Address</th>
                <th class="h-10 px-4 align-middle">OS / Version</th>
                <th class="h-10 px-4 align-middle text-right">Actions</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-border">
              <tr v-for="node in unaccepted" :key="node.id" class="hover:bg-muted/50 transition-colors">
                <td class="p-4 font-mono font-medium">
                    <div class="flex items-center gap-2">
                        <Server class="h-4 w-4 text-muted-foreground" />
                        {{ node.id }}
                    </div>
                </td>
                <td class="p-4">{{ node.ip || 'Unknown' }}</td>
                <td class="p-4 text-muted-foreground">{{ node.os }}</td>
                <td class="p-4 text-right">
                  <div class="flex items-center justify-end gap-2">
                    <button 
                      @click="handleAccept(node.id)" 
                      class="px-3 py-1.5 rounded-md text-xs font-medium bg-green-500/10 text-green-600 hover:bg-green-500/20 transition-colors"
                    >
                      Accept
                    </button>
                    <button 
                      @click="handleReject(node.id)" 
                      class="px-3 py-1.5 rounded-md text-xs font-medium bg-red-500/10 text-red-600 hover:bg-red-500/20 transition-colors"
                    >
                      Reject
                    </button>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Accepted Nodes -->
    <div class="space-y-4">
      <h3 class="text-lg font-semibold flex items-center gap-2 text-primary">
        <Server class="h-5 w-5" />
        Grid Members
      </h3>
      <div class="rounded-xl border border-border bg-card overflow-hidden shadow-sm">
        <div class="overflow-x-auto">
          <table class="w-full text-sm text-left">
            <thead class="bg-muted/50 text-muted-foreground font-medium border-b border-border">
              <tr>
                <th class="h-10 px-4 align-middle">Node ID / Hostname</th>
                <th class="h-10 px-4 align-middle">Status</th>
                <th class="h-10 px-4 align-middle text-right">Actions</th>
              </tr>
            </thead>
             <tbody class="divide-y divide-border">
                <tr v-if="loading && accepted.length === 0">
                    <td colspan="3" class="p-8 text-center text-muted-foreground">Loading grid members...</td>
                </tr>
                <tr v-else-if="accepted.length === 0 && !loading">
                     <td colspan="3" class="p-8 text-center text-muted-foreground">No active grid members found.</td>
                </tr>
                <tr v-else v-for="node in accepted" :key="node.id" class="hover:bg-muted/50 transition-colors group">
                    <td class="p-4 font-mono">
                        <div class="flex items-center gap-3">
                            <div class="h-8 w-8 rounded-full bg-primary/10 flex items-center justify-center text-primary">
                                <Cpu class="h-4 w-4" />
                            </div>
                            <div>
                                <div class="font-medium text-foreground">{{ node.id }}</div>
                                <div class="text-xs text-muted-foreground">{{ node.hostname || 'No Hostname' }}</div>
                            </div>
                        </div>
                    </td>
                    <td class="p-4">
                        <span class="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-500/10 text-green-600">
                            <CheckCircle2 class="h-3.5 w-3.5" />
                            Connected
                        </span>
                    </td>
                    <td class="p-4 text-right">
                         <button 
                            @click="handleDelete(node.id)" 
                            class="p-2 rounded-md hover:bg-red-500/10 text-muted-foreground hover:text-red-500 transition-colors opacity-0 group-hover:opacity-100"
                            title="Remove Node"
                        >
                            <Trash2 class="h-4 w-4" />
                        </button>
                    </td>
                </tr>
             </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Rejected/Denied Nodes (Collapsed or Bottom) -->
    <div v-if="rejected.length > 0 || denied.length > 0" class="space-y-4 pt-8">
         <h3 class="text-lg font-semibold flex items-center gap-2 text-muted-foreground">
            <XCircle class="h-5 w-5" />
            Rejected / Denied Nodes
        </h3>
         <div class="rounded-xl border border-border bg-card overflow-hidden shadow-sm opacity-75">
             <div class="overflow-x-auto">
                <table class="w-full text-sm text-left">
                    <thead class="bg-muted/50 text-muted-foreground font-medium border-b border-border">
                    <tr>
                        <th class="h-10 px-4 align-middle">Node ID</th>
                        <th class="h-10 px-4 align-middle">Status</th>
                        <th class="h-10 px-4 align-middle text-right">Actions</th>
                    </tr>
                    </thead>
                    <tbody class="divide-y divide-border">
                        <tr v-for="node in [...rejected, ...denied]" :key="node.id" class="hover:bg-muted/50 transition-colors">
                            <td class="p-4 font-mono text-muted-foreground">{{ node.id }}</td>
                            <td class="p-4">
                                <span class="capitalize text-destructive font-medium">{{ node.status }}</span>
                            </td>
                            <td class="p-4 text-right">
                                <button 
                                    @click="handleDelete(node.id)" 
                                    class="text-sm text-destructive hover:underline"
                                >
                                    Delete Permanently
                                </button>
                            </td>
                        </tr>
                    </tbody>
                </table>
             </div>
         </div>
    </div>

  </div>
</template>
