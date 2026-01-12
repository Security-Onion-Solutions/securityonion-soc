<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { Shield, AlertCircle } from 'lucide-vue-next'


const isLoading = ref(true)
const error = ref('')
const flow = ref<any>(null)
const csrfToken = ref('')
const passwordEnabled = ref(false)
const email = ref('')
const password = ref('')
const showPassword = ref(false)

// Function to get query parameters
function getSearchParam(param: string) {
  const searchParams = new URLSearchParams(window.location.search)
  return searchParams.get(param)
}

function getAuthFlowId() {
    let flowId = getSearchParam('flow')
    if (flowId) {
        localStorage.setItem('flowID', flowId)
    } else {
        flowId = localStorage.getItem('flowID')
    }
    return flowId;
}

// Ensure we have a flow ID, or redirect to init
async function initLogin() {
  const flowId = getAuthFlowId()
  if (!flowId) {
    // Redirect to Kratos init
    window.location.href = '/auth/self-service/login/browser'
    return
  }

  try {
    const response = await fetch(`/auth/self-service/login/flows?id=${flowId}`, {
        headers: { 'Accept': 'application/json' }
    })
    
    if (response.status === 410) {
        // Flow expired
        localStorage.removeItem('flowID')
        window.location.href = '/auth/self-service/login/browser'
        return
    }

    const data = await response.json()
    flow.value = data
    
    // Extract CSRF token
    const nodes = data.ui.nodes
    const csrfNode = nodes.find((n: any) => n.attributes.name === 'csrf_token')
    if (csrfNode) {
        csrfToken.value = csrfNode.attributes.value
    }

    // Check availability of password method
    const passwordGroup = nodes.find((n: any) => n.group === 'password')
    if (passwordGroup) {
        passwordEnabled.value = true
    }
    
    isLoading.value = false

  } catch (err: any) {
    error.value = err.message || 'Failed to load login flow'
    isLoading.value = false
  }
}

onMounted(() => {
  initLogin()
})
</script>

<template>
  <div class="min-h-screen flex flex-col items-center justify-center bg-background text-foreground p-4">
    <div class="w-full max-w-md space-y-8">
      <!-- Logo and Header -->
      <div class="flex flex-col items-center text-center">
        <div class="h-12 w-12 bg-primary rounded-lg flex items-center justify-center mb-4">
          <Shield class="h-8 w-8 text-primary-foreground" />
        </div>
        <h2 class="text-3xl font-bold tracking-tight">Welcome back</h2>
        <p class="mt-2 text-muted-foreground">Sign in to your account to continue</p>
      </div>

      <!-- Loading State -->
      <div v-if="isLoading" class="flex justify-center p-8">
        <div class="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent"></div>
      </div>

      <!-- Error State -->
      <div v-else-if="error" class="bg-destructive/10 border border-destructive/20 rounded-lg p-4 flex items-center gap-3 text-destructive">
        <AlertCircle class="h-5 w-5" />
        <p class="text-sm font-medium">{{ error }}</p>
      </div>

      <!-- Login Form -->
      <div v-else class="bg-card border border-border rounded-xl shadow-sm overflow-hidden">
        <div class="p-6 sm:p-8 space-y-6">
            
            <form v-if="flow" :action="flow.ui.action" method="POST" class="space-y-4">
                <input type="hidden" name="csrf_token" :value="csrfToken" />
                
                <div v-if="passwordEnabled" class="space-y-4">
                    <div class="space-y-2">
                        <label for="identifier" class="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70">Email</label>
                        <input 
                            id="identifier" 
                            name="identifier" 
                            v-model="email"
                            type="email" 
                            placeholder="name@example.com" 
                            required
                            class="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                        />
                    </div>
                    
                    <div class="space-y-2">
                         <div class="flex items-center justify-between">
                            <label for="password" class="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70">Password</label>
                            <!-- <a href="#" class="text-sm font-medium text-primary hover:underline">Forgot password?</a> -->
                         </div>
                        <div class="relative">
                            <input 
                                id="password" 
                                name="password" 
                                v-model="password"
                                :type="showPassword ? 'text' : 'password'" 
                                required
                                class="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                            />
                            <button 
                                type="button" 
                                @click="showPassword = !showPassword"
                                class="absolute right-3 top-2.5 text-muted-foreground hover:text-foreground"
                            > 
                                <span class="text-xs uppercase font-bold">{{ showPassword ? 'Hide' : 'Show' }}</span>
                            </button>
                        </div>
                    </div>
                    
                    <input type="hidden" name="method" value="password" />

                    <button 
                        type="submit" 
                        class="inline-flex items-center justify-center whitespace-nowrap rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 bg-primary text-primary-foreground hover:bg-primary/90 h-10 px-4 py-2 w-full"
                    >
                        Sign in
                    </button>
                </div>
                
                <div v-else class="text-center text-muted-foreground">
                    No password login available.
                </div>
            </form>

        </div>
      </div>
      
       <div class="text-center text-sm text-muted-foreground">
        <a href="/" class="hover:text-primary underline underline-offset-4">Back to Classic Interface</a>
      </div>

    </div>
  </div>
</template>
