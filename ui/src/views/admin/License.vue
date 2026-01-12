<script setup lang="ts">
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

import { ref, onMounted, computed } from 'vue'
import { useApi } from '../../composables/useApi'
import { formatDateOnly } from '../../composables/useFormatters'
import {
  Key,
  FileText,
  Copy,
  Pencil,
  AlertCircle,
  CheckCircle,
  Clock,
  XCircle,
  Info,
  ExternalLink,
  Bot,
  Zap,
  Sparkles,
  Crown,
  Check
} from 'lucide-vue-next'

// License status constants
const LICENSE_STATUS_ACTIVE = 'active'
const LICENSE_STATUS_EXCEEDED = 'exceeded'
const LICENSE_STATUS_EXPIRED = 'expired'
const LICENSE_STATUS_INVALID = 'invalid'
const LICENSE_STATUS_PENDING = 'pending'
const LICENSE_STATUS_UNPROVISIONED = 'unprovisioned'

// Feature name mappings
const featureNames: Record<string, string> = {
  'oai': 'Onion AI',
  'oidc': 'OpenID Connect',
  'enc': 'Disk Encryption',
  'fips': 'FIPS Compliance',
  'stig': 'STIG Compliance',
  'ntf': 'External Notifications',
  'tme': 'Time Tracking',
  'gmd': 'Guaranteed Message Delivery',
  'api': 'External API',
  'qry': 'Active Query Management',
  'rpt': 'Reporting & Exports',
  'mcp': 'AI/LLM MCP Server',
  'mom': 'Manager of Managers',
  'spl': 'Splunk App',
  'hvr': 'Hardware Virtualization'
}

interface LicenseKey {
  id: string
  name: string
  licensee: string
  effective: string
  expiration: string
  users: number
  nodes: number
  subgrids: number
  features: string[]
  socUrl: string
  dataUrl: string
  mgmtMac: string
}

interface LicenseInfo {
  licenseKey: LicenseKey | null
  licenseStatus: string
  mgmtMac: string
}

const { get, loading, error } = useApi()

const licenseInfo = ref<LicenseInfo | null>(null)
const activeTab = ref<'key' | 'terms'>('key')
const copySuccess = ref(false)

onMounted(async () => {
  await fetchLicenseInfo()
})

async function fetchLicenseInfo() {
  try {
    const data = await get<LicenseInfo>('/api/info')
    if (data) {
      licenseInfo.value = {
        licenseKey: data.licenseKey,
        licenseStatus: data.licenseStatus,
        mgmtMac: data.mgmtMac
      }
    }
  } catch (e) {
    console.error('Failed to fetch license info:', e)
  }
}

const isProvisioned = computed(() => {
  return licenseInfo.value?.licenseStatus !== LICENSE_STATUS_UNPROVISIONED &&
         licenseInfo.value?.licenseStatus !== LICENSE_STATUS_INVALID
})

function getStatusStyles(status: string): string {
  switch (status) {
    case LICENSE_STATUS_ACTIVE:
      return 'bg-green-500/10 text-green-500 border-green-500/20'
    case LICENSE_STATUS_EXCEEDED:
    case LICENSE_STATUS_INVALID:
      return 'bg-red-500/10 text-red-500 border-red-500/20'
    case LICENSE_STATUS_EXPIRED:
    case LICENSE_STATUS_PENDING:
      return 'bg-amber-500/10 text-amber-500 border-amber-500/20'
    default:
      return 'bg-blue-500/10 text-blue-500 border-blue-500/20'
  }
}

function getStatusIcon(status: string) {
  switch (status) {
    case LICENSE_STATUS_ACTIVE:
      return CheckCircle
    case LICENSE_STATUS_EXCEEDED:
    case LICENSE_STATUS_INVALID:
      return XCircle
    case LICENSE_STATUS_EXPIRED:
    case LICENSE_STATUS_PENDING:
      return Clock
    default:
      return Info
  }
}

function getStatusLabel(status: string): string {
  switch (status) {
    case LICENSE_STATUS_ACTIVE:
      return 'Active'
    case LICENSE_STATUS_EXCEEDED:
      return 'Exceeded'
    case LICENSE_STATUS_EXPIRED:
      return 'Expired'
    case LICENSE_STATUS_INVALID:
      return 'Invalid'
    case LICENSE_STATUS_PENDING:
      return 'Pending'
    case LICENSE_STATUS_UNPROVISIONED:
      return 'Community'
    default:
      return status
  }
}

function getFeatureName(feature: string): string {
  return featureNames[feature.toLowerCase()] || feature
}

async function copyToClipboard(text: string) {
  try {
    await navigator.clipboard.writeText(text)
    copySuccess.value = true
    setTimeout(() => {
      copySuccess.value = false
    }, 2000)
  } catch (e) {
    console.error('Failed to copy:', e)
  }
}

function formatLimit(value: number): string {
  return value > 0 ? value.toString() : 'Unlimited'
}

// Onion AI Registration
const showRegistrationDialog = ref(false)
const selectedPlan = ref<string | null>(null)

interface AiCreditPlan {
  id: string
  name: string
  credits: number
  price: number
  pricePerCredit: number
  popular?: boolean
  features: string[]
}

const aiCreditPlans: AiCreditPlan[] = [
  {
    id: 'starter',
    name: 'Starter',
    credits: 1000,
    price: 50,
    pricePerCredit: 0.05,
    features: [
      '1,000 AI credits',
      'Basic threat analysis',
      'Standard response time',
      'Email support'
    ]
  },
  {
    id: 'professional',
    name: 'Professional',
    credits: 5000,
    price: 200,
    pricePerCredit: 0.04,
    popular: true,
    features: [
      '5,000 AI credits',
      'Advanced threat analysis',
      'Priority response time',
      'Priority support',
      'Custom playbooks'
    ]
  },
  {
    id: 'enterprise',
    name: 'Enterprise',
    credits: 20000,
    price: 600,
    pricePerCredit: 0.03,
    features: [
      '20,000 AI credits',
      'Full threat intelligence',
      'Fastest response time',
      'Dedicated support',
      'Custom playbooks',
      'API access',
      'Bulk analysis'
    ]
  }
]

function openRegistrationDialog() {
  selectedPlan.value = null
  showRegistrationDialog.value = true
}

function selectPlan(planId: string) {
  selectedPlan.value = planId
}

function handleRegister() {
  // Placeholder - would integrate with actual registration flow
  console.log('Registering with plan:', selectedPlan.value)
  alert('This feature is coming soon! Registration with Onion AI will be available in a future release.')
  showRegistrationDialog.value = false
}
</script>

<template>
  <div class="space-y-6">
    <!-- Error Alert -->
    <div v-if="error" class="p-4 rounded-md bg-destructive/15 text-destructive flex items-center gap-2">
      <AlertCircle class="h-5 w-5" />
      <span class="text-sm font-medium">{{ error }}</span>
    </div>

    <!-- Header -->
    <div class="flex items-center justify-between">
      <h2 class="text-xl font-semibold">Licensing</h2>
    </div>

    <!-- Tabs -->
    <div class="border-b border-border">
      <div class="flex gap-4">
        <button
          @click="activeTab = 'key'"
          :class="[
            'flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors -mb-px',
            activeTab === 'key'
              ? 'border-primary text-primary'
              : 'border-transparent text-muted-foreground hover:text-foreground'
          ]"
        >
          <Key class="h-4 w-4" />
          License Key
        </button>
        <button
          @click="activeTab = 'terms'"
          :class="[
            'flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors -mb-px',
            activeTab === 'terms'
              ? 'border-primary text-primary'
              : 'border-transparent text-muted-foreground hover:text-foreground'
          ]"
        >
          <FileText class="h-4 w-4" />
          License Terms
        </button>
      </div>
    </div>

    <!-- Loading State -->
    <div v-if="loading" class="flex items-center justify-center py-12">
      <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
    </div>

    <!-- License Key Tab -->
    <div v-else-if="activeTab === 'key'" class="space-y-6">
      <!-- Onion AI Registration Card -->
      <div class="rounded-lg border border-border bg-card">
        <div class="p-4 border-b border-border flex items-center justify-between">
          <h3 class="font-semibold flex items-center gap-2">
            <Bot class="h-5 w-5" />
            Onion AI
          </h3>
          <span class="text-xs text-muted-foreground bg-amber-500/10 text-amber-500 px-2 py-0.5 rounded-full">
            Coming Soon
          </span>
        </div>
        <div class="p-6">
          <div class="flex flex-col md:flex-row md:items-center gap-4 md:gap-6">
            <div class="flex-1">
              <p class="text-sm text-muted-foreground mb-2">
                Register your grid with Onion AI to enable powerful AI-assisted threat analysis,
                automated investigations, and intelligent security recommendations.
              </p>
              <ul class="text-sm text-muted-foreground space-y-1">
                <li class="flex items-center gap-2">
                  <Sparkles class="h-4 w-4 text-primary" />
                  AI-powered threat analysis and hunting
                </li>
                <li class="flex items-center gap-2">
                  <Zap class="h-4 w-4 text-primary" />
                  Automated incident investigation
                </li>
                <li class="flex items-center gap-2">
                  <Bot class="h-4 w-4 text-primary" />
                  Natural language security queries
                </li>
              </ul>
            </div>
            <div class="flex-shrink-0">
              <button
                @click="openRegistrationDialog"
                class="inline-flex items-center justify-center gap-2 rounded-md text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring bg-primary text-primary-foreground shadow hover:bg-primary/90 h-10 px-6"
              >
                <Bot class="h-4 w-4" />
                Register with Onion AI
              </button>
            </div>
          </div>
        </div>
      </div>

      <div class="rounded-lg border border-border bg-card">
        <div class="p-4 border-b border-border flex items-center justify-between">
          <h3 class="font-semibold flex items-center gap-2">
            <Key class="h-5 w-5" />
            License Key
          </h3>
          <a
            href="/#/config?s=soc.config.licenseKey"
            class="inline-flex items-center gap-1 text-sm text-primary hover:underline"
          >
            <Pencil class="h-4 w-4" />
            Edit
          </a>
        </div>

        <div class="p-6" v-if="licenseInfo">
          <!-- License Status & MAC -->
          <div class="grid md:grid-cols-2 gap-6">
            <div class="space-y-4">
              <!-- Status -->
              <div class="flex items-center justify-between py-2 border-b border-border">
                <span class="text-sm text-muted-foreground">Status</span>
                <span
                  :class="[
                    'inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium border',
                    getStatusStyles(licenseInfo.licenseStatus)
                  ]"
                >
                  <component :is="getStatusIcon(licenseInfo.licenseStatus)" class="h-3 w-3" />
                  {{ getStatusLabel(licenseInfo.licenseStatus) }}
                </span>
              </div>

              <!-- Management MAC -->
              <div class="flex items-center justify-between py-2 border-b border-border">
                <span class="text-sm text-muted-foreground">Management MAC</span>
                <div class="flex items-center gap-2">
                  <span class="font-mono text-sm">{{ licenseInfo.mgmtMac }}</span>
                  <button
                    v-if="licenseInfo.mgmtMac"
                    @click="copyToClipboard(licenseInfo.mgmtMac)"
                    class="p-1 rounded hover:bg-muted text-muted-foreground hover:text-foreground transition-colors"
                    :title="copySuccess ? 'Copied!' : 'Copy to clipboard'"
                  >
                    <CheckCircle v-if="copySuccess" class="h-4 w-4 text-green-500" />
                    <Copy v-else class="h-4 w-4" />
                  </button>
                </div>
              </div>

              <!-- Pro License Details -->
              <template v-if="isProvisioned && licenseInfo.licenseKey">
                <div class="flex items-center justify-between py-2 border-b border-border">
                  <span class="text-sm text-muted-foreground">License ID</span>
                  <span class="text-sm font-medium">{{ licenseInfo.licenseKey.id }}</span>
                </div>

                <div class="flex items-center justify-between py-2 border-b border-border">
                  <span class="text-sm text-muted-foreground">Type</span>
                  <span class="text-sm font-medium">{{ licenseInfo.licenseKey.name }}</span>
                </div>

                <div class="flex items-center justify-between py-2 border-b border-border">
                  <span class="text-sm text-muted-foreground">Licensee</span>
                  <span class="text-sm font-medium">{{ licenseInfo.licenseKey.licensee }}</span>
                </div>

                <div class="flex items-center justify-between py-2 border-b border-border">
                  <span class="text-sm text-muted-foreground">Effective</span>
                  <span class="text-sm font-medium">{{ formatDateOnly(licenseInfo.licenseKey.effective) }}</span>
                </div>

                <div class="flex items-center justify-between py-2 border-b border-border">
                  <span class="text-sm text-muted-foreground">Expiration</span>
                  <span class="text-sm font-medium">{{ formatDateOnly(licenseInfo.licenseKey.expiration) }}</span>
                </div>
              </template>
            </div>

            <!-- Right Column - Limits & Features (Pro only) -->
            <div class="space-y-4" v-if="isProvisioned && licenseInfo.licenseKey">
              <div class="flex items-center justify-between py-2 border-b border-border">
                <span class="text-sm text-muted-foreground">User Limit</span>
                <span class="text-sm font-medium">{{ formatLimit(licenseInfo.licenseKey.users) }}</span>
              </div>

              <div class="flex items-center justify-between py-2 border-b border-border">
                <span class="text-sm text-muted-foreground">Pinned MAC</span>
                <span class="text-sm font-medium">{{ licenseInfo.licenseKey.mgmtMac || 'Unlocked' }}</span>
              </div>

              <div class="flex items-center justify-between py-2 border-b border-border">
                <span class="text-sm text-muted-foreground">Node Limit</span>
                <span class="text-sm font-medium">{{ formatLimit(licenseInfo.licenseKey.nodes) }}</span>
              </div>

              <div class="flex items-center justify-between py-2 border-b border-border">
                <span class="text-sm text-muted-foreground">Subgrid Limit</span>
                <span class="text-sm font-medium">{{ licenseInfo.licenseKey.subgrids }}</span>
              </div>

              <div class="flex items-center justify-between py-2 border-b border-border">
                <span class="text-sm text-muted-foreground">SOC URL</span>
                <span class="text-sm font-medium">{{ licenseInfo.licenseKey.socUrl || 'Unlocked' }}</span>
              </div>

              <div class="flex items-center justify-between py-2 border-b border-border">
                <span class="text-sm text-muted-foreground">Data URL</span>
                <span class="text-sm font-medium">{{ licenseInfo.licenseKey.dataUrl || 'Unlocked' }}</span>
              </div>

              <div class="flex items-start justify-between py-2 border-b border-border">
                <span class="text-sm text-muted-foreground">Features</span>
                <div class="flex flex-wrap gap-1 justify-end max-w-xs" v-if="licenseInfo.licenseKey.features?.length">
                  <span
                    v-for="feature in licenseInfo.licenseKey.features"
                    :key="feature"
                    class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-primary/10 text-primary border border-primary/20"
                  >
                    {{ getFeatureName(feature) }}
                  </span>
                </div>
                <span v-else class="text-sm font-medium">All</span>
              </div>
            </div>
          </div>

          <!-- Community License Promo -->
          <div
            v-if="!isProvisioned"
            class="mt-6 p-6 rounded-lg bg-gradient-to-br from-primary/5 to-primary/10 border border-primary/20"
          >
            <h3 class="text-lg font-semibold mb-3">You're missing out on some Pro features!</h3>
            <ul class="grid md:grid-cols-2 gap-x-8 gap-y-2 text-sm mb-4">
              <li class="flex items-center gap-2">
                <CheckCircle class="h-4 w-4 text-primary" />
                Onion AI
              </li>
              <li class="flex items-center gap-2">
                <CheckCircle class="h-4 w-4 text-primary" />
                OpenID Connect 3rd-party authentication
              </li>
              <li class="flex items-center gap-2">
                <CheckCircle class="h-4 w-4 text-primary" />
                Disk encryption
              </li>
              <li class="flex items-center gap-2">
                <CheckCircle class="h-4 w-4 text-primary" />
                FIPS OS compliance
              </li>
              <li class="flex items-center gap-2">
                <CheckCircle class="h-4 w-4 text-primary" />
                STIG OS compliance
              </li>
              <li class="flex items-center gap-2">
                <CheckCircle class="h-4 w-4 text-primary" />
                External notifications
              </li>
              <li class="flex items-center gap-2">
                <CheckCircle class="h-4 w-4 text-primary" />
                Time tracking inside of Cases
              </li>
              <li class="flex items-center gap-2">
                <CheckCircle class="h-4 w-4 text-primary" />
                Guaranteed Message Delivery
              </li>
              <li class="flex items-center gap-2">
                <CheckCircle class="h-4 w-4 text-primary" />
                External API
              </li>
              <li class="flex items-center gap-2">
                <CheckCircle class="h-4 w-4 text-primary" />
                Active Query Management
              </li>
              <li class="flex items-center gap-2">
                <CheckCircle class="h-4 w-4 text-primary" />
                Reporting & CSV Exports
              </li>
              <li class="flex items-center gap-2">
                <CheckCircle class="h-4 w-4 text-primary" />
                AI/LLM MCP Server
              </li>
              <li class="flex items-center gap-2">
                <CheckCircle class="h-4 w-4 text-primary" />
                Manager of Managers*
              </li>
              <li class="flex items-center gap-2">
                <CheckCircle class="h-4 w-4 text-primary" />
                Splunk App&dagger;
              </li>
              <li class="flex items-center gap-2">
                <CheckCircle class="h-4 w-4 text-primary" />
                Hardware Virtualization&Dagger;
              </li>
            </ul>
            <p class="text-sm mb-4">
              To learn more about these Pro features, please visit our website:
              <a
                href="https://securityonion.com/pro"
                target="_blank"
                rel="noopener noreferrer"
                class="text-primary hover:underline inline-flex items-center gap-1"
              >
                https://securityonion.com/pro
                <ExternalLink class="h-3 w-3" />
              </a>
            </p>
            <p class="text-xs text-muted-foreground">
              * Additional licensing requirements may apply<br />
              &dagger; Security Onion Solutions does not provide support for this feature<br />
              &Dagger; Available on select server hardware
            </p>
          </div>
        </div>
      </div>
    </div>

    <!-- License Terms Tab -->
    <div v-else-if="activeTab === 'terms'" class="space-y-6">
      <div class="rounded-lg border border-border bg-card p-6 prose prose-sm dark:prose-invert max-w-none">
        <h2 class="text-xl font-semibold mt-0">Elastic License 2.0 (ELv2) Terms</h2>

        <h3>Acceptance</h3>
        <p>By using the software, you agree to all of the terms and conditions below.</p>

        <h3>Copyright License</h3>
        <p>
          The licensor grants you a non-exclusive, royalty-free, worldwide, non-sublicensable, non-transferable
          license to use, copy, distribute, make available, and prepare derivative works of the software,
          in each case subject to the limitations and conditions below.
        </p>

        <h3>Limitations</h3>
        <p>
          You may not provide the software to third parties as a hosted or managed service, where the service
          provides users with access to any substantial set of the features or functionality of the software.
        </p>
        <p>
          You may not move, change, disable, or circumvent the license key functionality in the software,
          and you may not remove or obscure any functionality in the software that is protected by the license key.
        </p>
        <p>
          You may not alter, remove, or obscure any licensing, copyright, or other notices of the licensor
          in the software. Any use of the licensor's trademarks is subject to applicable law.
        </p>

        <h3>Patents</h3>
        <p>
          The licensor grants you a license, under any patent claims the licensor can license, or becomes
          able to license, to make, have made, use, sell, offer for sale, import and have imported the software,
          in each case subject to the limitations and conditions in this license. This license does not cover
          any patent claims that you cause to be infringed by modifications or additions to the software.
          If you or your company make any written claim that the software infringes or contributes to
          infringement of any patent, your patent license for the software granted under these terms ends
          immediately. If your company makes such a claim, your patent license ends immediately for work
          on behalf of your company.
        </p>

        <h3>Notices</h3>
        <p>
          You must ensure that anyone who gets a copy of any part of the software from you also gets a copy
          of these terms.
        </p>
        <p>
          If you modify the software, you must include in any modified copies of the software prominent
          notices stating that you have modified the software.
        </p>

        <h3>No Other Rights</h3>
        <p>These terms do not imply any licenses other than those expressly granted in these terms.</p>

        <h3>Termination</h3>
        <p>
          If you use the software in violation of these terms, such use is not licensed, and your licenses
          will automatically terminate. If the licensor provides you with a notice of your violation, and
          you cease all violation of this license no later than 30 days after you receive that notice,
          your licenses will be reinstated retroactively. However, if you violate these terms after such
          reinstatement, any additional violation of these terms will cause your licenses to terminate
          automatically and permanently.
        </p>

        <h3>No Liability</h3>
        <p class="font-semibold italic">
          As far as the law allows, the software comes as is, without any warranty or condition, and the
          licensor will not be liable to you for any damages arising out of these terms or the use or
          nature of the software, under any kind of legal claim.
        </p>

        <h3>Definitions</h3>
        <p>
          The <strong>licensor</strong> is the entity offering these terms, and the <strong>software</strong>
          is the software the licensor makes available under these terms, including any portion of it.
        </p>
        <p>
          <strong>you</strong> refers to the individual or entity agreeing to these terms.
        </p>
        <p>
          <strong>your company</strong> is any legal entity, sole proprietorship, or other kind of organization
          that you work for, plus all organizations that have control over, are under the control of, or are
          under common control with that organization. <strong>control</strong> means ownership of substantially
          all the assets of an entity, or the power to direct its management and policies by vote, contract,
          or otherwise. Control can be direct or indirect.
        </p>
        <p>
          <strong>your licenses</strong> are all the licenses granted to you for the software under these terms.
        </p>
        <p>
          <strong>use</strong> means anything you do with the software requiring one of your licenses.
        </p>
        <p>
          <strong>trademark</strong> means trademarks, service marks, and similar rights.
        </p>
      </div>
    </div>

    <!-- Onion AI Registration Dialog -->
    <div v-if="showRegistrationDialog" class="fixed inset-0 z-50 bg-black/50 flex items-center justify-center p-4">
      <div class="bg-card text-card-foreground border border-border rounded-lg shadow-lg w-full max-w-4xl max-h-[90vh] overflow-y-auto">
        <div class="p-6 border-b border-border">
          <div class="flex items-center justify-between">
            <div>
              <h3 class="text-xl font-semibold flex items-center gap-2">
                <Bot class="h-6 w-6 text-primary" />
                Register with Onion AI
              </h3>
              <p class="text-sm text-muted-foreground mt-1">
                Choose a credit plan that fits your security analysis needs
              </p>
            </div>
            <button
              @click="showRegistrationDialog = false"
              class="p-2 rounded-md hover:bg-muted text-muted-foreground hover:text-foreground transition-colors"
            >
              <XCircle class="h-5 w-5" />
            </button>
          </div>
        </div>

        <div class="p-6">
          <!-- Credit Plans Grid -->
          <div class="grid md:grid-cols-3 gap-4 mb-6">
            <div
              v-for="plan in aiCreditPlans"
              :key="plan.id"
              @click="selectPlan(plan.id)"
              :class="[
                'relative rounded-lg border-2 p-6 cursor-pointer transition-all',
                selectedPlan === plan.id
                  ? 'border-primary bg-primary/5'
                  : 'border-border hover:border-primary/50'
              ]"
            >
              <!-- Popular Badge -->
              <div
                v-if="plan.popular"
                class="absolute -top-3 left-1/2 -translate-x-1/2 px-3 py-0.5 rounded-full text-xs font-medium bg-primary text-primary-foreground"
              >
                Most Popular
              </div>

              <!-- Plan Icon -->
              <div class="flex justify-center mb-4">
                <div
                  :class="[
                    'p-3 rounded-full',
                    plan.id === 'starter' ? 'bg-blue-500/10 text-blue-500' : '',
                    plan.id === 'professional' ? 'bg-primary/10 text-primary' : '',
                    plan.id === 'enterprise' ? 'bg-amber-500/10 text-amber-500' : ''
                  ]"
                >
                  <Zap v-if="plan.id === 'starter'" class="h-6 w-6" />
                  <Sparkles v-else-if="plan.id === 'professional'" class="h-6 w-6" />
                  <Crown v-else class="h-6 w-6" />
                </div>
              </div>

              <!-- Plan Name -->
              <h4 class="text-lg font-semibold text-center mb-2">{{ plan.name }}</h4>

              <!-- Price -->
              <div class="text-center mb-4">
                <span class="text-3xl font-bold">${{ plan.price }}</span>
                <span class="text-sm text-muted-foreground">/pack</span>
                <div class="text-xs text-muted-foreground mt-1">
                  ${{ plan.pricePerCredit.toFixed(2) }} per credit
                </div>
              </div>

              <!-- Credits -->
              <div class="text-center mb-4 py-2 bg-muted/50 rounded-md">
                <span class="text-2xl font-bold text-primary">{{ plan.credits.toLocaleString() }}</span>
                <span class="text-sm text-muted-foreground ml-1">credits</span>
              </div>

              <!-- Features -->
              <ul class="space-y-2">
                <li
                  v-for="feature in plan.features"
                  :key="feature"
                  class="flex items-start gap-2 text-sm"
                >
                  <Check class="h-4 w-4 text-green-500 mt-0.5 flex-shrink-0" />
                  <span>{{ feature }}</span>
                </li>
              </ul>

              <!-- Selection Indicator -->
              <div
                v-if="selectedPlan === plan.id"
                class="absolute top-3 right-3"
              >
                <CheckCircle class="h-5 w-5 text-primary" />
              </div>
            </div>
          </div>

          <!-- Info Note -->
          <div class="p-4 rounded-lg bg-muted/50 text-sm text-muted-foreground mb-6">
            <p class="flex items-start gap-2">
              <Info class="h-4 w-4 mt-0.5 flex-shrink-0" />
              <span>
                AI credits are used for threat analysis, natural language queries, and automated investigations.
                Credits do not expire and can be used at your own pace. Additional credits can be purchased at any time.
              </span>
            </p>
          </div>

          <!-- Actions -->
          <div class="flex justify-end gap-3">
            <button
              @click="showRegistrationDialog = false"
              class="inline-flex items-center justify-center rounded-md text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring border border-input bg-transparent shadow-sm hover:bg-accent hover:text-accent-foreground h-10 px-6"
            >
              Cancel
            </button>
            <button
              @click="handleRegister"
              :disabled="!selectedPlan"
              :class="[
                'inline-flex items-center justify-center gap-2 rounded-md text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring h-10 px-6',
                selectedPlan
                  ? 'bg-primary text-primary-foreground shadow hover:bg-primary/90'
                  : 'bg-muted text-muted-foreground cursor-not-allowed'
              ]"
            >
              <Bot class="h-4 w-4" />
              Continue to Registration
            </button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
