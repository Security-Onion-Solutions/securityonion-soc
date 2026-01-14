// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

import { ref } from 'vue'

// Regex patterns for artifact type detection (from classic interface)
const ipRegex = /^[0-9a-fA-F:]*([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F:]*$|^(\d{1,3}\.){3}\d{1,3}$/
const fqdnRegex = /(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$)/
const domainRegex = /^(xn\-\-)?([a-z0-9\-]{1,61}|[a-z0-9\-]{1,30})\.[a-z]{2,}$/
const urlRegex = /^[a-z]+:\/\//
const filenameRegex = /(\/)?[\w,\s-]+\.[A-Za-z]{3}$/
const uriPathRegex = /^\/[\w,\s-]/
const hashRegex = /^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$|^[0-9a-fA-F]{128}$/

export interface Artifact {
    id: string
    caseId: string
    groupType: 'attachments' | 'evidence'
    groupId?: string
    artifactType: string
    value: string
    description?: string
    tlp?: string
    tags?: string[]
    ioc?: boolean
    protected?: boolean
    // File-related fields (read-only, set by server)
    mimeType?: string
    streamLen?: number
    streamLength?: number // API returns this
    streamId?: string
    md5?: string
    sha1?: string
    sha256?: string
    // Audit fields
    createTime?: string
    updateTime?: string
    userId?: string
}

export interface ArtifactCreateData {
    caseId: string
    groupType: 'attachments' | 'evidence'
    artifactType: string
    value?: string
    description?: string
    tlp?: string
    tags?: string[]
    ioc?: boolean
    protected?: boolean
}

export interface AnalyzeJob {
    id: string
    kind: string
    status: string
    createTime: string
    updateTime?: string
    userId?: string
    owner?: string
    nodeId?: string
    filter?: {
        parameters?: {
            artifact?: Artifact
        }
    }
    results?: AnalyzerResult[]
}

export interface AnalyzerResult {
    id: string
    summary: string
    data?: {
        status?: 'info' | 'ok' | 'caution' | 'threat'
        [key: string]: any
    }
}

// Global CSRF token cache (shared with useApi)
let srvToken: string | null = null
let tokenPromise: Promise<string | null> | null = null

async function ensureSrvToken(): Promise<string | null> {
    if (srvToken) {
        return srvToken
    }

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

export function useArtifacts() {
    const loading = ref(false)
    const error = ref<string | null>(null)

    // Detect artifact type from value
    function detectArtifactType(value: string): string | null {
        if (!value) return null
        const trimmed = value.trim()

        if (ipRegex.test(trimmed)) return 'ip'
        if (domainRegex.test(trimmed)) return 'domain'
        if (fqdnRegex.test(trimmed)) return 'fqdn'
        if (urlRegex.test(trimmed)) return 'url'
        if (filenameRegex.test(trimmed)) return 'filename'
        if (uriPathRegex.test(trimmed)) return 'uri_path'
        if (hashRegex.test(trimmed)) return 'hash'

        return null
    }

    // Fetch artifacts for a case
    async function getArtifacts(caseId: string, groupType: 'attachments' | 'evidence'): Promise<Artifact[]> {
        loading.value = true
        error.value = null

        try {
            const response = await fetch(`/api/case/artifacts/${groupType}?id=${caseId}`)
            if (!response.ok) {
                throw new Error(`Failed to fetch ${groupType}`)
            }
            return await response.json()
        } catch (e: any) {
            error.value = e.message || `Failed to fetch ${groupType}`
            console.error('Error fetching artifacts:', e)
            return []
        } finally {
            loading.value = false
        }
    }

    // Create artifact (non-file)
    async function createArtifact(data: ArtifactCreateData): Promise<Artifact | null> {
        loading.value = true
        error.value = null

        try {
            const token = await ensureSrvToken()
            const headers: Record<string, string> = {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
            }
            if (token) {
                headers['X-Srv-Token'] = token
            }

            const response = await fetch('/api/case/artifacts', {
                method: 'POST',
                headers,
                body: JSON.stringify(data),
            })

            if (!response.ok) {
                const errorText = await response.text()
                throw new Error(errorText || 'Failed to create artifact')
            }

            return await response.json()
        } catch (e: any) {
            error.value = e.message || 'Failed to create artifact'
            console.error('Error creating artifact:', e)
            throw e
        } finally {
            loading.value = false
        }
    }

    // Create file artifact (multipart form)
    async function createFileArtifact(data: ArtifactCreateData, file: File): Promise<Artifact | null> {
        loading.value = true
        error.value = null

        try {
            const token = await ensureSrvToken()
            const formData = new FormData()
            formData.append('json', JSON.stringify(data))
            formData.append('attachment', file)

            const headers: Record<string, string> = {}
            if (token) {
                headers['X-Srv-Token'] = token
            }

            const response = await fetch('/api/case/artifacts', {
                method: 'POST',
                headers,
                body: formData,
            })

            if (!response.ok) {
                const errorText = await response.text()
                throw new Error(errorText || 'Failed to upload file')
            }

            return await response.json()
        } catch (e: any) {
            error.value = e.message || 'Failed to upload file'
            console.error('Error uploading file:', e)
            throw e
        } finally {
            loading.value = false
        }
    }

    // Update artifact metadata
    async function updateArtifact(artifact: Partial<Artifact> & { id: string }): Promise<Artifact | null> {
        loading.value = true
        error.value = null

        try {
            const token = await ensureSrvToken()
            const headers: Record<string, string> = {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
            }
            if (token) {
                headers['X-Srv-Token'] = token
            }

            const response = await fetch('/api/case/artifacts', {
                method: 'PUT',
                headers,
                body: JSON.stringify(artifact),
            })

            if (!response.ok) {
                const errorText = await response.text()
                throw new Error(errorText || 'Failed to update artifact')
            }

            return await response.json()
        } catch (e: any) {
            error.value = e.message || 'Failed to update artifact'
            console.error('Error updating artifact:', e)
            throw e
        } finally {
            loading.value = false
        }
    }

    // Delete artifact
    async function deleteArtifact(artifactId: string): Promise<void> {
        loading.value = true
        error.value = null

        try {
            const token = await ensureSrvToken()
            const headers: Record<string, string> = {}
            if (token) {
                headers['X-Srv-Token'] = token
            }

            const response = await fetch(`/api/case/artifacts?id=${artifactId}`, {
                method: 'DELETE',
                headers,
            })

            if (!response.ok) {
                const errorText = await response.text()
                throw new Error(errorText || 'Failed to delete artifact')
            }
        } catch (e: any) {
            error.value = e.message || 'Failed to delete artifact'
            console.error('Error deleting artifact:', e)
            throw e
        } finally {
            loading.value = false
        }
    }

    // Generate download URL for artifact stream
    function getDownloadUrl(artifactId: string): string {
        return `/api/case/artifactstream?id=${artifactId}`
    }

    // Submit artifact for analysis
    async function analyzeArtifact(artifact: Artifact, analyzerNodeId?: string): Promise<AnalyzeJob | null> {
        loading.value = true
        error.value = null

        try {
            const token = await ensureSrvToken()
            const headers: Record<string, string> = {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
            }
            if (token) {
                headers['X-Srv-Token'] = token
            }

            const response = await fetch('/api/job/', {
                method: 'POST',
                headers,
                body: JSON.stringify({
                    kind: 'analyze',
                    nodeId: analyzerNodeId,
                    filter: {
                        parameters: {
                            artifact: artifact
                        }
                    }
                }),
            })

            if (!response.ok) {
                const errorText = await response.text()
                throw new Error(errorText || 'Failed to submit analysis job')
            }

            return await response.json()
        } catch (e: any) {
            error.value = e.message || 'Failed to submit analysis job'
            console.error('Error submitting analysis:', e)
            throw e
        } finally {
            loading.value = false
        }
    }

    // Get analyze jobs for an artifact
    async function getAnalyzeJobs(artifactId: string): Promise<AnalyzeJob[]> {
        try {
            // Build query params matching the classic interface approach
            const params = new URLSearchParams({
                kind: 'analyze',
                'parameters.artifact.id': artifactId,
            })

            const response = await fetch(`/api/jobs/?${params.toString()}`)
            if (!response.ok) {
                if (response.status === 404) {
                    return []
                }
                throw new Error('Failed to fetch analyze jobs')
            }

            const jobs: AnalyzeJob[] = await response.json()
            return jobs
        } catch (e: any) {
            console.error('Error fetching analyze jobs:', e)
            return []
        }
    }

    // Build hunt query for a value
    function buildHuntQuery(value: string): string {
        const escaped = value.replace(/"/g, '\\"')
        return `"${escaped}" | groupby event.module event.dataset`
    }

    // Copy text to clipboard
    async function copyToClipboard(text: string): Promise<boolean> {
        try {
            await navigator.clipboard.writeText(text)
            return true
        } catch (e) {
            console.error('Failed to copy to clipboard:', e)
            return false
        }
    }

    // Format file size
    function formatFileSize(bytes: number | undefined): string {
        if (!bytes) return '0 B'
        const units = ['B', 'KB', 'MB', 'GB']
        let size = bytes
        let unitIndex = 0
        while (size >= 1024 && unitIndex < units.length - 1) {
            size /= 1024
            unitIndex++
        }
        return `${size.toFixed(unitIndex > 0 ? 1 : 0)} ${units[unitIndex]}`
    }

    // Get analyzer result decoration
    function getAnalyzerDecoration(result: AnalyzerResult): { color: string; icon: string; severity: number } {
        const status = result.data?.status
        switch (status) {
            case 'info':
                return { color: 'text-blue-500', icon: 'info', severity: 10 }
            case 'ok':
                return { color: 'text-green-500', icon: 'check-circle', severity: 0 }
            case 'caution':
                return { color: 'text-amber-500', icon: 'alert-triangle', severity: 80 }
            case 'threat':
                return { color: 'text-red-500', icon: 'alert-circle', severity: 100 }
            default:
                return { color: 'text-muted-foreground', icon: 'help-circle', severity: 50 }
        }
    }

    return {
        loading,
        error,
        detectArtifactType,
        getArtifacts,
        createArtifact,
        createFileArtifact,
        updateArtifact,
        deleteArtifact,
        getDownloadUrl,
        analyzeArtifact,
        getAnalyzeJobs,
        buildHuntQuery,
        copyToClipboard,
        formatFileSize,
        getAnalyzerDecoration,
    }
}
