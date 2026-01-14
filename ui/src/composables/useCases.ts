// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

import { ref } from 'vue'
import { useApi } from './useApi'

export interface CaseCreateData {
  title: string
  description?: string
  severity?: string
  priority?: number
  assigneeId?: string
  tlp?: string
  pap?: string
  category?: string
  tags?: string[]
}

export interface CaseResponse {
  id: string
  title: string
  description: string
  severity: string
  priority: number
  status: string
  assigneeId: string
  tlp: string
  pap: string
  category: string
  tags: string[]
  createTime: string
  updateTime: string
  userId: string
}

export function useCases() {
  const { post, loading, error } = useApi()
  const creating = ref(false)

  async function createCase(data: CaseCreateData): Promise<CaseResponse | null> {
    creating.value = true
    try {
      const result = await post<CaseResponse>('/api/case/', data)
      return result
    } finally {
      creating.value = false
    }
  }

  return {
    createCase,
    creating,
    loading,
    error
  }
}
