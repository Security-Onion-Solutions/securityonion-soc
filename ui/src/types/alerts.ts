// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

// Re-export types from hunt that we need
export type { EventRecord, EventSearchResponse, ChartMetric } from './hunt'

// =============================================================================
// Alert Group Types
// =============================================================================

export interface AlertGroup {
    ruleName: string
    ruleId: string           // URL-safe encoded name
    count: number
    severity: string         // Highest severity in group
    module: string           // Event module (suricata, sigma, etc.)
}

// =============================================================================
// Source/Destination Pair Types
// =============================================================================

export interface SourceDestPair {
    sourceIp: string
    destinationIp: string
    count: number
}

// =============================================================================
// Filter Types
// =============================================================================

export type AcknowledgedFilter = 'all' | 'acknowledged' | 'unacknowledged'

export interface AlertFilters {
    search: string
    acknowledged: AcknowledgedFilter
    severity: string[]
}

// =============================================================================
// State Types
// =============================================================================

export interface AlertsState {
    groups: AlertGroup[]
    totalAlerts: number
    loading: boolean
    error: string | null
    hasMore: boolean
}

export interface AlertGroupDetailState {
    ruleName: string
    pairs: SourceDestPair[]
    alerts: import('./hunt').EventRecord[]
    selectedPair: SourceDestPair | null
    loading: boolean
    loadingMore: boolean
    error: string | null
    hasMorePairs: boolean
    hasMoreAlerts: boolean
}
