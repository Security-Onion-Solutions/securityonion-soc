/**
 * Shared status and severity styling utilities.
 * Use this composable instead of reimplementing color/style logic in each module.
 */

/**
 * Get Tailwind classes for severity badges (critical, high, medium, low).
 * Returns classes for text color, background, and border.
 */
export function getSeverityStyles(severity: string | null | undefined): string {
    const s = severity?.toLowerCase()
    if (s === 'critical' || s === 'high') return 'text-red-500 bg-red-500/10 border-red-500/20'
    if (s === 'medium') return 'text-amber-500 bg-amber-500/10 border-amber-500/20'
    if (s === 'low') return 'text-blue-500 bg-blue-500/10 border-blue-500/20'
    return 'text-muted-foreground bg-muted border-border'
}

/**
 * Get Tailwind classes for case/item status badges (open, closed, etc.).
 * Returns classes for text color, background, and border.
 */
export function getStatusStyles(status: string | null | undefined): string {
    switch (status?.toLowerCase()) {
        case 'open':
            return 'bg-green-500/10 text-green-500 border-green-500/20'
        case 'closed':
            return 'bg-slate-500/10 text-muted-foreground border-border'
        default:
            return 'bg-blue-500/10 text-blue-500 border-blue-500/20'
    }
}

/**
 * Get Tailwind classes for job status badges.
 * Handles: Completed (1), Pending (0), Incomplete (2), Deleted (3).
 */
export function getJobStatusStyles(status: number): string {
    switch (status) {
        case 1: // Completed
            return 'text-green-500 bg-green-500/10 border-green-500/20'
        case 0: // Pending
            return 'text-blue-500 bg-blue-500/10 border-blue-500/20'
        case 2: // Incomplete
            return 'text-amber-500 bg-amber-500/10 border-amber-500/20'
        case 3: // Deleted
            return 'text-red-500 bg-red-500/10 border-red-500/20'
        default:
            return 'text-muted-foreground bg-muted border-border'
    }
}

/**
 * Get Tailwind text color class for node/system status (ok, fault, pending, restart).
 */
export function getNodeStatusColor(status: string | null | undefined): string {
    switch (status?.toLowerCase()) {
        case 'ok':
            return 'text-green-500'
        case 'fault':
            return 'text-red-500'
        case 'pending':
            return 'text-amber-500'
        case 'restart':
            return 'text-blue-500'
        default:
            return 'text-gray-500'
    }
}

/**
 * Get Tailwind text color class based on usage percentage threshold.
 * >= 90%: red, >= 75%: amber, else: default
 */
export function getUsageColor(percent: number): string {
    if (percent >= 90) return 'text-red-500'
    if (percent >= 75) return 'text-amber-500'
    return 'text-foreground'
}

/**
 * Get Tailwind background color class for progress bars based on percentage.
 * >= 90%: red, >= 75%: amber, else: primary
 */
export function getProgressColor(percent: number): string {
    if (percent >= 90) return 'bg-red-500'
    if (percent >= 75) return 'bg-amber-500'
    return 'bg-primary'
}

/**
 * Composable wrapper for all status styling functions.
 * Usage: const { getSeverityStyles, getUsageColor } = useStatusStyles()
 */
export function useStatusStyles() {
    return {
        getSeverityStyles,
        getStatusStyles,
        getJobStatusStyles,
        getNodeStatusColor,
        getUsageColor,
        getProgressColor
    }
}
