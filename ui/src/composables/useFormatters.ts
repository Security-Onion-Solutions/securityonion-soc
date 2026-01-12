/**
 * Shared formatting utilities for dates, times, and durations.
 * Use this composable instead of reimplementing formatting logic in each module.
 */

/**
 * Format a date string to localized date/time.
 * Handles null values and Go's zero time "0001-01-01".
 */
export function formatDate(dateStr: string | null | undefined): string {
    if (!dateStr || dateStr.startsWith("0001")) return "-"
    return new Date(dateStr).toLocaleString()
}

/**
 * Format a date string to localized date only (no time).
 */
export function formatDateOnly(dateStr: string | null | undefined): string {
    if (!dateStr || dateStr.startsWith("0001")) return "-"
    return new Date(dateStr).toLocaleDateString()
}

/**
 * Format seconds into human-readable uptime string.
 * Examples: "5d 2h", "3h 45m", "12m"
 */
export function formatUptime(seconds: number | null | undefined): string {
    if (!seconds) return '0m'
    const d = Math.floor(seconds / (3600 * 24))
    const h = Math.floor(seconds % (3600 * 24) / 3600)
    const m = Math.floor(seconds % 3600 / 60)

    if (d > 0) return `${d}d ${h}h`
    if (h > 0) return `${h}h ${m}m`
    return `${m}m`
}

/**
 * Format a date into relative time ago string.
 * Examples: "Just now", "5 minutes", "3 hours", "2 days"
 */
export function formatRelativeTime(dateStr: string | null | undefined): string {
    if (!dateStr) return 'N/A'
    const seconds = Math.floor((Date.now() - new Date(dateStr).getTime()) / 1000)
    if (seconds < 60) return 'Just now'

    const d = Math.floor(seconds / (3600 * 24))
    const h = Math.floor(seconds % (3600 * 24) / 3600)
    const m = Math.floor(seconds % 3600 / 60)

    if (d > 365) return `${Math.floor(d / 365)} years`
    if (d > 30) return `${Math.floor(d / 30)} months`
    if (d > 0) return `${d} days`
    if (h > 0) return `${h} hours`
    return `${m} minutes`
}

/**
 * Format a Date object to the format used by the events API.
 * Format: "YYYY/MM/DD h:mm:ss AM/PM" (12-hour format, unpadded hours)
 * Matches Go reference time: "2006/01/02 3:04:05 PM"
 */
export function formatDateForApi(date: Date): string {
    const pad = (n: number) => n.toString().padStart(2, '0')
    const year = date.getFullYear()
    const month = pad(date.getMonth() + 1)
    const day = pad(date.getDate())
    let hours = date.getHours()
    const ampm = hours >= 12 ? 'PM' : 'AM'
    hours = hours % 12
    hours = hours ? hours : 12
    const minutes = pad(date.getMinutes())
    const seconds = pad(date.getSeconds())
    return `${year}/${month}/${day} ${hours}:${minutes}:${seconds} ${ampm}`
}

/**
 * Format a date range string for API queries.
 * Returns: "startDate - endDate" in API format
 */
export function formatDateRangeForApi(start: Date, end: Date): string {
    return `${formatDateForApi(start)} - ${formatDateForApi(end)}`
}

/**
 * Composable wrapper for all formatters.
 * Usage: const { formatDate, formatUptime } = useFormatters()
 */
export function useFormatters() {
    return {
        formatDate,
        formatDateOnly,
        formatUptime,
        formatRelativeTime,
        formatDateForApi,
        formatDateRangeForApi
    }
}
