import { ref, computed, type Ref } from 'vue'

/**
 * Shared table sorting and filtering utilities.
 * Use this composable for tables that need sorting and search functionality.
 */

export type SortDirection = 'asc' | 'desc' | null

export interface SortState {
    column: string | null
    direction: SortDirection
}

/**
 * Generic table sorting and filtering composable.
 *
 * @param items - Ref to the array of items to sort/filter
 * @param defaultSort - Optional default sort configuration
 *
 * Usage:
 * ```ts
 * const {
 *   sortState, searchQuery, sortedAndFilteredItems,
 *   toggleSort, getSortIcon
 * } = useTableSort(nodes, { column: 'id', direction: 'asc' })
 * ```
 */
export function useTableSort<T extends Record<string, any>>(
    items: Ref<T[]>,
    defaultSort: SortState = { column: null, direction: null }
) {
    const sortState = ref<SortState>({ ...defaultSort })
    const searchQuery = ref('')

    /**
     * Toggle sort for a column. Cycles through: asc -> desc -> none
     */
    const toggleSort = (column: string) => {
        if (sortState.value.column !== column) {
            sortState.value = { column, direction: 'asc' }
        } else if (sortState.value.direction === 'asc') {
            sortState.value = { column, direction: 'desc' }
        } else {
            sortState.value = { column: null, direction: null }
        }
    }

    /**
     * Set sort directly (useful for programmatic sorting)
     */
    const setSort = (column: string | null, direction: SortDirection = 'asc') => {
        sortState.value = { column, direction }
    }

    /**
     * Get the sort indicator for a column ('asc', 'desc', or null)
     */
    const getSortDirection = (column: string): SortDirection => {
        return sortState.value.column === column ? sortState.value.direction : null
    }

    /**
     * Check if a column is currently sorted
     */
    const isSorted = (column: string): boolean => {
        return sortState.value.column === column && sortState.value.direction !== null
    }

    /**
     * Compare function for sorting
     */
    const compareValues = (a: any, b: any, direction: SortDirection): number => {
        if (a === b) return 0
        if (a === null || a === undefined) return 1
        if (b === null || b === undefined) return -1

        let comparison = 0
        if (typeof a === 'string' && typeof b === 'string') {
            comparison = a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' })
        } else if (typeof a === 'number' && typeof b === 'number') {
            comparison = a - b
        } else {
            comparison = String(a).localeCompare(String(b))
        }

        return direction === 'desc' ? -comparison : comparison
    }

    /**
     * Filter items by search query against specified fields
     */
    const filterItems = (items: T[], query: string, searchFields: (keyof T)[]): T[] => {
        if (!query.trim()) return items
        const lowerQuery = query.toLowerCase().trim()
        return items.filter(item =>
            searchFields.some(field => {
                const value = item[field]
                return value && String(value).toLowerCase().includes(lowerQuery)
            })
        )
    }

    /**
     * Sort items by current sort state
     */
    const sortItems = (items: T[]): T[] => {
        if (!sortState.value.column || !sortState.value.direction) {
            return items
        }
        const column = sortState.value.column as keyof T
        const direction = sortState.value.direction
        return [...items].sort((a, b) => compareValues(a[column], b[column], direction))
    }

    /**
     * Create a computed property for filtered and sorted items
     *
     * @param searchFields - Fields to search in when filtering
     */
    const createFilteredSortedItems = (searchFields: (keyof T)[]) => {
        return computed(() => {
            let result = items.value
            result = filterItems(result, searchQuery.value, searchFields)
            result = sortItems(result)
            return result
        })
    }

    return {
        sortState,
        searchQuery,
        toggleSort,
        setSort,
        getSortDirection,
        isSorted,
        filterItems,
        sortItems,
        createFilteredSortedItems
    }
}
