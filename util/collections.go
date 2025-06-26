package util

func TruncateMap[K comparable, V any](originalMap map[K]V, limit uint) map[K]V {
	if uint(len(originalMap)) <= limit {
		return originalMap // Return the original map if it's already within the limit
	}

	truncatedMap := make(map[K]V, limit)
	count := uint(0)
	for key, value := range originalMap {
		if count >= limit {
			break
		}
		truncatedMap[key] = value
		count++
	}
	return truncatedMap
}

func TruncateList[T any](originalList []T, limit uint) []T {
	if uint(len(originalList)) <= limit {
		return originalList // Return the original list if it's already within the limit
	}

	return originalList[:limit]
}
