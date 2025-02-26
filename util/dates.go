package util

import "time"

func Overlap(start1, end1, start2, end2 time.Time) bool {
	if end1.Before(start1) || end2.Before(start2) {
		return false
	}

	return !(start1.After(end2) || start2.After(end1))
}
