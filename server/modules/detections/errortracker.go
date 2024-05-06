package detections

import (
	"container/ring"

	"github.com/hashicorp/go-multierror"
)

type ErrorTrackerError struct {
	err *multierror.Error
}

func (e ErrorTrackerError) Error() string {
	return e.err.Error()
}

type ErrorTracker struct {
	max          int
	count        int
	recentlySeen *ring.Ring
	ringSize     int
}

func NewErrorTracker(count int) *ErrorTracker {
	ringSize := min(count, 10)

	return &ErrorTracker{
		max:          count,
		recentlySeen: ring.New(ringSize),
		ringSize:     ringSize,
	}
}

func (et *ErrorTracker) Reset() {
	et.count = 0
}

func (et *ErrorTracker) AddError(err error) error {
	if err == nil {
		et.Reset()

		return nil
	}

	et.count++

	// Note: not thread safe
	et.recentlySeen.Value = err
	et.recentlySeen = et.recentlySeen.Next()

	if et.count >= et.max {
		return ErrorTrackerError{err: multierror.Append(nil, et.GetErrors()...)}
	}

	return nil
}

func (et *ErrorTracker) GetErrors() []error {
	errors := make([]error, 0, et.ringSize)
	et.recentlySeen.Do(func(v interface{}) {
		if v != nil {
			errors = append(errors, v.(error))
		}
	})

	return errors
}
