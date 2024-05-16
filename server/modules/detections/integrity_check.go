package detections

import (
	"fmt"
	"sync"
	"time"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
)

var ErrIntCheckerStopped = fmt.Errorf("integrity checker has stopped running")
var ErrIntCheckFailed = fmt.Errorf("integrity check failed; discrepancies found")

type IntegrityChecked interface {
	IntegrityCheck() error
	InterruptSync(forceFull bool, notify bool)
	IsRunning() bool
}

type IntegrityCheckerData struct {
	Thread           *sync.WaitGroup
	IsRunning        bool
	FrequencySeconds int
	Interrupt        chan bool
}

func IntegrityChecker(engName model.EngineName, eng IntegrityChecked, data *IntegrityCheckerData, intCheckFailure *bool) {
	data.Thread.Add(1)
	defer func() {
		data.Thread.Done()
		data.IsRunning = false
	}()

	logger := log.WithField("engineName", engName)
	failCount := uint(0)

	for {
		if !eng.IsRunning() {
			logger.Info("integrity checker stopping")
			return
		}

		timer := time.NewTimer(time.Second * time.Duration(data.FrequencySeconds))
		select {
		case <-timer.C:
		case <-data.Interrupt:
		}

		if !data.IsRunning {
			continue
		}

		err := eng.IntegrityCheck()
		if err != nil {
			if err != ErrIntCheckerStopped {
				failCount++

				// we just had a bad integrity check, we should:
				// 1) Run a force sync to try to fix the issue
				// 2) Rerun an integrity check (happens after engine re-enables integrity checker)
				// 2a) If the integrity check fails again, we should alert the user

				switch failCount {
				case 1:
					// 1
					logger.WithError(err).Error("integrity check first failure, running force sync")

					eng.InterruptSync(true, false)
				default:
					// 2a
					*intCheckFailure = true
					logger.WithError(err).Error("integrity check repeat failure, alerting user")
					failCount = 0
				}
			} else {
				logger.Info("integrity check stopped by something else")
			}
		} else {
			*intCheckFailure = false
			failCount = 0
		}
	}
}

func DiffLists[T comparable](A []T, B []T) (onlyA []T, onlyB []T, both []T) {
	onlyA = []T{}
	onlyB = []T{}
	both = []T{}

	aMap := make(map[T]struct{})
	for _, a := range A {
		aMap[a] = struct{}{}
	}

	for _, b := range B {
		if _, ok := aMap[b]; ok {
			both = append(both, b)
			delete(aMap, b)
		} else {
			onlyB = append(onlyB, b)
		}
	}

	for a := range aMap {
		onlyA = append(onlyA, a)
	}

	return
}
