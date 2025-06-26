//go:build debug

package web

import (
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"time"

	"github.com/apex/log"
)

const (
	rootDir = "/tmp"
)

func GenPerformanceMetrics(name string, mem bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nowMicro := time.Now().UnixMicro()

			logger := log.WithFields(log.Fields{
				"performanceMetrics": name,
				"micro":              nowMicro,
			})

			profName := fmt.Sprintf("%s_%d", name, nowMicro)

			prof := pprof.NewProfile(profName)
			if mem {
				prof.Add(runtime.MemProfileRecord{}, 0)
			}

			cpuFilename := fmt.Sprintf("%s_cpu_%d.pprof", name, nowMicro)
			cpuFilename = filepath.Join(rootDir, cpuFilename)

			// Start CPU profiling
			f, err := os.Create(cpuFilename)
			if err != nil {
				logger.WithError(err).Error("failed to create CPU profile file")
				return
			}
			defer f.Close()

			err = pprof.StartCPUProfile(f)
			if err != nil {
				logger.WithError(err).Error("failed to start CPU profile, completing request anyway")
			} else {
				defer pprof.StopCPUProfile()
			}

			next.ServeHTTP(w, r)

			if mem {
				memFilename := fmt.Sprintf("%s_mem_%d.pprof", name, nowMicro)
				memFilename = filepath.Join(rootDir, memFilename)

				// Create memory profile
				memProf, err := os.Create(memFilename)
				if err != nil {
					logger.WithError(err).Error("failed to create memory profile file")
					return
				}
				defer memProf.Close()

				runtime.GC() // Force garbage collection to get accurate memory profile

				err = pprof.WriteHeapProfile(memProf)
				if err != nil {
					logger.WithError(err).Error("failed to write memory profile")
					return
				}
			}
		})
	}
}
