package util

import (
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"time"

	"github.com/apex/log"
)

type IOManager interface {
	ReadFile(path string) ([]byte, error)
	WriteFile(path string, contents []byte, perm fs.FileMode) error
	DeleteFile(path string) error
}

// go install go.uber.org/mock/mockgen@latest
//go:generate mockgen -destination mock/mock_iomanager.go -package mock . IOManager

func DetermineWaitTime(iom IOManager, path string, importFrequency time.Duration) time.Duration {
	lastImport, err := readStateFile(iom, path)
	if err != nil {
		log.WithError(err).Error("unable to read state file, deleting it")

		derr := iom.DeleteFile(path)
		if derr != nil {
			log.WithError(derr).WithField("path", path).Error("unable to remove state file, ignoring it")
		}
	}

	var timerDur time.Duration

	if lastImport != nil {
		lastImportTime := time.Unix(int64(*lastImport), 0)
		nextImportTime := lastImportTime.Add(importFrequency)

		timerDur = time.Until(nextImportTime)
	} else {
		log.Info("no ElastAlert state file found, waiting 20 mins for first import")
		timerDur = time.Duration(time.Minute * 20)
	}

	return timerDur
}

func readStateFile(iom IOManager, path string) (lastImport *uint64, err error) {
	raw, err := iom.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}

		return nil, fmt.Errorf("unable to read ElastAlert state file: %w", err)
	}

	unix, err := strconv.ParseUint(string(raw), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("unable to parse ElastAlert state file: %w", err)
	}

	return &unix, nil
}

func WriteStateFile(iom IOManager, path string) {
	unix := time.Now().Unix()
	sUnix := strconv.FormatInt(unix, 10)

	err := iom.WriteFile(path, []byte(sUnix), 0644)
	if err != nil {
		log.WithError(err).Error("unable to write state file")
	}
}
