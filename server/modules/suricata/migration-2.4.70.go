package suricata

import (
	"strings"

	"github.com/apex/log"
)

func (e *SuricataEngine) Migration2470(state []byte) error {
	s := strings.TrimSpace(string(state))
	if s == "1" {
		log.WithField("stateFile", s).Info("state file indicates that the migration to 2.4.70 has already been performed")
		return nil
	}

	if s != "0" {
		log.WithField("stateFile", s).Error("unexpected state file contents, not applying migration to 2.4.70")
		return nil
	}

	log.WithField("stateFile", s).Info("suricata is now migrating to 2.4.70") // for support

	// read in idstools.yaml


	return nil
}
