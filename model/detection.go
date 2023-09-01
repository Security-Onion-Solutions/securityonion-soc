package model

import (
	"errors"
	"strings"
)

type ScanType string
type SigLanguage string
type Severity string
type IDType string
type EngineName = string

const (
	ScanTypeFiles           ScanType = "files"
	ScanTypePackets         ScanType = "packets"
	ScanTypePacketsAndFiles ScanType = "files,packets"
	ScanTypeElastic         ScanType = "elastic"

	SigLangElastic  SigLanguage = "elastic"  // yaml
	SigLangSigma    SigLanguage = "sigma"    // yaml
	SigLangSuricata SigLanguage = "suricata" // action, header, options
	SigLangYara     SigLanguage = "yara"
	SigLangZeek     SigLanguage = "zeek"

	SeverityLow    Severity = "low"
	SeverityMedium Severity = "medium"
	SeverityHigh   Severity = "high"

	IDTypeUUID IDType = "uuid"
	IDTypeSID  IDType = "sid"

	EngineNameSuricata   EngineName = "suricata"
	EngineNameYara       EngineName = "yara"
	EngineNameElastAlert EngineName = "elastalert"
)

var (
	EnginesByName = map[EngineName]*DetectionEngine{
		EngineNameSuricata: {
			Name:        string(EngineNameSuricata),
			IDType:      IDTypeSID,
			ScanType:    ScanTypePackets,
			SigLanguage: SigLangSuricata,
		},
		EngineNameYara: {
			Name:        string(EngineNameYara),
			IDType:      IDTypeUUID,
			ScanType:    ScanTypeFiles,
			SigLanguage: SigLangYara,
		},
		EngineNameElastAlert: {
			Name:        string(EngineNameElastAlert),
			IDType:      IDTypeUUID,
			ScanType:    ScanTypeElastic,
			SigLanguage: SigLangElastic,
		},
	}

	ErrUnsupportedEngine = errors.New("unsupported engine")
)

type DetectionEngine struct {
	Name        string      `json:"name"`
	IDType      IDType      `json:"idType"`
	ScanType    ScanType    `json:"scanType"`
	SigLanguage SigLanguage `json:"sigLanguage"`
}

type Detection struct {
	Auditable
	PublicID    string     `json:"publicId"`
	Title       string     `json:"title"`
	Severity    Severity   `json:"severity"`
	Author      string     `json:"author"`
	Description string     `json:"description"`
	Content     string     `json:"content"`
	IsEnabled   bool       `json:"isEnabled"`
	IsReporting bool       `json:"isReporting"`
	IsCommunity bool       `json:"isCommunity"`
	Note        string     `json:"note"`
	Engine      EngineName `json:"engine"`
}

func (detect *Detection) Validate() error {
	detect.Engine = strings.ToLower(detect.Engine)
	_, engIsSupported := EnginesByName[detect.Engine]
	if !engIsSupported {
		return ErrUnsupportedEngine
	}

	return nil
}

func SyncDetections(detections []*Detection) error {
	byEngine := map[EngineName][]*Detection{}
	for _, detect := range detections {
		byEngine[detect.Engine] = append(byEngine[detect.Engine], detect)
	}

	if len(byEngine[EngineNameSuricata]) > 0 {
		err := syncSuricata(byEngine[EngineNameSuricata])
		if err != nil {
			return err
		}
	}

	return nil
}

func syncSuricata(detections []*Detection) error {
	return nil
}
