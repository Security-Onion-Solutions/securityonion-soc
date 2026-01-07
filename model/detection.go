// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/util"
	"gopkg.in/yaml.v3"
)

type ScanType string
type SigLanguage string
type Severity string
type IDType string
type EngineName string
type OverrideType string

const (
	ScanTypeFiles           ScanType = "files"
	ScanTypePackets         ScanType = "packets"
	ScanTypePacketsAndFiles ScanType = "files,packets"
	ScanTypeElastic         ScanType = "elastic"

	SigLangSigma    SigLanguage = "sigma"    // yaml
	SigLangSuricata SigLanguage = "suricata" // action, header, options
	SigLangYara     SigLanguage = "yara"     // meta, strings, condition

	SeverityUnknown       Severity = "unknown"
	SeverityInformational Severity = "informational"
	SeverityLow           Severity = "low"
	SeverityMedium        Severity = "medium"
	SeverityHigh          Severity = "high"
	SeverityCritical      Severity = "critical"

	IDTypeUUID IDType = "uuid"
	IDTypeSID  IDType = "sid"

	EngineNameSuricata   EngineName = "suricata"
	EngineNameStrelka    EngineName = "strelka"
	EngineNameElastAlert EngineName = "elastalert"

	OverrideTypeSuppress     OverrideType = "suppress"
	OverrideTypeThreshold    OverrideType = "threshold"
	OverrideTypeModify       OverrideType = "modify"
	OverrideTypeCustomFilter OverrideType = "customFilter"

	// Valid values for Track parameter (shared between threshold and suppress)
	TrackBySrc = "by_src"
	TrackByDst = "by_dst"
	// TrackByEither is only valid for suppress overrides
	TrackByEither = "by_either"
	// TrackByBoth is only valid for threshold overrides
	TrackByBoth = "by_both"

	// Valid values for ThresholdType parameter
	ThresholdTypeLimit     = "limit"
	ThresholdTypeThreshold = "threshold"
	ThresholdTypeBoth      = "both"

	LicenseDRL        = "DRL"
	LicenseCommercial = "Commercial"
	LicenseBSD        = "BSD"
	LicenseUnknown    = "Unknown"
)

var (
	EnginesByName = map[EngineName]*DetectionEngine{
		EngineNameSuricata: {
			Name:        string(EngineNameSuricata),
			IDType:      IDTypeSID,
			ScanType:    ScanTypePackets,
			SigLanguage: SigLangSuricata,
		},
		EngineNameStrelka: {
			Name:        string(EngineNameStrelka),
			IDType:      IDTypeUUID,
			ScanType:    ScanTypeFiles,
			SigLanguage: SigLangYara,
		},
		EngineNameElastAlert: {
			Name:        string(EngineNameElastAlert),
			IDType:      IDTypeUUID,
			ScanType:    ScanTypeElastic,
			SigLanguage: SigLangSigma,
		},
	}

	SupportedLanguages = map[SigLanguage]struct{}{
		SigLangSigma:    {},
		SigLangSuricata: {},
		SigLangYara:     {},
	}

	ErrUnsupportedEngine   = errors.New("unsupported engine")
	ErrInvalidOverrideType = errors.New("invalid override type")
)

type DetectionEngine struct {
	// The name of the detection engine
	Name string `json:"name" enum:"elastalert,strelka,suricata"`
	// Which ID methodology is used by this detection engine
	IDType IDType `json:"idType" enum:"sid,uuid"`
	// Which scan methodology is used by this detection engine
	ScanType ScanType `json:"scanType" enum:"files,packets,elastic"`
	// The language that this detection engine uses.
	SigLanguage SigLanguage `json:"sigLanguage" enums:"sigma,suricata,yara"`
}

type Detection struct {
	Auditable
	// The public ID shared across all Security Onion grids
	PublicID string `json:"publicId" example:"923421c7-9b1e-45d4-80cc-e21d060c8723"`
	// Summarized title of the detection
	Title string `json:"title" example:"Security Onion - Grid Node Login Failure (SSH)"`
	// The severity classification of this detection
	Severity Severity `json:"severity" enums:"unknown,informational,low,medium,high,critical"`
	// The original author of this detection. This can be a mixture of email address, organization name, first name, or any freeform value
	Author string `json:"author" example:"Security Onion Solutions"`
	// Used for categorizing this detection into a broader grouping such as firewalls or web servers
	Category string `json:"category,omitempty" example:"ps_script"`
	// Brief explanation of this detection
	Description string `json:"description" example:"Detects when a user fails to login to a grid node via SSH. Review associated logs for username and source IP."`
	// The underlying detection rule source content
	Content string `json:"content" example:"title: CobaltStrike Named Pipe\nid: ...\n logsource:\n ...\ncondition: selection\nfalsepositives:\n..."`
	// Indicates whether this detection is currently enabled in the Security Onion grid
	IsEnabled bool `json:"isEnabled" example:"true"`
	// Indicates whether this detection is currently triggering alerts. Not yet fully implemented.
	IsReporting bool `json:"isReporting" example:"false"`
	// Indicates whether this detection originated from a community ruleset. Duplicated detections will show 'false'.
	IsCommunity bool `json:"isCommunity" example:"true"`
	// The engine that processes this detection
	Engine EngineName `json:"engine"`
	// The language that this detection uses.
	Language SigLanguage `json:"language" enums:"sigma,suricata,yara"`
	// A list of tuning overrides that apply to this detection.
	Overrides []*Override `json:"overrides"` // Tuning
	// An optional list of user-defined tags, useful for grouping similar detections together
	Tags []string `json:"tags"`
	// The name of the ruleset from which this detection originated, or __custom__ if the ruleset was created outside of a ruleset
	Ruleset string `json:"ruleset" example:"__custom__"`
	// The license that applies to this detection
	License string `json:"license" example:"DRL"`
	// The date and time when the underlying detection rule source was created. This is not when the detection was added to this grid.
	SourceCreated *time.Time `json:"sourceCreated"`
	// The date and time when the underlying detection rule source was last updated. This is not when the detection was updated in this grid.
	SourceUpdated *time.Time `json:"sourceUpdated"`

	// these are transient fields, not stored in the database
	PendingDelete bool `json:"-"`
	PersistChange bool `json:"-"`

	// Used by Sigma rules for filtering log outputs to a specific product, such as the Windows eventlog types
	Product string `json:"product,omitempty" example:"windows"`
	// Used by Sigma rules for filtering a subset of log ouputs to a specific server.
	Service string `json:"service,omitempty" example:"sshd"`

	// AI Description fields
	*AiFields `json:",omitempty"`
}

type AiFields struct {
	// The detection summary generated by artificial intelligence
	AiSummary string `json:"aiSummary" example:"This rule detects antivirus alerts reporting the presence of ransomware,..."`
	// Reserved for future use
	AiSummaryReviewed bool `json:"aiSummaryReviewed" example:"false"`
	// Indicates whether this detection's AI summary is current (true) or if the detection source has changed but the generated summary has not yet been updated to reflect the change"
	IsAiSummaryStale bool `json:"isSummaryStale" example:"false"`
}

type DetectionComment struct {
	Auditable
	// The detection ID to which this comment was added
	DetectionId string `json:"detectionId" example:"CwR86o8B-vS4HfrbMV5Y"`
	// The comment text or markdown content
	Value string `json:"value" example:"This detection is known to trigger FPs on the first of the month"`
}

// Note: JSON tags are used when storing the object in ElasticSearch,
// YAML tags are used when storing the object in a YAML config file (Suricata).

type Override struct {
	// The type of override; available values vary between detection engines
	Type OverrideType `json:"type" yaml:"type" enums:"customFilter,modify,suppress,threshold"`
	// Indicates whether this override is enabled
	IsEnabled bool `json:"isEnabled" yaml:"-" example:"true"`
	// An optional operational note for this override
	Note string `json:"note" yaml:"-" example:"Exclude the SMTP server due to FPs"`
	// The date and time when this override was created
	CreatedAt time.Time `json:"createdAt" yaml:"-" example:"2024-12-06T14:36:45.579994541Z"`
	// The date and time when this override was last modified
	UpdatedAt          time.Time `json:"updatedAt" yaml:"-" example:"2024-12-06T14:36:45.579994541Z"`
	OverrideParameters `yaml:",inline"`
}

type OverrideParameters struct {
	// (suricata only) Regular expression for matching modify overrides
	Regex *string `json:"regex,omitempty" yaml:"regex,omitempty" example:"content:xyz"` // modify
	// (suricata only) The value needing to match the regex in order for this override to apply
	Value *string `json:"value,omitempty" yaml:"value,omitempty" example:"content:xyz content:!1.2.3.4/32"` // modify
	// (suricata only) Threshold type, for threshold overrides
	ThresholdType *string `json:"thresholdType,omitempty" yaml:"type,omitempty" enums:"threshold,limit,both"` // threshold
	// (suricata only) Track type for suppress and threshold overrides (by_either only applies to suppress overrides)
	Track *string `json:"track,omitempty" yaml:"track,omitempty" enums:"by_src,by_dst,by_either"` // suppress, threshold
	// (suricata only) The IP address or network value, must be in CIDR format: x.x.x.x/y
	IP *string `json:"ip,omitempty" yaml:"ip,omitempty" example:"1.2.3.4/32"` // suppress
	// (suricata only) For treshold overrides, this is the number of occurrences allowed, within the given seconds interval, before this detection triggers an alert. Must be non-negative and greater than 0.
	Count *int `json:"count,omitempty" yaml:"count,omitempty" example:"10"` // threshold
	// (suricata only) For treshold overrides, this is the number of seconds that the occurrence threshold must occur within. Must be non-negative and greater than 0.
	Seconds *int `json:"seconds,omitempty" yaml:"seconds,omitempty" example:"120"` // threshold

	// (elastalert only) The custom filter applied to Sigma detections before the detection will trigger an alert.
	CustomFilter *string `json:"customFilter,omitempty" yaml:"-" example:"sofilter:\n  user.name: dresden"` // customFilter
}

type OverrideNoteUpdate struct {
	// The note content to replace on an existing override.
	Note string `json:"note" example:"corrected note"`
}

type BulkUpdateStats struct {
	Updated        int
	Audited        int
	Filtered       int
	ErrMap         map[string]string
	UpdateDuration time.Duration
	NeedToSync     []*Detection
}

func (o Override) PrepareForSigma() (map[string]interface{}, error) {
	if o.CustomFilter == nil || !o.IsEnabled {
		return map[string]interface{}{}, nil
	}

	mid := map[string]interface{}{}
	out := map[string]interface{}{}

	filter := util.TabsToSpaces(*o.CustomFilter, 2)

	err := yaml.Unmarshal([]byte(filter), mid)

	for k, v := range mid {
		// does the property begin with sofilter?
		if !strings.HasPrefix(k, "sofilter") {
			// does the object already contain a property with the sofilter prefix?
			_, exists := out["sofilter_"+k]
			if exists {
				// keep appending numbers until there's no collision
				for i := 0; ; i++ {
					num := strconv.Itoa(i)
					_, exists = out["sofilter_"+k+num]
					if !exists {
						out["sofilter_"+k+num] = v
						break
					}
				}
			} else {
				// the property doesn't begin with sofilter, but adding it isn't a collsion
				out["sofilter_"+k] = v
			}
		} else {
			// the property begins with sofilter
			out[k] = v
		}
	}

	return out, err
}

func (o Override) MarshalYAML() (interface{}, error) {
	out := map[string]*OverrideParameters{
		string(o.Type): &o.OverrideParameters,
	}

	return out, nil
}

func (o *Override) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var m map[string]*OverrideParameters
	if err := unmarshal(&m); err != nil {
		return err
	}

	for k, v := range m {
		o.Type = OverrideType(k)
		o.IsEnabled = true
		o.OverrideParameters = *v
	}

	return nil
}

func (detect *Detection) Validate() error {
	detect.Engine = EngineName(strings.ToLower(string(detect.Engine)))
	_, engIsSupported := EnginesByName[detect.Engine]
	if !engIsSupported {
		return ErrUnsupportedEngine
	}

	for _, o := range detect.Overrides {
		if err := o.Validate(detect.Engine); err != nil {
			return err
		}
	}

	return nil
}

func (o *Override) Validate(engine EngineName) error {
	if o.Type == "" {
		return errors.New("override type is required")
	}

	if engine == EngineNameSuricata {
		switch o.Type {
		case OverrideTypeModify:
			if o.Regex == nil || o.Value == nil {
				return errors.New("missing required parameter(s)")
			}

			// Validate that the regex pattern compiles
			if _, err := regexp.Compile(*o.Regex); err != nil {
				return fmt.Errorf("invalid regex pattern: %w", err)
			}

			if o.ThresholdType != nil ||
				o.Track != nil ||
				o.Count != nil ||
				o.Seconds != nil ||
				o.CustomFilter != nil {
				return errors.New("unnecessary fields in override")
			}
		case OverrideTypeSuppress:
			if o.IP == nil || o.Track == nil {
				return errors.New("missing required parameter(s)")
			}

			if o.Regex != nil ||
				o.Value != nil ||
				o.ThresholdType != nil ||
				o.Count != nil ||
				o.Seconds != nil ||
				o.CustomFilter != nil {
				return errors.New("unnecessary fields in override")
			}

			// Validate Track value (suppress allows by_either)
			switch *o.Track {
			case TrackBySrc, TrackByDst, TrackByEither:
				// valid
			default:
				return fmt.Errorf("invalid track value %q: must be by_src, by_dst, or by_either", *o.Track)
			}

			// Validate IP format
			if err := validateSuricataIP(*o.IP); err != nil {
				return err
			}
		case OverrideTypeThreshold:
			if o.ThresholdType == nil || o.Track == nil || o.Count == nil || o.Seconds == nil {
				return errors.New("missing required parameter(s)")
			}

			if o.Regex != nil ||
				o.Value != nil ||
				o.CustomFilter != nil {
				return errors.New("unnecessary fields in override")
			}

			// Validate ThresholdType value
			switch *o.ThresholdType {
			case ThresholdTypeLimit, ThresholdTypeThreshold, ThresholdTypeBoth:
				// valid
			default:
				return fmt.Errorf("invalid thresholdType value %q: must be limit, threshold, or both", *o.ThresholdType)
			}

			// Validate Track value (threshold allows by_both, not by_either)
			switch *o.Track {
			case TrackBySrc, TrackByDst, TrackByBoth:
				// valid
			default:
				return fmt.Errorf("invalid track value %q: must be by_src, by_dst, or by_both", *o.Track)
			}

			// Validate Count is positive
			if *o.Count <= 0 {
				return fmt.Errorf("invalid count value %d: must be greater than 0", *o.Count)
			}

			// Validate Seconds is positive
			if *o.Seconds <= 0 {
				return fmt.Errorf("invalid seconds value %d: must be greater than 0", *o.Seconds)
			}
		}

	} else if engine == EngineNameElastAlert {
		switch o.Type {
		case OverrideTypeCustomFilter:
			if o.CustomFilter == nil {
				return errors.New("missing required parameter(s)")
			}

			if o.Regex != nil ||
				o.Value != nil ||
				o.ThresholdType != nil ||
				o.Track != nil ||
				o.Count != nil ||
				o.Seconds != nil {
				return errors.New("unnecessary fields in override")
			}

			*o.CustomFilter = util.TabsToSpaces(*o.CustomFilter, 2)
			fauxDoc := map[string]interface{}{}

			err := yaml.Unmarshal([]byte(*o.CustomFilter), fauxDoc)
			if err != nil {
				return fmt.Errorf("custom filter override has invalid YAML: %w", err)
			}
		default:
			return ErrInvalidOverrideType
		}
	} else {
		return ErrInvalidOverrideType
	}

	return nil
}

// validateSuricataIP validates IP format for Suricata suppress rules.
// Valid formats: plain IP (1.2.3.4), CIDR (1.2.3.0/24), variable ($HOME_NET),
// or bracketed list ([1.2.3.4,5.6.7.8/24])
func validateSuricataIP(ip string) error {
	if ip == "" {
		return errors.New("ip value cannot be empty")
	}

	// Allow Suricata variables like $HOME_NET
	if strings.HasPrefix(ip, "$") {
		return nil
	}

	// Handle bracketed list format [ip1,ip2,...]
	if strings.HasPrefix(ip, "[") && strings.HasSuffix(ip, "]") {
		inner := ip[1 : len(ip)-1]
		parts := strings.Split(inner, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if err := validateSingleIP(part); err != nil {
				return fmt.Errorf("invalid IP in list %q: %w", part, err)
			}
		}
		return nil
	}

	return validateSingleIP(ip)
}

// validateSingleIP validates a single IP or CIDR
func validateSingleIP(ip string) error {
	// Try CIDR first
	if strings.Contains(ip, "/") {
		_, _, err := net.ParseCIDR(ip)
		if err != nil {
			return fmt.Errorf("invalid CIDR %q: %w", ip, err)
		}
		return nil
	}

	// Try plain IP
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address %q", ip)
	}
	return nil
}

func (o *Override) Equal(other *Override) bool {
	if o == nil && other == nil {
		return true
	}

	if (o == nil || other == nil) ||
		(o.Type != other.Type) ||
		(o.IsEnabled != other.IsEnabled) ||
		(o.CreatedAt != other.CreatedAt) ||
		(o.UpdatedAt != other.UpdatedAt) {
		return false
	}

	result := false

	switch o.Type {
	case OverrideTypeSuppress:
		result = util.ComparePtrs(o.IP, other.IP) &&
			util.ComparePtrs(o.Track, other.Track)
	case OverrideTypeThreshold:
		result = util.ComparePtrs(o.ThresholdType, other.ThresholdType) &&
			util.ComparePtrs(o.Track, other.Track) &&
			util.ComparePtrs(o.Count, other.Count) &&
			util.ComparePtrs(o.Seconds, other.Seconds)
	case OverrideTypeModify:
		result = util.ComparePtrs(o.Regex, other.Regex) &&
			util.ComparePtrs(o.Value, other.Value)
	case OverrideTypeCustomFilter:
		result = util.ComparePtrs(o.CustomFilter, other.CustomFilter)
	}

	return result
}

type AuditInfo struct {
	DocId  string
	Op     string
	Object interface{}
}

type AiSummary struct {
	PublicId     string
	Reviewed     bool   `yaml:"Reviewed"`
	Summary      string `yaml:"Summary"`
	RuleBodyHash string `yaml:"Rule-Body-Hash"`
}
