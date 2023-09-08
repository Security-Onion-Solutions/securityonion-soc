package syntax

import (
	"fmt"
	"strings"

	"github.com/security-onion-solutions/securityonion-soc/util"
)

type SuricataRule struct {
	Action      string
	Protocol    string
	Source      string
	Direction   string
	Destination string
	Options     []*RuleOption
}

type RuleOption struct {
	Name  string
	Value *string
}

type state int

const (
	stateAction state = iota
	stateProtocol
	stateSource
	stateDirection
	stateDestination
	stateOptions
)

func ParseSuricataRule(rule string) (*SuricataRule, error) {
	r := strings.NewReader(rule)
	curState := stateAction
	buf := strings.Builder{}
	inQuotes := false
	isEscaping := false

	out := &SuricataRule{
		Options: []*RuleOption{},
	}

	for r.Len() != 0 {
		// TODO: Parse Source and Destination into Address and Ports
		ch, _, _ := r.ReadRune()

		switch curState {
		case stateAction:
			if ch == ' ' {
				out.Action = strings.TrimSpace(buf.String())
				buf.Reset()
				curState = stateProtocol
			} else {
				buf.WriteRune(ch)
			}
		case stateProtocol:
			if ch == ' ' {
				out.Protocol = strings.TrimSpace(buf.String())
				buf.Reset()
				curState = stateSource
			} else {
				buf.WriteRune(ch)
			}
		case stateSource:
			if ch == '<' || ch == '-' {
				out.Source = strings.TrimSpace(buf.String())
				buf.Reset()
				buf.WriteRune(ch)
				curState = stateDirection
			} else {
				buf.WriteRune(ch)
			}
		case stateDirection:
			if ch == ' ' {
				out.Direction = strings.TrimSpace(buf.String())
				if out.Direction != "<>" && out.Direction != "->" {
					return nil, fmt.Errorf("invalid direction, must be '<>' or '->', got %s", out.Direction)
				}

				buf.Reset()
				curState = stateDestination
			} else {
				buf.WriteRune(ch)
			}
		case stateDestination:
			if ch == '(' {
				out.Destination = strings.TrimSpace(buf.String())
				buf.Reset()
				curState = stateOptions
			} else {
				buf.WriteRune(ch)
			}
		case stateOptions:
			if ch == ')' && !inQuotes && !isEscaping {
				if r.Len() != 0 {
					// end of options, but not end of rule?
					return nil, fmt.Errorf("invalid rule, expected end of rule, got %d more bytes", r.Len())
				}
			} else if ch == ';' && !inQuotes && !isEscaping {
				option := strings.TrimSpace(buf.String())
				buf.Reset()

				split := strings.SplitN(option, ":", 2)
				opt := &RuleOption{
					Name: strings.TrimSpace(split[0]),
				}

				if len(split) == 2 {
					opt.Value = util.Ptr(strings.TrimSpace(split[1]))
				}

				out.Options = append(out.Options, opt)
			} else if ch == '"' { // TODO: current test rule has angled quotes, needs fixing
				buf.WriteRune(ch)
				if isEscaping {
					isEscaping = false
				} else {
					inQuotes = !inQuotes
				}
			} else if ch == '\\' {
				isEscaping = true
				buf.WriteRune(ch)
			} else {
				buf.WriteRune(ch)
			}
		}
	}

	return out, nil
}

func (rule *SuricataRule) GetOption(key string) (value *string, ok bool) {
	for _, opt := range rule.Options {
		if opt.Name == key {
			return opt.Value, true
		}
	}

	return nil, false
}

func (rule *SuricataRule) String() string {
	opts := make([]string, 0, len(rule.Options))
	for _, opt := range rule.Options {
		if opt.Value == nil {
			opts = append(opts, fmt.Sprintf("%s;", opt.Name))
		} else {
			opts = append(opts, fmt.Sprintf("%s:%s;", opt.Name, *opt.Value))
		}
	}

	return fmt.Sprintf("%s %s %s %s %s (%s)", rule.Action, rule.Protocol, rule.Source, rule.Direction, rule.Destination, strings.Join(opts, " "))
}
