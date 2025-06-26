package server

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"github.com/apex/log"
)

type EntryMatcher struct {
	validators []EntryValidator
}

type EntryValidator func(*log.Entry) error

func NewEntryMatcher(opts ...EntryValidator) EntryMatcher {
	m := EntryMatcher{
		validators: opts,
	}

	return m
}

func (m *EntryMatcher) Validate(e *log.Entry) error {
	for _, v := range m.validators {
		if err := v(e); err != nil {
			return err
		}
	}

	return nil
}

func LogLevelEq(level log.Level) EntryValidator {
	return func(e *log.Entry) error {
		if e.Level != level {
			return fmt.Errorf("expected level %s, got %s", level, e.Level)
		}

		return nil
	}
}

func LogMessageEq(message string) EntryValidator {
	return func(e *log.Entry) error {
		if e.Message != message {
			return fmt.Errorf("expected message %q, got %q", message, e.Message)
		}

		return nil
	}
}

func LogMessageContains(substr string) EntryValidator {
	return func(e *log.Entry) error {
		if !strings.Contains(e.Message, substr) {
			return fmt.Errorf("expected message to contain %q, got %q", substr, e.Message)
		}

		return nil
	}
}

func LogMessageRegex(pattern *regexp.Regexp) EntryValidator {
	return func(e *log.Entry) error {
		if !pattern.MatchString(e.Message) {
			return fmt.Errorf("expected message to match %q, got %q", pattern, e.Message)
		}

		return nil
	}
}

func LogFieldExists(key string) EntryValidator {
	return func(e *log.Entry) error {
		_, ok := e.Fields[key]
		if !ok {
			return fmt.Errorf("expected field %q to exist", key)
		}

		return nil
	}
}

func LogFieldEq(key string, value interface{}) EntryValidator {
	return func(e *log.Entry) error {
		if !reflect.DeepEqual(e.Fields[key], value) {
			return fmt.Errorf("expected field %q to be %v, got %v", key, value, e.Fields[key])
		}

		return nil
	}
}

func LogFieldContains(key string, substr string) EntryValidator {
	return func(e *log.Entry) error {
		if !strings.Contains(e.Fields[key].(string), substr) {
			return fmt.Errorf("expected field %q to contain %q, got %q", key, substr, e.Fields[key])
		}

		return nil
	}
}

func LogFieldRegex(key string, pattern *regexp.Regexp) EntryValidator {
	return func(e *log.Entry) error {
		if !pattern.MatchString(e.Fields[key].(string)) {
			return fmt.Errorf("expected field %q to match %q, got %q", key, pattern, e.Fields[key])
		}

		return nil
	}
}
