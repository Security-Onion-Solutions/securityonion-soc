package model

import "fmt"

type GetAllOption func(query string, schemaPrefix string) string

func WithEngine(engine EngineName) GetAllOption {
	return func(query string, schemaPrefix string) string {
		return fmt.Sprintf(`%s AND %sdetection.engine:"%s"`, query, schemaPrefix, engine)
	}
}

func WithEnabled(isEnabled bool) GetAllOption {
	return func(query string, schemaPrefix string) string {
		return fmt.Sprintf(`%s AND %sdetection.isEnabled:"%t"`, query, schemaPrefix, isEnabled)
	}
}

func WithCommunity(isCommunity bool) GetAllOption {
	return func(query string, schemaPrefix string) string {
		return fmt.Sprintf(`%s AND %sdetection.isCommunity:"%t"`, query, schemaPrefix, isCommunity)
	}
}
