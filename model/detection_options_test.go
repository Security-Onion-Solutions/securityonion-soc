package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWithEngine(t *testing.T) {
	queryModder := WithEngine(EngineNameElastAlert)
	query := queryModder("query", "schemaPrefix")
	assert.Equal(t, query, `query AND schemaPrefixdetection.engine:"elastalert"`)

	queryModder = WithEngine(EngineNameStrelka)
	query = queryModder("query", "schemaPrefix")
	assert.Equal(t, query, `query AND schemaPrefixdetection.engine:"strelka"`)

	queryModder = WithEngine(EngineNameSuricata)
	query = queryModder("query", "schemaPrefix")
	assert.Equal(t, query, `query AND schemaPrefixdetection.engine:"suricata"`)

	queryModder = WithEngine(EngineName("unknown"))
	query = queryModder("query", "schemaPrefix")
	assert.Equal(t, query, `query AND schemaPrefixdetection.engine:"unknown"`)
}

func TestWithEnabled(t *testing.T) {
	queryModder := WithEnabled(true)
	query := queryModder("query", "schemaPrefix")
	assert.Equal(t, query, `query AND schemaPrefixdetection.isEnabled:"true"`)

	queryModder = WithEnabled(false)
	query = queryModder("query", "schemaPrefix")
	assert.Equal(t, query, `query AND schemaPrefixdetection.isEnabled:"false"`)
}

func TestWithCommunity(t *testing.T) {
	queryModder := WithCommunity(true)
	query := queryModder("query", "schemaPrefix")
	assert.Equal(t, query, `query AND schemaPrefixdetection.isCommunity:"true"`)

	queryModder = WithCommunity(false)
	query = queryModder("query", "schemaPrefix")
	assert.Equal(t, query, `query AND schemaPrefixdetection.isCommunity:"false"`)
}
