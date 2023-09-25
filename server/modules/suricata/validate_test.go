package suricata

import (
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/util"
	"github.com/tj/assert"
)

func TestParseSuricata(t *testing.T) {
	table := []struct {
		Name   string
		Input  string
		Output *SuricataRule
		Error  *string
	}{
		{
			Name:  "Minimal Rule",
			Input: `a b source port <> destination port ()`,
			Output: &SuricataRule{
				Action:      "a",
				Protocol:    "b",
				Source:      "source port",
				Direction:   "<>",
				Destination: "destination port",
				Options:     []*RuleOption{},
			},
		},
		{
			Name:  "Bad Direction",
			Input: `a b source port <- destination port ()`,
			Error: util.Ptr("invalid direction, must be '<>' or '->', got <-"),
		},
		{
			Name:  "Unnecessary Suffix",
			Input: `a b source port <> destination port () x`,
			Error: util.Ptr("invalid rule, expected end of rule, got 2 more bytes"),
		},
		{
			Name:  "Escaped Option",
			Input: `a b source port <> destination port (msg:"\\\"";)`,
			Output: &SuricataRule{
				Action:      "a",
				Protocol:    "b",
				Source:      "source port",
				Direction:   "<>",
				Destination: "destination port",
				Options: []*RuleOption{
					{Name: "msg", Value: util.Ptr(`"\\\""`)},
				},
			},
		},
		{
			Name:  "Real rule",
			Input: `alert http any any -> any any (msg:"GPL ATTACK_RESPONSE id check returned root"; content:"uid=0|28|root|29|"; classtype:bad-unknown; sid:2100498; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)`,
			Output: &SuricataRule{
				Action:      "alert",
				Protocol:    "http",
				Source:      "any any",
				Direction:   "->",
				Destination: "any any",
				Options: []*RuleOption{
					{Name: "msg", Value: util.Ptr(`"GPL ATTACK_RESPONSE id check returned root"`)},
					{Name: "content", Value: util.Ptr(`"uid=0|28|root|29|"`)},
					{Name: "classtype", Value: util.Ptr("bad-unknown")},
					{Name: "sid", Value: util.Ptr("2100498")},
					{Name: "rev", Value: util.Ptr("7")},
					{Name: "metadata", Value: util.Ptr("created_at 2010_09_23, updated_at 2010_09_23")},
				},
			},
		},
	}

	for _, test := range table {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			rule, err := ParseSuricataRule(test.Input)
			if test.Error != nil {
				assert.Nil(t, rule)
				assert.Equal(t, *test.Error, err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.Output, rule)
			}
		})
	}
}

func TestSuricataRule(t *testing.T) {
	input := `a b source port <> destination port (msg:"\\\""; noalert; sid:12345; rev: "9"; )`

	rule, err := ParseSuricataRule(input)
	assert.NoError(t, err)

	rule2, err := ParseSuricataRule(rule.String())
	assert.NoError(t, err)

	assert.Equal(t, rule, rule2)

	opt, ok := rule.GetOption("msg")
	assert.True(t, ok)
	assert.NotNil(t, opt)
	assert.Equal(t, `"\\\""`, *opt)

	opt, ok = rule.GetOption("sid")
	assert.True(t, ok)
	assert.NotNil(t, opt)
	assert.Equal(t, "12345", *opt)

	opt, ok = rule.GetOption("rev")
	assert.True(t, ok)
	assert.NotNil(t, opt)
	assert.Equal(t, `"9"`, *opt)

	opt, ok = rule.GetOption("noalert")
	assert.True(t, ok)
	assert.Nil(t, opt)

	opt, ok = rule.GetOption("notfound")
	assert.False(t, ok)
	assert.Nil(t, opt)
}
