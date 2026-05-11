package main

import (
	"fmt"
	"github.com/security-onion-solutions/securityonion-soc/syntax"
)

func main() {
	escaped := "new setting [SO_JINJA_SL_START]foo[SO_JINJA_SL_END] [SO_JINJA_CM_START] comment [SO_JINJA_CM_END] [SO_JINJA_ML_START] multiline [SO_JINJA_ML_END]"
	unescaped := syntax.UnescapeJinja(escaped)
	fmt.Printf("Unescaped: %s\n", unescaped)
}
