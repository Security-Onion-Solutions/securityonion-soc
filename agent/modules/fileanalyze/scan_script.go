// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package fileanalyze

import (
	"regexp"
	"strings"
)

// JavascriptScanner analyzes JavaScript files for suspicious patterns
type JavascriptScanner struct{}

func NewJavascriptScanner() *JavascriptScanner {
	return &JavascriptScanner{}
}

func (s *JavascriptScanner) Name() string { return "ScanJavascript" }

func (s *JavascriptScanner) Init(config map[string]interface{}) error { return nil }

func (s *JavascriptScanner) Flavors() []string {
	return []string{"application/javascript", "text/javascript"}
}

func (s *JavascriptScanner) Priority() int { return 5 }

var (
	jsEvalPattern    = regexp.MustCompile(`(?i)\beval\s*\(`)
	jsDocWritePattern = regexp.MustCompile(`(?i)document\.write\s*\(`)
	jsFromCharCode   = regexp.MustCompile(`(?i)String\.fromCharCode`)
	jsUnescape       = regexp.MustCompile(`(?i)\bunescape\s*\(`)
	jsActiveX        = regexp.MustCompile(`(?i)ActiveXObject|WScript\.Shell|Scripting\.FileSystemObject`)
	jsBase64Pattern  = regexp.MustCompile(`(?i)\batob\s*\(|\bbtoa\s*\(`)
	jsFuncPattern    = regexp.MustCompile(`(?i)\bfunction\b`)
	jsVarPattern     = regexp.MustCompile(`(?i)\bvar\b|\blet\b|\bconst\b`)
	jsLongString     = regexp.MustCompile(`["'][^"']{500,}["']`)
	jsHexEscape      = regexp.MustCompile(`\\x[0-9a-fA-F]{2}`)
)

func (s *JavascriptScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	content := string(file)

	result := map[string]interface{}{
		"functions": len(jsFuncPattern.FindAllStringIndex(content, -1)),
		"variables": len(jsVarPattern.FindAllStringIndex(content, -1)),
	}

	var suspicious []interface{}

	if jsEvalPattern.MatchString(content) {
		suspicious = append(suspicious, "eval()")
	}
	if jsDocWritePattern.MatchString(content) {
		suspicious = append(suspicious, "document.write()")
	}
	if jsFromCharCode.MatchString(content) {
		suspicious = append(suspicious, "String.fromCharCode")
	}
	if jsUnescape.MatchString(content) {
		suspicious = append(suspicious, "unescape()")
	}
	if jsActiveX.MatchString(content) {
		suspicious = append(suspicious, "ActiveX/WScript")
	}
	if jsBase64Pattern.MatchString(content) {
		suspicious = append(suspicious, "base64_encoding")
	}
	if jsLongString.MatchString(content) {
		suspicious = append(suspicious, "long_string_literal")
	}

	hexEscapes := len(jsHexEscape.FindAllStringIndex(content, -1))
	if hexEscapes > 20 {
		suspicious = append(suspicious, "heavy_hex_encoding")
	}
	result["hexEscapes"] = hexEscapes

	if len(suspicious) > 0 {
		result["suspicious"] = suspicious
	}

	return &ScanResult{
		Scanner: s.Name(),
		Data:    result,
	}, nil
}

// PhpScanner analyzes PHP files for suspicious patterns
type PhpScanner struct{}

func NewPhpScanner() *PhpScanner {
	return &PhpScanner{}
}

func (s *PhpScanner) Name() string { return "ScanPhp" }

func (s *PhpScanner) Init(config map[string]interface{}) error { return nil }

func (s *PhpScanner) Flavors() []string {
	return []string{"application/x-php", "text/x-php"}
}

func (s *PhpScanner) Priority() int { return 5 }

var (
	phpEvalPattern    = regexp.MustCompile(`(?i)\beval\s*\(`)
	phpExecPattern    = regexp.MustCompile(`(?i)\b(exec|system|passthru|shell_exec|popen|proc_open)\s*\(`)
	phpBase64Pattern  = regexp.MustCompile(`(?i)\bbase64_decode\s*\(`)
	phpAssertPattern  = regexp.MustCompile(`(?i)\bassert\s*\(`)
	phpGlobalsPattern = regexp.MustCompile(`(?i)\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[`)
	phpIncludePattern = regexp.MustCompile(`(?i)\b(include|require|include_once|require_once)\s*\(?\s*\$`)
	phpCreateFuncPattern = regexp.MustCompile(`(?i)\bcreate_function\s*\(`)
)

func (s *PhpScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	content := string(file)

	result := make(map[string]interface{})
	var suspicious []interface{}

	if phpEvalPattern.MatchString(content) {
		suspicious = append(suspicious, "eval()")
	}
	if phpExecPattern.MatchString(content) {
		suspicious = append(suspicious, "command_execution")
	}
	if phpBase64Pattern.MatchString(content) {
		suspicious = append(suspicious, "base64_decode()")
	}
	if phpAssertPattern.MatchString(content) {
		suspicious = append(suspicious, "assert()")
	}
	if phpGlobalsPattern.MatchString(content) && (phpEvalPattern.MatchString(content) || phpExecPattern.MatchString(content)) {
		suspicious = append(suspicious, "user_input_to_execution")
	}
	if phpIncludePattern.MatchString(content) {
		suspicious = append(suspicious, "dynamic_include")
	}
	if phpCreateFuncPattern.MatchString(content) {
		suspicious = append(suspicious, "create_function()")
	}

	if len(suspicious) > 0 {
		result["suspicious"] = suspicious
	}

	return &ScanResult{
		Scanner: s.Name(),
		Data:    result,
	}, nil
}

// VbScanner analyzes VBScript files
type VbScanner struct{}

func NewVbScanner() *VbScanner {
	return &VbScanner{}
}

func (s *VbScanner) Name() string { return "ScanVb" }

func (s *VbScanner) Init(config map[string]interface{}) error { return nil }

func (s *VbScanner) Flavors() []string {
	return []string{"text/vbscript"}
}

func (s *VbScanner) Priority() int { return 5 }

func (s *VbScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	content := string(file)
	contentLower := strings.ToLower(content)

	result := make(map[string]interface{})
	var suspicious []interface{}

	suspiciousPatterns := map[string]string{
		"createobject":    "CreateObject",
		"wscript.shell":  "WScript.Shell",
		"shell.application": "Shell.Application",
		"scripting.filesystemobject": "FileSystemObject",
		"adodb.stream":   "ADODB.Stream",
		"msxml2.xmlhttp": "XMLHTTP",
		"powershell":     "PowerShell",
		"cmd /c":         "cmd_execution",
		"execute ":       "Execute",
		"executeglobal":  "ExecuteGlobal",
	}

	for pattern, name := range suspiciousPatterns {
		if strings.Contains(contentLower, pattern) {
			suspicious = append(suspicious, name)
		}
	}

	if len(suspicious) > 0 {
		result["suspicious"] = suspicious
	}

	return &ScanResult{
		Scanner: s.Name(),
		Data:    result,
	}, nil
}

// BatchScanner analyzes Windows batch files
type BatchScanner struct{}

func NewBatchScanner() *BatchScanner {
	return &BatchScanner{}
}

func (s *BatchScanner) Name() string { return "ScanBatch" }

func (s *BatchScanner) Init(config map[string]interface{}) error { return nil }

func (s *BatchScanner) Flavors() []string {
	return []string{"application/x-bat", "text/x-bat"}
}

func (s *BatchScanner) Priority() int { return 5 }

func (s *BatchScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	content := string(file)
	contentLower := strings.ToLower(content)

	result := make(map[string]interface{})
	var suspicious []interface{}

	suspiciousPatterns := map[string]string{
		"powershell":     "PowerShell",
		"certutil":       "certutil",
		"bitsadmin":      "bitsadmin",
		"mshta":          "mshta",
		"regsvr32":       "regsvr32",
		"rundll32":       "rundll32",
		"wmic":           "wmic",
		"net user":       "net_user",
		"net localgroup": "net_localgroup",
		"schtasks":       "schtasks",
		"sc create":      "sc_create",
		"-encodedcommand": "encoded_command",
		"-enc ":          "encoded_command",
		"bypass":         "execution_policy_bypass",
		"downloadstring": "download_string",
		"downloadfile":   "download_file",
		"invoke-expression": "invoke_expression",
		"iex":            "iex",
	}

	for pattern, name := range suspiciousPatterns {
		if strings.Contains(contentLower, pattern) {
			suspicious = append(suspicious, name)
		}
	}

	// Check for heavy obfuscation (lots of ^ characters or %var% substitution)
	caretCount := strings.Count(content, "^")
	if caretCount > 20 {
		suspicious = append(suspicious, "caret_obfuscation")
	}

	varSubCount := strings.Count(contentLower, "%")
	if varSubCount > 40 {
		suspicious = append(suspicious, "variable_obfuscation")
	}

	if len(suspicious) > 0 {
		result["suspicious"] = suspicious
	}

	return &ScanResult{
		Scanner: s.Name(),
		Data:    result,
	}, nil
}
