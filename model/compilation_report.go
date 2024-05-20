package model

type CompilationReport struct {
	Timestamp         string   `json:"timestamp"`
	Success           []string `json:"success"`
	Failure           []string `json:"failure"`
	CompiledRulesHash string   `json:"compiled_sha256"`
}
