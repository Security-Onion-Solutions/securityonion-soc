package model

type CompilationReport struct {
	Timestamp    string   `json:"timestamp"`
	Successful   []string `json:"successful"`
	Failed       []string `json:"failed"`
	CompiledHash string   `json:"compiledHash"`
}
