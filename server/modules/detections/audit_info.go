package detections

import "github.com/security-onion-solutions/securityonion-soc/model"

type AuditInfo struct {
	DocId     string
	Op        string
	Detection *model.Detection
}
