SECURITY ONION SAMPLE REPORT
============================

{{ if .Error }}
**NOTE: This report encountered a problem extracting the relevant data and may not be complete.**

**Error:** {{.Error}}
{{ end }}


Records must have been created or updated during the following time frame in order to be reflected in this report.

**Report Start Date:** {{formatDateTime "Mon Jan 02 15:04:05 -0700 2006" .BeginDate}}

**Report End Date:** {{formatDateTime "Mon Jan 02 15:04:05 -0700 2006" .EndDate}}

## Sample Doc Events
{{- /* query.myDocEvents.Oql = metadata.type: _doc | groupby event.module, event.dataset }}
{{- /* query.myDocEvents.MetricLimit = 10 }}
{{- /* query.myDocEvents.EventLimit = 100 }}

**Total Events:** {{ formatNumber "%d" "en" .Results.myDocEvents.TotalEvents}}

### Event Counts By Module and Dataset

| Count | Proportion | Module | Dataset |
| ----- | ---------- | ------ | ------- |
{{ range sortMetrics "Value" "desc" .Results.myDocEvents.groupby_0 -}}
| {{ formatNumber "%.0f" "en" .Value}} | {{ formatNumber "%.1f" "en" .Percentage}}% | {{index .Keys 0}} | {{index .Keys 1}} |
{{end}}

### Individual Events (Limited to first {{.Results.myDocEvents.EventLimit}})

| Event Time | Log ID | Source IP | Destination IP |
| ---------- | ------ | --------- | ----------------- |
{{ range sort "fields:soc_timestamp" "asc" .Results.myDocEvents.Events -}}
| {{.Fields.soc_timestamp}} | {{.Fields.log_id_uid}} | {{.Fields.source_ip}} | {{.Fields.destination_ip}} |
{{end}}
