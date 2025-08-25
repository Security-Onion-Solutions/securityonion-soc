# Guided Analysis Integration for Alert Escalation

## Overview
This document describes the integration of guided analysis/playbook functionality into the alert escalation workflow in Security Onion SOC.

## User-Facing Changes

### 1. Automatic Guided Analysis Loading
- When escalating an alert to a case, the system now automatically attempts to load and execute guided analysis queries
- This happens even when escalating directly from the alert list without opening the alert detail popup first
- Progress indicator shows while guided analysis is loading

### 2. Enhanced Case Creation
When escalating alerts with guided analysis:
- The case description includes a summary of guided analysis results
- Related events found by guided analysis queries are automatically attached to the case
- Cases are tagged with `guided-analysis` for easy identification
- Metadata about the analysis is stored in case comments

### 3. Graceful Degradation
- If guided analysis queries cannot be executed due to missing field data, the escalation still proceeds
- The case description notes how many queries could not be executed
- Queries with unresolved variables are skipped to prevent errors

### 4. Visual Indicators in Cases
Cases created with guided analysis show:
- Special "Analysis" tab displaying query results
- Badge indicating guided analysis was performed
- Count of related events found
- Summary of successful queries

### 5. Alert Detail Popup Enhancement
- New "Escalate" button added to the alert detail popup
- Allows direct escalation with all guided analysis context

## Technical Improvements

### Error Handling
- Queries with missing variables are now skipped instead of causing 500 errors
- Better fallback when full event data cannot be loaded
- Support for both `{{variable}}` and `{variable}` syntax in playbooks

### Event Search
- Improved event ID handling for both `soc_id` and `_id` fields
- Better detection of which search pattern to use based on ID format

### Performance
- Guided analysis loads asynchronously during escalation
- Queries are executed in parallel where possible
- Failed queries don't block the escalation process

## Known Limitations

1. Some playbook queries require fields that may not be available in all alerts (e.g., `network.community_id`, `related.ip`)
2. Event search by ID may not always find the original alert if the ID format doesn't match expected patterns
3. Guided analysis results depend on the quality and completeness of the playbook definitions

## Usage Notes

### For Analysts
- Click "Escalate" on any alert to create a case with guided analysis
- The system will automatically gather related events based on the playbook queries
- Check the case Events tab to see all attached events
- Review the Analysis tab (when available) for detailed query results

### For Administrators
- Ensure playbooks are properly configured with appropriate queries
- Variables in playbook queries should match available event fields
- Consider adding fallback queries for common missing fields

## Configuration
No additional configuration is required. The feature works automatically when:
- Alerts have a `rule.uuid` field
- Playbooks are defined for the detection rule
- The `/playbook/detection/{uuid}` API endpoint is available

## Troubleshooting

### Queries Not Executing
- Check browser console for "Variable X not found" messages
- Verify the alert has the required fields for variable substitution
- Ensure playbook queries use correct field names

### No Events Attached
- Verify guided analysis queries returned results
- Check that events have `soc_id` fields for attachment
- Review case Events tab filters

### 500 Errors in Queries
- Update to latest version which includes query validation
- Check for unsubstituted variables in query strings (e.g., `{network.community_id}`)
- Report persistent issues with specific playbook queries

## Version History
- v1.0 - Initial integration of guided analysis into alert escalation
- v1.1 - Added automatic loading when escalating from list view
- v1.2 - Improved error handling and variable substitution
- v1.3 - Fixed 500 errors from unresolved variables