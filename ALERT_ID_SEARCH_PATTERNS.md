# Alert ID Search Patterns Documentation

## Overview
This document describes the correct search patterns for finding alerts by their IDs in Security Onion SOC.

## ID Field Types

Security Onion alerts can be identified using two different fields:

1. **`_id`** - Elasticsearch document ID
2. **`soc_id`** - Security Onion specific ID

## ID Format Detection

The system uses the following logic to determine which field to search:

### Pattern 1: Alphanumeric IDs (No Underscores)
- **Example**: `67il4pgBixiL5MLlzqUf`
- **Format**: Matches `/^[a-zA-Z0-9]+$/`
- **Search Order**: 
  1. Try `_id` first ✅ (usually successful)
  2. Fallback to `soc_id` if needed

### Pattern 2: IDs with Underscores
- **Example**: `alert_123_456`
- **Format**: Contains `_` character
- **Search Order**:
  1. Try `soc_id` first (typical for this format)
  2. Fallback to `_id` if needed

### Pattern 3: Other Formats
- **Default Behavior**: Try both fields
- **Search Order**:
  1. Try `_id` first
  2. Fallback to `soc_id`

## Console Logging

The system provides detailed console logging to help identify which search pattern works:

```javascript
// Successful search
✅ Successfully found event using _id field
   Alert ID format: 67il4pgBixiL5MLlzqUf
   Full query: _id:"67il4pgBixiL5MLlzqUf"

// Failed search
❌ No event found with soc_id field: 67il4pgBixiL5MLlzqUf

// Documentation summary
===========================================
📝 SEARCH PATTERN DOCUMENTATION:
   ID Pattern: 67il4pgBixiL5MLlzqUf
   ID Format: Alphanumeric (no underscores)
   Successful Field: _id
   Successful Query: _id:"67il4pgBixiL5MLlzqUf"
===========================================
```

## Implementation Details

The search logic is implemented in two key functions:

1. **`showAlertDetails(alert)`** - Used when opening the alert detail popup
2. **`loadGuidedAnalysisForAlert(alert)`** - Used when loading guided analysis without the popup

Both functions:
- Try multiple query patterns in sequence
- Stop on the first successful match
- Log which pattern succeeded for documentation
- Provide fallback handling if no match is found

## API Query Format

The system constructs queries using these patterns:

```javascript
// For _id field
query = `_id:"${alert.id}"`

// For soc_id field  
query = `soc_id:"${alert.id}"`
```

These queries are then passed to the `/events/` API endpoint with appropriate date range and format parameters.

## Troubleshooting

If alerts are not being found:

1. Check the console logs to see which field types were attempted
2. Verify the ID format matches expected patterns
3. Ensure the date range includes the alert timestamp
4. Confirm the alert exists in the index

## Future Improvements

Consider:
- Caching successful ID patterns to optimize future searches
- Adding a configuration option to specify preferred search field
- Implementing a unified ID resolution service