# API Changes Required for Guided Analysis Integration

## Current API Analysis

### Existing Case Creation Flow

Currently, the case creation involves two separate API calls:

1. **Create Case** (`POST /case/`)
   - Accepts: `model.Case` struct with basic fields
   - Returns: Case with generated ID
   
2. **Attach Events** (`POST /case/events`)
   - Accepts: `model.AttachEventCriteria` with search criteria
   - Attaches events to existing case asynchronously

### Current Frontend Implementation

```javascript
// Frontend currently sends:
const caseData = {
  title: "Alert Title",
  description: "Alert Description",
  severity: "high",
  status: "new",
  events: ["event1", "event2", ...]  // Array of event IDs
};

await this.$root.papi.post('case', caseData);
```

### Backend Case Model

```go
type Case struct {
  Auditable
  StartTime    *time.Time `json:"startTime"`
  CompleteTime *time.Time `json:"completeTime"`
  Title        string     `json:"title"`
  Description  string     `json:"description"`
  Priority     int        `json:"priority"`
  Severity     string     `json:"severity"`
  Status       string     `json:"status"`
  Template     string     `json:"template"`
  Tlp          string     `json:"tlp"`
  Pap          string     `json:"pap"`
  Category     string     `json:"category"`
  AssigneeId   string     `json:"assigneeId"`
  Tags         []string   `json:"tags"`
  // No metadata or events field currently
}
```

## Required API Changes

### Option 1: Minimal Changes (Recommended)

**Leverage existing mechanisms with minimal backend changes:**

#### 1. Enhanced Case Creation Handler

Modify `casehandler.go` to handle the `events` field during case creation:

```go
// casehandler.go modifications
func (h *CaseHandler) createCase(w http.ResponseWriter, r *http.Request) {
  ctx := r.Context()
  
  // Parse the incoming JSON into a temporary struct
  type CaseCreationRequest struct {
    model.Case
    Events   []string               `json:"events,omitempty"`
    Metadata map[string]interface{} `json:"metadata,omitempty"`
  }
  
  var request CaseCreationRequest
  err := json.NewDecoder(r.Body).Decode(&request)
  if err != nil {
    web.Respond(w, r, http.StatusBadRequest, err)
    return
  }
  
  // Create the case
  newCase := model.Case(request.Case)
  createdCase, err := h.server.Casestore.Create(ctx, &newCase)
  if err != nil {
    web.Respond(w, r, http.StatusInternalServerError, err)
    return
  }
  
  // Attach events if provided
  if len(request.Events) > 0 {
    go h.attachEventsToCase(ctx, createdCase.Id, request.Events)
  }
  
  // Store metadata if provided
  if request.Metadata != nil {
    go h.storeMetadata(ctx, createdCase.Id, request.Metadata)
  }
  
  web.Respond(w, r, http.StatusOK, createdCase)
}
```

#### 2. Metadata Storage Using Tags

Since the Case model already has a `Tags` field, we can encode metadata as special tags:

```javascript
// Frontend approach
const caseData = {
  title: this.caseTitle,
  description: this.buildEnrichedDescription(),
  severity: this.selectedAlert.severityLabel,
  status: 'new',
  events: allEventIds,
  tags: [
    'guided-analysis',
    `primary-event:${this.selectedAlert.id}`,
    `rule:${this.selectedAlert.ruleName}`,
    `queries:${analysisData.metadata.length}`
  ]
};
```

#### 3. Store Detailed Metadata as Case Artifact

Use the existing artifact system to store the full guided analysis metadata:

```javascript
// After case creation, add metadata as artifact
const metadataArtifact = {
  caseId: response.data.id,
  type: 'guided_analysis_metadata',
  value: JSON.stringify({
    primaryEventId: this.selectedAlert.id,
    guidedAnalysisQueries: analysisData.metadata,
    aiSummary: this.selectedAlert.aiSummary,
    ruleName: this.selectedAlert.ruleName,
    ruleText: this.selectedAlert.ruleText,
    collectionTimestamp: new Date().toISOString()
  }),
  description: 'Guided Analysis Context',
  tags: ['metadata', 'automated']
};

await this.$root.papi.post('case/artifacts', metadataArtifact);
```

### Option 2: Full Backend Modifications

**Add proper metadata support to the Case model:**

#### 1. Extend Case Model

```go
// model/case.go
type Case struct {
  Auditable
  // ... existing fields ...
  Tags     []string               `json:"tags"`
  Metadata map[string]interface{} `json:"metadata,omitempty"` // NEW
  Events   []string               `json:"events,omitempty"`   // NEW (transient)
}
```

#### 2. Database Schema Changes

For Elasticsearch-based storage:

```json
// Elasticsearch mapping update
{
  "mappings": {
    "properties": {
      // ... existing fields ...
      "metadata": {
        "type": "object",
        "enabled": true
      }
    }
  }
}
```

#### 3. Update Casestore Interface

```go
// server/casestore.go
type Casestore interface {
  // ... existing methods ...
  
  // New methods for metadata
  UpdateMetadata(ctx context.Context, caseId string, metadata map[string]interface{}) error
  GetMetadata(ctx context.Context, caseId string) (map[string]interface{}, error)
}
```

### Option 3: Hybrid Approach (Best Balance)

**Combine minimal backend changes with smart frontend usage:**

#### Backend Changes (Minimal)

1. **Modify Case Creation Handler** to accept and process `events` array
2. **No model changes** - use existing fields creatively

#### Frontend Implementation

```javascript
// Enhanced case creation
async function createEnhancedCase(alert, analysisData) {
  // Step 1: Create case with events
  const caseResponse = await this.$root.papi.post('case/', {
    title: this.caseTitle,
    description: this.buildEnrichedDescription(alert, analysisData),
    severity: alert.severityLabel,
    status: 'new',
    events: [alert.id, ...analysisData.eventIds], // All events
    tags: [
      'guided-analysis',
      `primary:${alert.id}`,
      `rule:${alert.ruleName}`,
      `total-events:${analysisData.eventIds.length + 1}`
    ]
  });
  
  // Step 2: Store detailed metadata as comment (immediately visible)
  await this.$root.papi.post('case/comments', {
    caseId: caseResponse.data.id,
    description: `## Guided Analysis Metadata\n\`\`\`json\n${JSON.stringify({
      primaryEventId: alert.id,
      guidedAnalysisQueries: analysisData.metadata,
      aiSummary: alert.aiSummary,
      timestamp: new Date().toISOString()
    }, null, 2)}\n\`\`\``,
    hours: 0
  });
  
  return caseResponse.data;
}
```

## Backward Compatibility Strategy

### 1. Version Detection

```javascript
// Frontend version detection
async function getCaseAPIVersion() {
  try {
    const response = await this.$root.papi.get('server/info');
    return response.data.apiVersion || '1.0';
  } catch {
    return '1.0'; // Assume old version
  }
}

// Conditional behavior
const apiVersion = await getCaseAPIVersion();
if (apiVersion >= '2.0') {
  // Use new enhanced API
  await createEnhancedCase(alert, analysisData);
} else {
  // Fall back to old behavior
  await createBasicCase(alert);
  await attachEventsManually(caseId, eventIds);
}
```

### 2. Graceful Degradation

```javascript
// Handler wrapper for backward compatibility
async function createCaseWithContext(alert, analysisData) {
  try {
    // Try enhanced method first
    return await createEnhancedCase(alert, analysisData);
  } catch (error) {
    if (error.response?.status === 400) {
      // Fall back to basic creation if enhanced fails
      console.warn('Enhanced case creation failed, using basic method');
      return await createBasicCase(alert);
    }
    throw error;
  }
}
```

### 3. Progressive Enhancement

```javascript
// Add features based on capabilities
const capabilities = await detectCapabilities();

const caseData = {
  title: this.caseTitle,
  description: this.caseDescription,
  severity: this.selectedAlert.severityLabel,
  status: 'new'
};

// Add events if supported
if (capabilities.supportsEventsInCreation) {
  caseData.events = allEventIds;
}

// Add metadata if supported
if (capabilities.supportsMetadata) {
  caseData.metadata = guidedAnalysisMetadata;
}

// Add tags (always supported)
caseData.tags = generateTags(alert, analysisData);

const response = await this.$root.papi.post('case/', caseData);

// Attach events separately if needed
if (!capabilities.supportsEventsInCreation && allEventIds.length > 0) {
  await attachEventsToCase(response.data.id, allEventIds);
}
```

## Recommended Implementation Path

### Phase 1: Frontend-Only Changes (No API Changes)
- Use enriched descriptions to include all context
- Store metadata as JSON in case comments
- Use tags to mark guided analysis cases
- **Timeline: 1 week**

### Phase 2: Minimal Backend Support
- Modify case creation handler to accept `events` array
- Process events asynchronously after case creation
- **Timeline: 1 week**

### Phase 3: Full Metadata Support (Optional)
- Add metadata field to Case model
- Update database schema
- Implement metadata storage and retrieval
- **Timeline: 2-3 weeks**

## Migration Considerations

### For Existing Cases
- No migration needed for Phase 1 (frontend-only)
- Phase 2 requires no data migration
- Phase 3 would need migration script for existing cases

### Database Impact
- Phase 1: No database changes
- Phase 2: No schema changes, just handler logic
- Phase 3: Schema update required

## Performance Considerations

### Event Attachment
- Current: Synchronous single event attachment
- Proposed: Batch attachment (up to 100+ events)
- Solution: Async processing with progress tracking

```go
// Batch event attachment
func (h *CaseHandler) attachEventsToCase(ctx context.Context, caseId string, eventIds []string) {
  const batchSize = 50
  
  for i := 0; i < len(eventIds); i += batchSize {
    end := i + batchSize
    if end > len(eventIds) {
      end = len(eventIds)
    }
    
    batch := eventIds[i:end]
    go h.processBatch(ctx, caseId, batch)
  }
}
```

## Security Considerations

### Input Validation
- Validate event ID format
- Limit maximum events per case (e.g., 500)
- Sanitize metadata content

```go
// Validation example
func validateEventIds(ids []string) error {
  if len(ids) > 500 {
    return errors.New("too many events: maximum 500")
  }
  
  for _, id := range ids {
    if !isValidEventId(id) {
      return fmt.Errorf("invalid event ID: %s", id)
    }
  }
  
  return nil
}
```

### Authorization
- Verify user has access to all events being attached
- Check case creation permissions
- Validate metadata doesn't contain sensitive data

## Testing Requirements

### Unit Tests
```go
// Test case creation with events
func TestCreateCaseWithEvents(t *testing.T) {
  // Test creating case with 0, 1, 10, 100 events
  // Test invalid event IDs
  // Test metadata storage
}
```

### Integration Tests
```javascript
// Frontend integration test
describe('Enhanced Case Creation', () => {
  it('should create case with guided analysis context', async () => {
    const alert = mockAlertWithGuidedAnalysis();
    const caseData = await createEnhancedCase(alert);
    
    expect(caseData.events).toHaveLength(15); // Primary + related
    expect(caseData.tags).toContain('guided-analysis');
  });
});
```

## Conclusion

The recommended approach is the **Hybrid Approach (Option 3)** which:

1. **Requires minimal backend changes** - just handle `events` array in creation
2. **Maintains full backward compatibility**
3. **Can be implemented incrementally**
4. **Preserves all guided analysis context**
5. **Works with existing infrastructure**

This approach allows immediate value delivery while keeping the door open for future enhancements.