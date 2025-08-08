# Plan: "Simple Mode" Alerts Interface

This document outlines the plan for creating a new "simple mode" interface for viewing and managing alerts in Security Onion SOC.

## 1. Goals and Non-Goals

### Goals

*   **Simplify Alert Triage:** Provide a streamlined view of alerts that is easier for junior analysts or those new to the platform to understand and act upon.
*   **Focus on Actionable Information:** Highlight the most critical information for each alert, such as source/destination, severity, and rule name, while de-emphasizing complex or raw data.
*   **Improve Usability:** Create a more intuitive and less cluttered user interface for alert management.
*   **Guided Workflow:** Guide analysts through a simplified triage process, such as acknowledging, escalating, or dismissing alerts.
*   **Faster Onboarding:** Reduce the learning curve for new users of the platform.

### Non-Goals

*   **Replacing the Existing Interface:** "Simple mode" is an alternative, not a replacement, for the existing, more detailed alert interface (the "expert mode").
*   **Advanced Analysis:** This interface is not intended for deep-dive analysis, packet inspection, or complex query building. Users will be directed to the expert view for these tasks.
*   **Detection Rule Management:** Creating, editing, or managing detection rules is out of scope for this interface.
*   **Case Management Complexity:** While it may link to cases, it will not replicate the full case management functionality.
*   **Configuration Changes:** The simple mode will not include any system or grid configuration options.

## 2. User Stories

*   **As a junior security analyst,** I want to see a list of the latest alerts, so that I can quickly understand the current threat landscape.
*   **As a junior security analyst,** I want to filter alerts by severity (low, medium, high), so that I can focus on the most critical issues first.
*   **As a junior security analyst,** I want to view the key details of an alert in a simple format (e.g., timestamp, rule name, source/destination IP, severity), so that I can quickly assess its importance.
*   **As a junior security analyst,** I want to perform basic actions on an alert, such as "Acknowledge", "Escalate to Case", or "Dismiss", so that I can manage the alert lifecycle.
*   **As a junior security analyst,** I want to see a clear visual indicator for alerts that have been acknowledged or escalated, so that I can track their status.
*   **As a junior security analyst,** I want to easily switch to the "expert mode" for a specific alert, so that I can perform a deeper investigation when needed.
*   **As a security manager,** I want the simple mode to be intuitive for new team members, so that they can become productive quickly with minimal training.

## 3. High-Level Architecture

### Frontend Components

The new interface will be built as a new route within the existing Vue.js single-page application.

*   **New Route:**
    *   `path: '/alerts'`
    *   `name: 'simple-alerts'`
    *   This will be added to the navigation drawer.

*   **New Page Template:**
    *   `html/pages/alerts.html`: A new page template for the simple mode interface.

*   **New Vue Components (`html/js/components/`):**
    *   `SimpleAlertsView.js`: The main component for the `/alerts` page. It will manage the overall layout and state of the simple mode interface.
    *   `AlertCard.js`: A component to display a single alert with its key information in a card-like format. This will be used within `SimpleAlertsView.js`.
    *   `AlertFilter.js`: A component for filtering alerts by severity, status, and other simple criteria.
    *   `AlertActions.js`: A component containing the action buttons for an alert (Acknowledge, Escalate, Dismiss).

*   **Diagram: Frontend Component Interaction**
    ```mermaid
    graph TD
        A[SimpleAlertsView] --> B[AlertFilter];
        A --> C[AlertCard];
        C --> D[AlertActions];
    ```

### Backend API Endpoints

To support the simple mode, we may need to enhance the existing API. The goal is to use existing endpoints as much as possible, but some modifications or new endpoints might be necessary.

*   **`GET /api/events` (Existing, may need enhancement):**
    *   This endpoint is likely used to fetch alert data. We need to ensure it can efficiently serve the simplified data required for the `AlertCard` component.
    *   **Potential Enhancement:** Add a `view=simple` query parameter to return a condensed version of the alert object, containing only the fields needed for the simple mode UI. This would reduce payload size and improve frontend performance.

*   **`PUT /api/events/:id/status` (New):**
    *   A new endpoint to update the status of an alert. This would be used by the `AlertActions.js` component.
    *   **Request Body:** `{ "status": "acknowledged" | "dismissed" }`
    *   This provides a more specific API for managing the alert lifecycle than using a generic update endpoint.

*   **`POST /api/cases` (Existing):**
    *   The "Escalate to Case" action will use the existing case creation endpoint. The frontend will need to gather the necessary information from the alert to populate the case.

*   **Diagram: Frontend-Backend Interaction**
    ```mermaid
    sequenceDiagram
        participant Frontend
        participant Backend
        Frontend->>Backend: GET /api/events?view=simple
        Backend-->>Frontend: [Simplified Alert Data]
        Frontend->>Backend: PUT /api/events/123/status
        Backend-->>Frontend: { "status": "acknowledged" }
        Frontend->>Backend: POST /api/cases
        Backend-->>Frontend: { "caseId": "456" }
    ```

## 4. Implementation Roadmap

The implementation will be broken down into the following phases:

### Phase 1: Backend API Development (if necessary)

*   **Task 1.1:** Investigate the existing `GET /api/events` endpoint to determine if it can be used as-is or if the `view=simple` parameter is needed.
*   **Task 1.2:** Implement the `view=simple` parameter on the `GET /api/events` endpoint if deemed necessary. This will involve modifying the Go backend code.
*   **Task 1.3:** Create the new `PUT /api/events/:id/status` endpoint in the Go backend to handle alert status updates.
*   **Task 1.4:** Add unit and integration tests for the new and modified API endpoints.

### Phase 2: Frontend Scaffolding

*   **Task 2.1:** Create the new `alerts.html` page template.
*   **Task 2.2:** Add the new `/alerts` route and link it in the main navigation.
*   **Task 2.3:** Create placeholder Vue components: `SimpleAlertsView.js`, `AlertCard.js`, `AlertFilter.js`, and `AlertActions.js`.

### Phase 3: Frontend Component Development

*   **Task 3.1:** Implement the `AlertFilter.js` component with controls for filtering by severity and status.
*   **Task 3.2:** Implement the `SimpleAlertsView.js` component to fetch and display a list of alerts from the backend.
*   **Task 3.3:** Implement the `AlertCard.js` component to display individual alerts with the simplified data structure.
*   **Task 3.4:** Implement the `AlertActions.js` component with buttons for "Acknowledge", "Escalate", and "Dismiss".
*   **Task 3.5:** Integrate the components so that filtering and actions work together.

### Phase 4: Integration and Testing

*   **Task 4.1:** Connect the frontend components to the backend API endpoints.
*   **Task 4.2:** Conduct end-to-end testing of the entire workflow: filtering, viewing, and taking action on alerts.
*   **Task 4.3:** Perform UI/UX testing to ensure the interface is intuitive and meets the goals of simplicity.
*   **Task 4.4:** Write frontend unit tests for the new components.

### Phase 5: Documentation

*   **Task 5.1:** Update the user documentation to include a guide on how to use the new "simple mode" alerts interface.
*   **Task 5.2:** Update the API documentation for any new or modified endpoints.