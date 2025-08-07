# Security Onion SOC Frontend Architecture

## Overview

The Security Onion SOC (Security Operations Center) frontend is a modern web application built using Vue 3 and Vuetify 3 components. It provides a comprehensive interface for security analysts to hunt for threats, manage cases, analyze detections, and monitor grid members. The frontend follows a single-page application (SPA) architecture with client-side routing.

## Technologies Used

### Core Framework
- **Vue 3**: The primary JavaScript framework for building the user interface
- **Vue Router 4**: Handles client-side routing and navigation
- **Vuetify 3**: Material Design component framework for Vue 3
- **jQuery 3.7.1**: Used for DOM manipulation and utility functions

### External Libraries
- **Axios 1.9.0**: HTTP client library for API communication
- **Moment.js 2.30.1**: Date and time manipulation library
- **Moment Timezone 0.5.47**: Timezone support for Moment.js
- **Chart.js 4.4.9**: Charting and data visualization library
- **Marked 15.0.12**: Markdown parsing library
- **DOMPurify 3.2.6**: HTML sanitization library for XSS protection
- **js-yaml 4.1.0**: YAML parsing library

### Utility Libraries
- **LZ-String 1.5.0**: String compression library
- **Prism Editor**: Syntax highlighting editor component
- **Date Range Picker**: Custom date range selection component

## Application Structure

### Main Entry Point
The application starts at `html/index.html`, which serves as the single HTML file for the entire SPA. This file contains:

- **HTML Template**: Basic structure with Vuetify components
- **CSS Imports**: Vuetify, Font Awesome, and custom application styles
- **JavaScript Imports**: All required libraries and application modules

### Core Application Logic
`html/js/app.js` contains the main Vue application setup and core functionality:

#### Global Data Management
- Theme management (dark/light mode)
- Internationalization (i18n) support
- WebSocket connections for real-time updates
- API client configuration and interceptors
- User session and authentication handling
- Grid and subgrid management
- Detection engine status tracking

#### API Integration
The frontend uses Axios to communicate with backend APIs:
- Base API URL: `/api/`
- Authentication APIs: `/auth/`
- Real-time updates via WebSocket connections
- Server settings and parameter loading
- User management APIs
- Detection synchronization status tracking

#### Event System
`html/js/app.js` implements a publish-subscribe pattern for handling real-time events:
- WebSocket-based event broadcasting
- Component subscription management
- Status updates for grid members and detection engines

### Component Architecture
Components are located in `html/js/components/` and follow Vue 3 composition API patterns:

#### Detection Panel Component (`detection-panel.js`)
- Manages detection rule editing and validation
- Handles detection engine-specific logic (Suricata, ElastAlert, Strelka)
- Provides override management for detection rules
- Integrates with Prism Editor for syntax highlighting

#### TreeView Component (`treeview.js`)
- Hierarchical data visualization component
- Supports deep search functionality
- Manages selection state and item filtering
- Used for configuration settings display

### Routing System
Routes are defined in individual files within `html/js/routes/`:

#### Route Registration
- Routes are pushed to a global `routes` array
- Each route file defines its component logic
- Page templates are loaded asynchronously using `loadPageTemplate()`

#### Key Routes
- **Home** (`/`): Dashboard and message of the day display
- **Job** (`/job/:jobId`): Packet analysis and job details
- **Hunt** (`/hunt`): Security event hunting interface
- **Cases** (`/cases`): Case management system
- **Detections** (`/detections`): Detection rule management
- **Grid** (`/grid`): Grid member monitoring
- **Admin Routes**: Users, clients, configuration, license management

### Page Templates
HTML templates are stored in `html/pages/` and loaded dynamically:

#### Template Loading
- Pages use `loadPageTemplate()` function to load HTML content
- Templates are cached with version-specific cache busters
- Each route corresponds to a specific page template file

#### Template Structure
- Uses Vuetify components for layout and styling
- Responsive design with mobile-friendly elements
- Data binding through Vue directives (v-text, v-html, v-model, etc.)

## Routing Mechanism

### Route Definition
Routes are defined using Vue Router 4 syntax:
```javascript
routes.push({ 
  path: '/route-path', 
  name: 'route-name', 
  component: {
    template: '#template-id',
    data() { return { /* component data */ } },
    methods: { /* component methods */ }
  }
});
```

### Template Loading Workflow
1. Route files call `loadPageTemplate('template-id', 'pages/template.html')`
2. Templates are loaded asynchronously with cache busting
3. Templates are appended to the document body
4. Router components reference templates by their ID

### Navigation
- Navigation drawer with categorized menu items
- Toolbar with user profile and settings access
- Breadcrumb navigation and page titles
- External tool integration via dynamic links

## Component-Based Structure

### Component Registration
Components are registered globally in the main Vue application:
```javascript
app.component(component.name, component.component);
```

### Component Properties and Methods (`detection-panel.js` example)
**Props**:
- `detection`: Detection object to display/edit
- `zone`: Timezone for date formatting
- `ackColor`: Color for acknowledgment status
- `alertInfo`: Alert information object

**Methods**:
- Detection rule validation and saving
- Override management (add, edit, delete)
- Syntax highlighting and formatting
- Error handling and user feedback

### Data Flow
1. Components receive props from parent routes
2. Local data state management within components
3. API calls through the global `$root.papi` Axios instance
4. Event publishing for real-time updates
5. WebSocket subscription for status changes

## Backend API Integration

### API Client Setup
The frontend uses a centralized Axios instance configured in `app.js`:
- Base URL construction based on current location
- HTTP interceptors for request/response handling
- Authentication flow integration
- Error handling and unauthorized access redirection

### Data Fetching Patterns
```javascript
// API calls with parameter management
await this.$root.papi.get('endpoint', { params: { /* parameters */ } });

// POST/PUT requests with data payloads
await this.$root.papi.put('/detection', this.detection);

// Authentication APIs
await this.$root.authApi.get('logout/browser');
```

### WebSocket Communication
Real-time updates are handled through WebSocket connections:
- Connection management and reconnection logic
- Event subscription system for component updates
- Status broadcasting for grid health and detections
- Automatic grid ID parameter handling

### Error Handling
- Centralized error display with snackbars
- Automatic redirection on authentication failures
- API timeout and connection state management
- User-friendly error messages with localization support

## Security Considerations

### Authentication Flow
- Integration with Ory Kratos for user authentication
- Session management through cookies
- Automatic redirection after login/logout flows
- Role-based access control (RBAC) integration

### Data Protection
- Markdown sanitization using DOMPurify
- Input validation and rule syntax checking
- API request/response interception for security
- WebSocket authentication token management

### UI Security Indicators
- Connection status indicators (disconnected/reconnecting)
- License expiration warnings
- Detection engine health status
- Grid member health monitoring

## Internationalization

### Localization System
- i18n integration with language-specific translations
- Dynamic message localization based on navigator.language
- Parameterized message system
- Date/time formatting with locale support

### Supported Features
- Multilingual UI elements
- Timezone-aware date formatting
- Localized error messages
- Theme-aware color adjustments

## Responsive Design

### Vuetify Integration
- Material Design responsive layouts
- Theme-aware styling (dark/light modes)
- Mobile-friendly navigation and components
- Dynamic spacing and sizing adjustments

### Custom CSS
- Application-specific styling in `html/css/app.css`
- Responsive breakpoints for different screen sizes
- Custom animations and visual effects
- Theme override capabilities

## Performance Considerations

### Lazy Loading
- Route components loaded on-demand
- Template files loaded asynchronously
- External libraries loaded via CDN references
- Component registration optimized for usage

### Caching
- Local storage for user preferences
- Parameter caching with expiration management
- Theme and toolbar settings persistence
- User details caching for performance

## Deployment Architecture

### Static File Serving
- HTML, CSS, and JavaScript files served statically
- Version-specific cache busting through URL parameters
- External library CDN integration
- Image and font asset management

### Build Process Integration
- Version placeholder replacement during build
- File compression and optimization
- Security-focused content delivery
- Multi-environment configuration support