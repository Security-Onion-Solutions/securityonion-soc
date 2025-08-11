# SecurityOnion SOC Comprehensive Project Review

## Project Purpose and High-Level Architecture

SecurityOnion SOC (Security Onion Console) is a distributed security analysis platform designed to coordinate jobs across multiple sensor nodes. The system enables centralized management of security detection rules and job processing, allowing for scalable threat hunting and analysis operations across a security grid.

The platform follows a distributed architecture with centralized coordination, built around three primary components:

1. **Server Component**: Central coordination point managing jobs, detections, and grid configuration
2. **Agent Components**: Distributed sensor nodes that process jobs assigned by the server
3. **Web Interface**: Browser-based UI for job management, threat hunting, and system configuration

The system is implemented as a single-page application (SPA) using modern web technologies, providing security analysts with comprehensive tools for threat detection, case management, and grid monitoring.

## Backend Architecture

### Overview

The SecurityOnion SOC backend is designed as a distributed system with two primary components: Server and Agent. These components work together to provide security monitoring, analysis, and response capabilities across a grid of security sensors.

### Server Component

The server serves as the central management and coordination point, providing REST API endpoints for client interactions and managing the distribution of work to agent nodes.

#### Primary Responsibilities
- API Management: Exposes RESTful endpoints for frontend clients and external integrations
- Job Orchestration: Creates, manages, and distributes jobs to agent nodes
- Data Storage: Interfaces with various backend datastores (Elasticsearch, InfluxDB, etc.)
- Authentication & Authorization: Handles user authentication and role-based access control
- Grid Management: Maintains information about all nodes in the security grid
- Case Management: Manages security cases, related events, comments, and artifacts

#### Key Components
The server is built around a modular architecture where different functionalities are implemented as loadable modules:

- **Datastore**: Handles persistent storage of jobs, cases, and related data
- **Eventstore**: Manages security events and packet capture data
- **Casestore**: Manages case-related data including related events, comments, and artifacts
- **Userstore/Clientstore**: Manages users and API clients
- **Authorizer**: Implements role-based access control (RBAC)
- **Host**: Provides the HTTP server and routing framework

#### Server Modules
Server modules are dynamically loaded components that extend functionality:

- **Authentication Modules**: `statickeyauth`, `kratos`, `hydra` - Handle different authentication mechanisms
- **Authorization Modules**: `staticrbac` - Implements RBAC for access control
- **Datastore Modules**: `elastic`, `filedatastore` - Different storage backends
- **Case Management Modules**: `elasticcases`, `httpcase`, `thehive` - Different case management systems
- **Detection Modules**: `suricataengine`, `elastalertengine`, `strelkaengine` - Rule-based threat detection engines
- **Utility Modules**: `salt`, `influxdb`, `sostatus`, `navigator`, `playbook`, `assistant` - Various helper and specialized services

### Agent Component

The agent runs on distributed nodes (sensors) and processes jobs assigned by the server.

#### Primary Responsibilities
- Job Processing: Executes assigned jobs such as packet capture queries
- Node Metrics: Reports system metrics and status information to the server
- Data Collection: Gathers and processes security-related data
- Grid Participation: Checks in with the server to receive job assignments

#### Key Components
- **Client**: HTTP client for communicating with the server
- **JobManager**: Manages the job processing lifecycle
- **JobProcessors**: Array of modules that can process different types of jobs

#### Agent Modules
Agent modules handle specific job processing tasks:
- **stenoquery**: Processes PCAP jobs using Stenographer
- **suriquery**: Processes PCAP jobs using Suricata  
- **analyze**: Performs security analysis on artifacts
- **importer**: Handles data import operations
- **statickeyauth**: Agent authentication with the server

### Communication Patterns and Protocols

#### Server-Agent Communication
The communication between server and agents follows a pull-based model where agents periodically check in with the server:

1. Node Check-in: Agents POST to `/api/node` endpoint with current node metrics
2. Job Assignment: Server responds with any pending jobs assigned to that node
3. Job Processing: Agent processes the job locally
4. Result Upload: Agent POSTs job results to `/api/stream` endpoint
5. Job Update: Agent PUTs final job status to `/api/job` endpoint

#### Authentication
Communication between server and agents is secured through static API keys or more advanced authentication systems like Kratos/Hydra. Agents must authenticate before they can check in or upload results.

#### REST API Endpoints
Key server endpoints include:
- POST /api/node: Agent check-in and job request
- POST /api/stream: Upload job result streams (PCAP files, etc.)
- GET /api/stream/{jobId}: Download job result streams
- POST /api/job: Create new jobs
- PUT /api/job: Update existing jobs
- GET /api/job/{jobId}: Retrieve job information

### Core Data Structures

#### Node (model.Node)
Represents an agent node in the security grid with unique identifier, timing information, system metrics, status, role, and version details.

#### Job (model.Job)
Represents a task that needs to be processed by an agent, including creation/completion timestamps, status tracking, assignment details, and result management.

#### Filter (model.Filter)
Defines filtering criteria for jobs with time ranges, IP addresses, ports, protocols, and additional parameters.

#### Case (model.Case)
Security case management structure with identifiers, timing, title, description, severity, priority, status, and associated metadata.

## Frontend Architecture

### Overview

The frontend is a modern web application built using Vue 3 and Vuetify 3 components, providing a comprehensive interface for security analysts. It follows a single-page application (SPA) architecture with client-side routing.

### Technologies Used

#### Core Framework
- Vue 3: Primary JavaScript framework
- Vue Router 4: Client-side routing
- Vuetify 3: Material Design component framework
- jQuery 3.7.1: DOM manipulation utilities

#### External Libraries
- Axios 1.9.0: HTTP client for API communication
- Moment.js 2.30.1: Date/time manipulation
- Chart.js 4.4.9: Data visualization
- Marked 15.0.12: Markdown parsing
- DOMPurify 3.2.6: HTML sanitization for XSS protection

### Application Structure

#### Main Entry Point
The application starts at `html/index.html`, serving as the SPA's single HTML file containing HTML templates, CSS imports, and JavaScript library references.

#### Core Application Logic
`html/js/app.js` manages global data, API integration, WebSocket communication, and implements a publish-subscribe pattern for real-time updates.

#### Component Architecture
Components in `html/js/components/` follow Vue 3 composition API patterns:
- Detection Panel Component: Manages detection rule editing, validation, and overrides
- TreeView Component: Hierarchical data visualization with search functionality

#### Routing System
Routes defined in `html/js/routes/` use Vue Router 4 syntax:
- Home (`/`): Dashboard and message of the day
- Job (`/job/:jobId`): Packet analysis and job details
- Hunt (`/hunt`): Security event hunting interface
- Cases (`/cases`): Case management system
- Detections (`/detections`): Detection rule management
- Grid (`/grid`): Grid member monitoring
- Admin Routes: Users, clients, configuration, license management

### Backend API Integration

#### API Client Setup
Centralized Axios instance configured in `app.js` handles base URLs, HTTP interceptors, authentication flow integration, and error handling.

#### WebSocket Communication
Real-time updates managed through WebSocket connections with automatic reconnection logic, event subscription system, and status broadcasting.

#### Security Considerations
Integration with Ory Kratos for authentication, session management through cookies, RBAC integration, and input validation with XSS protection.

## System Integration and Communication

The SecurityOnion SOC system operates through seamless integration between its backend server-agent distributed architecture and frontend web interface:

1. **Frontend-Backend API Communication**: The Vue frontend uses Axios to communicate with the server's REST API endpoints at `/api/`, enabling real-time interaction with job management, case handling, and detection systems.

2. **Real-time Updates**: WebSocket connections provide live status updates for grid members, detection engines, and system health directly to the frontend UI.

3. **Distributed Job Processing**: Frontend users initiate security analysis jobs which are orchestrated by the server and processed by available agent nodes, with results streamed back through the API.

4. **Unified Security Management**: The system provides a cohesive interface for threat hunting, case management, rule editing, and grid monitoring while maintaining the scalability of distributed processing.

The modular architecture of both server and agent components allows for flexible extension and integration with various security tools and datastores, while the Vue frontend provides an intuitive, responsive interface for security analysts to operate the distributed system effectively.