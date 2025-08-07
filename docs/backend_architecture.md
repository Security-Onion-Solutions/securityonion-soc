# Security Onion SOC Backend Architecture

## Overview

The Security Onion SOC (Security Operations Center) backend is designed as a distributed system with two primary components: **Server** and **Agent**. These components work together to provide security monitoring, analysis, and response capabilities across a grid of security sensors.

## Server Component

The server component serves as the central management and coordination point for the SOC system. It provides REST API endpoints for client interactions and manages the distribution of work to agent nodes.

### Primary Responsibilities

- **API Management**: Exposes RESTful endpoints for frontend clients and external integrations
- **Job Orchestration**: Creates, manages, and distributes jobs to agent nodes
- **Data Storage**: Interfaces with various backend datastores (Elasticsearch, InfluxDB, etc.)
- **Authentication & Authorization**: Handles user authentication and role-based access control
- **Grid Management**: Maintains information about all nodes in the security grid
- **Case Management**: Manages security cases, related events, comments, and artifacts

### Key Components

#### Core Server Structure
The server is built around a modular architecture where different functionalities are implemented as loadable modules:

- **Datastore**: Handles persistent storage of jobs, cases, and related data
- **Eventstore**: Manages security events and packet capture data
- **Casestore**: Manages case-related data including related events, comments, and artifacts
- **Userstore/Clientstore**: Manages users and API clients
- **Authorizer**: Implements role-based access control (RBAC)
- **Host**: Provides the HTTP server and routing framework

#### Modules
Server modules are dynamically loaded components that extend functionality:

- **Authentication Modules**: `statickeyauth`, `kratos`, `hydra` - Handle different authentication mechanisms
- **Authorization Modules**: `staticrbac` - Implements RBAC for access control
- **Datastore Modules**: `elastic`, `filedatastore` - Different storage backends
- **Case Management Modules**: `elasticcases`, `httpcase`, `thehive` - Different case management systems
- **Detection Modules**: `suricataengine`, `elastalertengine`, `strelkaengine` - Rule-based threat detection engines
- **Utility Modules**: `salt`, `influxdb`, `sostatus`, `navigator`, `playbook`, `assistant` - Various helper and specialized services

## Agent Component

The agent component runs on distributed nodes (sensors) and processes jobs assigned by the server.

### Primary Responsibilities

- **Job Processing**: Executes assigned jobs such as packet capture queries
- **Node Metrics**: Reports system metrics and status information to the server
- **Data Collection**: Gathers and processes security-related data
- **Grid Participation**: Checks in with the server to receive job assignments

### Key Components

#### Core Agent Structure
- **Client**: HTTP client for communicating with the server
- **JobManager**: Manages the job processing lifecycle
- **JobProcessors**: Array of modules that can process different types of jobs

#### Modules
Agent modules handle specific job processing tasks:

- **stenoquery**: Processes PCAP jobs using Stenographer
- **suriquery**: Processes PCAP jobs using Suricata  
- **analyze**: Performs security analysis on artifacts
- **importer**: Handles data import operations
- **statickeyauth**: Agent authentication with the server

## Communication Patterns and Protocols

### Server-Agent Communication

The communication between server and agents follows a **pull-based model** where agents periodically check in with the server:

1. **Node Check-in**: Agents POST to `/api/node` endpoint with current node metrics
2. **Job Assignment**: Server responds with any pending jobs assigned to that node
3. **Job Processing**: Agent processes the job locally
4. **Result Upload**: Agent POSTs job results to `/api/stream` endpoint
5. **Job Update**: Agent PUTs final job status to `/api/job` endpoint

### Authentication

Communication between server and agents is secured through static API keys or more advanced authentication systems like Kratos/Hydra. Agents must authenticate before they can check in or upload results.

### Data Flow

```
[Agent] → (Node Check-in + Metrics) → [Server] → (Job Assignment) → [Agent]
[Agent] → (Job Processing) → [Agent] → (Result Upload) → [Server]
[Agent] → (Job Status Update) → [Server]
```

### REST API Endpoints

Key server endpoints include:
- **POST /api/node**: Agent check-in and job request
- **POST /api/stream**: Upload job result streams (PCAP files, etc.)
- **GET /api/stream/{jobId}**: Download job result streams
- **POST /api/job**: Create new jobs
- **PUT /api/job**: Update existing jobs
- **GET /api/job/{jobId}**: Retrieve job information

## Modular Architecture

### Server Modules Directory Structure

The server modules are organized by functional area:

- **assistant/**: AI assistant integration
- **context/**: Contextual analysis services
- **detections/**: Threat detection engines
- **elastic/**: Elasticsearch integration for events and cases
- **elastalert/**: ElastAlert detection engine
- **elasticcases/**: Elasticsearch case management
- **filedatastore/**: File-based datastore implementation
- **generichttp/**: Generic HTTP case management
- **hydra/**: ORY Hydra authentication integration
- **influxdb/**: Metrics storage and management
- **kratos/**: ORY Kratos authentication integration
- **navigator/**: MITRE ATT&CK navigator integration
- **playbook/**: Security playbook management
- **salt/**: SaltStack configuration management integration
- **sostatus/**: Security Onion system status monitoring
- **statickeyauth/**: Static API key authentication
- **staticrbac/**: Static role-based access control
- **strelka/**: Strelka file analysis engine
- **suricata/**: Suricata detection engine
- **thehive/**: TheHive case management integration

### Agent Modules Directory Structure

Agent modules are organized by job processing capabilities:

- **analyze/**: Security artifact analysis processors
- **importer/**: Data import functionality
- **statickeyauth/**: Static key authentication for server communication
- **stenoquery/**: Stenographer query processor for PCAP extraction
- **suriquery/**: Suricata query processor for PCAP extraction

### Module Lifecycle

1. **Initialization**: Modules implement an `Init()` method that configures the module based on provided configuration
2. **Prerequisites**: Modules can declare prerequisite modules that must be loaded first
3. **Startup**: Modules implement a `Start()` method for runtime initialization
4. **Runtime**: Modules perform their designated functions
5. **Shutdown**: Modules implement a `Stop()` method for graceful termination

## Core Data Structures

### Node (model.Node)

Represents an agent node in the security grid:

- **Id**: Unique node identifier
- **OnlineTime**: When the node first came online
- **UpdateTime**: Last update timestamp
- **EpochTime**: Oldest available PCAP data timestamp
- **Metrics**: System performance metrics (CPU, memory, disk, network)
- **Status**: Node status (unknown, ok, fault, pending, restart)
- **Role**: Node role (so-desktop, so-standalone, etc.)
- **Version**: Security Onion version installed

### Job (model.Job)

Represents a task that needs to be processed by an agent:

- **Id**: Unique job identifier
- **CreateTime**: Job creation timestamp
- **Status**: Job status (pending, completed, incomplete, deleted)
- **CompleteTime**: Job completion timestamp
- **FailTime**: Last failure timestamp
- **Failure**: Failure reason string
- **FailCount**: Number of failed attempts
- **NodeId**: Assigned node identifier
- **FileExtension**: Result file extension
- **Filter**: Job filtering parameters
- **UserId**: User who created the job
- **Kind**: Job type (pcap, analyze, import, etc.)
- **Results**: Array of job results
- **Size**: Result size in bytes

### Filter (model.Filter)

Defines filtering criteria for jobs:

- **ImportId**: Optional import identifier
- **BeginTime/EndTime**: Time range for packet capture
- **SrcIp/DstIp**: Source and destination IP addresses
- **SrcPort/DstPort**: Source and destination ports
- **Protocol**: Network protocol (tcp, udp, icmp)
- **Parameters**: Additional untyped parameters for other job types

### Case (model.Case)

Security case management structure:

- **Id**: Unique case identifier
- **CreateTime**: Case creation timestamp
- **UpdateTime**: Last update timestamp
- **Title**: Case title
- **Description**: Detailed case description
- **Severity**: Case severity level
- **Priority**: Case priority
- **Status**: Case status
- **Tags**: Array of case tags
- **Tlp/Pap**: Traffic Light Protocol and Permissive Action Protocol values

### Artifacts and Related Objects

- **RelatedEvent**: Links external events to security cases
- **Comment**: User comments on cases
- **Artifact**: Security artifacts (files, observables) associated with cases
- **ArtifactStream**: Binary content of artifact files

## Application Entry Points

### Main Entry Point (cmd/sensoroni.go)

The application starts from `cmd/sensoroni.go` which:
1. Loads configuration from JSON file
2. Initializes logging
3. Creates server instance if server configuration exists
4. Creates agent instance if agent configuration exists
5. Launches server modules
6. Launches agent modules
7. Starts server and agent components in separate goroutines
8. Handles graceful shutdown signals

### Startup Process

1. **Configuration Loading**: Reads `sensoroni.json` configuration file
2. **Module Manager Initialization**: Creates a module manager for handling plugins
3. **Server Creation**: If server config exists, creates server instance with API routes
4. **Agent Creation**: If agent config exists, creates agent instance
5. **Module Loading**: Dynamically loads and initializes configured modules
6. **Component Startup**: Starts server and agent components
7. **Shutdown Handling**: Listens for termination signals and shuts down gracefully

### Component Lifecycles

#### Server Lifecycle
- **Init**: Load configuration, initialize logging
- **Start**: Launch modules, start HTTP server, register API routes
- **Run**: Serve API requests, manage jobs and cases
- **Stop**: Graceful shutdown of HTTP server and modules

#### Agent Lifecycle
- **Init**: Load configuration, initialize client and job manager
- **Start**: Launch modules, begin job processing loop
- **Run**: Periodic node check-ins, job processing, result uploads
- **Stop**: Graceful shutdown of job processing and modules
