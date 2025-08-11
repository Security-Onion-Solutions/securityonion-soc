# SecurityOnion SOC Project Overview

## Project Purpose

SecurityOnion SOC (Security Onion Console) is a distributed security analysis platform designed to coordinate jobs across multiple sensor nodes. The system enables centralized management of security detection rules and job processing, allowing for scalable threat hunting and analysis operations across a security grid.

## Primary Technologies

- **Go**: Core backend services, job management, and detection engine implementations
- **JavaScript**: Frontend web interface and client-side functionality
- **TypeScript**: Enhanced frontend components with type safety
- **YAML**: Configuration files and detection rule definitions
- **Python**: Analyzer scripts and detection rule processing
- **Docker**: Containerized deployment components

## Key Directories and Their Roles

### `/agent`
Contains the sensor node agent implementation responsible for job processing:
- Core agent functionality and job management
- Modular processors for different job types (analyze, importer, query modules)
- Detection engine integrations for Suricata, Strelka, and other security tools

### `/server`
Houses the centralized server components:
- API handlers for jobs, detections, cases, and system management
- Detection engine implementations for Suricata, Strelka, and ElastAlert
- Configuration management and grid coordination services
- Data storage interfaces and user management systems

### `/html`
Frontend web application files:
- Main user interface with pages for hunting, job management, and detections
- JavaScript components for interactive functionality
- CSS styling and static assets
- Login interface and system pages

### `/model`
Core data structures and object definitions:
- Job and detection models
- User, case, and grid member definitions
- API response objects and shared data types
- Detection engine specifications and override configurations

### `/module`
Base module system and manager:
- Framework for extensible module functionality
- Module lifecycle management (init, start, stop)
- Interface definitions for modular components

### `/config`
Configuration handling:
- Agent and server configuration structures
- Configuration validation and management tools

### `/docs`
Documentation and API specifications:
- API documentation and endpoint definitions
- System architecture and usage guides

### `/cmd`
Main application entry points:
- Primary server and agent command-line interfaces
- Application initialization and startup logic

### `/json`
JSON serialization utilities:
- Custom JSON handling for consistent object marshaling
- JSON writing and loading functions

### `/util`
Shared utility functions:
- Common helper methods and validation tools
- Date parsing, UUID generation, and string manipulation
- File system operations and process execution utilities

## System Architecture

The platform follows a distributed architecture with centralized coordination:

1. **Server Component**: Central coordination point managing jobs, detections, and grid configuration
2. **Agent Components**: Distributed sensor nodes that process jobs assigned by the server
3. **Job Processing**: Asynchronous job handling with support for multiple job types (analyze, pcap, etc.)
4. **Detection Management**: Ruleset management for multiple security engines (Suricata, YARA/Strelka, ElastAlert/Sigma)
5. **Web Interface**: Browser-based UI for job management, threat hunting, and system configuration

## Core Functionality

- **Job Distribution**: Centralized job assignment to available sensor nodes
- **Security Analysis**: Integration with multiple security analysis engines
- **Rule Management**: Detection rule synchronization and override capabilities
- **Grid Coordination**: Multi-node security infrastructure management
- **Web Interface**: Interactive dashboard for security operations