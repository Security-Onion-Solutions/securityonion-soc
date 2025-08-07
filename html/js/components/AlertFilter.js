// Copyright 2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

// Register as a global component after Vue app is created
components.push({
  name: 'alert-filter',
  component: {
  template: `
    <v-row dense>
      <v-col cols="12" sm="4" md="3">
        <v-select
          :model-value="severity"
          @update:model-value="$emit('update:severity', $event)"
          :items="severityOptions"
          label="Severity"
          density="compact"
          variant="outlined"
          hide-details
        >
          <template v-slot:selection="{ item }">
            <v-chip
              v-if="item.value !== 'all'"
              :color="getSeverityColor(item.value)"
              size="small"
              text-color="white"
            >
              {{ item.title }}
            </v-chip>
            <span v-else>{{ item.title }}</span>
          </template>
          <template v-slot:item="{ item, props }">
            <v-list-item v-bind="props">
              <template v-slot:prepend v-if="item.value !== 'all'">
                <v-icon 
                  :color="getSeverityColor(item.value)"
                  size="small"
                >
                  fa-exclamation-circle
                </v-icon>
              </template>
            </v-list-item>
          </template>
        </v-select>
      </v-col>
      
      <v-col cols="12" sm="4" md="3">
        <v-select
          :model-value="status"
          @update:model-value="$emit('update:status', $event)"
          :items="statusOptions"
          label="Status"
          density="compact"
          variant="outlined"
          hide-details
        >
          <template v-slot:item="{ item, props }">
            <v-list-item v-bind="props">
              <template v-slot:prepend>
                <v-icon 
                  :color="getStatusColor(item.value)"
                  size="small"
                >
                  {{ getStatusIcon(item.value) }}
                </v-icon>
              </template>
            </v-list-item>
          </template>
        </v-select>
      </v-col>
      
      <v-col cols="12" sm="4" md="3">
        <v-select
          :model-value="timeRange"
          @update:model-value="console.log('Time range selected:', $event); $emit('update:timeRange', $event)"
          :items="timeRangeOptions"
          label="Time Range"
          density="compact"
          variant="outlined"
          hide-details
        >
          <template v-slot:item="{ item, props }">
            <v-list-item v-bind="props">
              <template v-slot:prepend>
                <v-icon size="small">fa-clock</v-icon>
              </template>
            </v-list-item>
          </template>
        </v-select>
      </v-col>
      
      <v-col cols="12" md="3" class="d-flex align-center">
        <v-btn
          color="primary"
          variant="flat"
          block
          @click="$emit('update')"
          prepend-icon="fa-sync"
        >
          Refresh
        </v-btn>
      </v-col>
    </v-row>
  `,
  props: {
    severity: {
      type: String,
      default: 'all'
    },
    status: {
      type: String,
      default: 'active'
    },
    timeRange: {
      type: String,
      default: '24h'
    }
  },
  data() {
    return {
      severityOptions: [
        { value: 'all', title: 'All Severities' },
        { value: 'high', title: 'High' },
        { value: 'medium', title: 'Medium' },
        { value: 'low', title: 'Low' }
      ],
      statusOptions: [
        { value: 'all', title: 'All Statuses' },
        { value: 'active', title: 'Active' },
        { value: 'acknowledged', title: 'Acknowledged' },
        { value: 'escalated', title: 'Escalated' }
      ],
      timeRangeOptions: [
        { value: '1h', title: 'Last Hour' },
        { value: '24h', title: 'Last 24 Hours' },
        { value: '7d', title: 'Last 7 Days' },
        { value: '30d', title: 'Last 30 Days' }
      ]
    };
  },
  methods: {
    getSeverityColor(severity) {
      switch (severity) {
        case 'high': return 'error';
        case 'medium': return 'warning';
        case 'low': return 'info';
        default: return 'grey';
      }
    },
    getStatusColor(status) {
      switch (status) {
        case 'active': return 'error';
        case 'acknowledged': return 'info';
        case 'escalated': return 'warning';
        default: return 'grey';
      }
    },
    getStatusIcon(status) {
      switch (status) {
        case 'active': return 'fa-bell';
        case 'acknowledged': return 'fa-check';
        case 'escalated': return 'fa-briefcase';
        default: return 'fa-list';
      }
    }
  }
  }
});