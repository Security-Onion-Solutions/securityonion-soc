// Copyright 2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

// Register as a global component after Vue app is created
components.push({
  name: 'alert-actions',
  component: {
  template: `
    <div class="d-flex flex-wrap justify-end ga-2">
      <v-tooltip location="top" v-if="!alert.acknowledged && !alert.escalated && !alert.dismissed">
        <template v-slot:activator="{ props }">
          <v-btn
            v-bind="props"
            color="info"
            size="small"
            variant="flat"
            @click="$emit('acknowledge')"
            :disabled="isProcessing"
          >
            <v-icon size="small">fa-check</v-icon>
            <span class="ml-1 d-none d-md-inline">Acknowledge</span>
          </v-btn>
        </template>
        <span>Mark this alert as acknowledged</span>
      </v-tooltip>
      
      <v-tooltip location="top" v-if="!alert.escalated">
        <template v-slot:activator="{ props }">
          <v-btn
            v-bind="props"
            color="warning"
            size="small"
            variant="flat"
            @click="$emit('escalate')"
            :disabled="isProcessing"
          >
            <v-icon size="small">fa-briefcase</v-icon>
            <span class="ml-1 d-none d-md-inline">Escalate</span>
          </v-btn>
        </template>
        <span>Create a case from this alert</span>
      </v-tooltip>
      
      <v-tooltip location="top" v-if="!alert.dismissed && !alert.escalated">
        <template v-slot:activator="{ props }">
          <v-btn
            v-bind="props"
            color="secondary"
            size="small"
            variant="outlined"
            @click="$emit('dismiss')"
            :disabled="isProcessing"
          >
            <v-icon size="small">fa-xmark</v-icon>
            <span class="ml-1 d-none d-md-inline">Dismiss</span>
          </v-btn>
        </template>
        <span>Dismiss this alert</span>
      </v-tooltip>
      
      <v-tooltip location="top">
        <template v-slot:activator="{ props }">
          <v-btn
            v-bind="props"
            color="primary"
            size="small"
            variant="text"
            :href="huntUrl"
            target="_blank"
            icon
          >
            <v-icon size="small">fa-magnifying-glass</v-icon>
          </v-btn>
        </template>
        <span>View in Hunt</span>
      </v-tooltip>
    </div>
  `,
  props: {
    alert: {
      type: Object,
      required: true
    },
    isProcessing: {
      type: Boolean,
      default: false
    }
  },
  computed: {
    huntUrl() {
      // Build a hunt URL to view this specific alert
      const query = `id:"${this.alert.id}"`;
      return `#/hunt?q=${encodeURIComponent(query)}`;
    }
  }
  }
});