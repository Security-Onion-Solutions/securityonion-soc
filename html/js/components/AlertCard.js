// Copyright 2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

// Register as a global component after Vue app is created
components.push({
  name: 'alert-card',
  component: {
  template: `
    <v-card 
      :class="cardClasses"
      :elevation="isHovered ? 8 : 2"
      @mouseenter="isHovered = true"
      @mouseleave="isHovered = false"
    >
      <v-card-text>
        <v-row align="center">
          <v-col cols="12" md="8">
            <!-- Alert Header -->
            <div class="d-flex align-center mb-2">
              <v-chip
                :color="severityColor"
                :text-color="severityTextColor"
                size="small"
                class="mr-2"
              >
                {{ alert.severityLabel }}
              </v-chip>
              <v-chip
                v-if="alert.acknowledged"
                color="info"
                variant="outlined"
                size="small"
                class="mr-2"
              >
                <v-icon start size="x-small">fa-check</v-icon>
                Acknowledged
              </v-chip>
              <v-chip
                v-if="alert.escalated"
                color="warning"
                variant="outlined"
                size="small"
                class="mr-2"
              >
                <v-icon start size="x-small">fa-briefcase</v-icon>
                Escalated
              </v-chip>
              <v-chip
                v-if="alert.dismissed"
                color="secondary"
                variant="outlined"
                size="small"
              >
                <v-icon start size="x-small">fa-xmark</v-icon>
                Dismissed
              </v-chip>
            </div>
            
            <!-- Rule Name -->
            <div class="text-h6 mb-1">{{ alert.ruleName }}</div>
            
            <!-- Network Info -->
            <div class="text-body-2 mb-2">
              <v-icon size="small" class="mr-1">fa-network-wired</v-icon>
              {{ formatNetworkInfo() }}
            </div>
            
            <!-- Metadata -->
            <div class="text-caption text--secondary">
              <v-icon size="x-small" class="mr-1">fa-clock</v-icon>
              {{ formatTimestamp() }}
              <span class="mx-2">|</span>
              <v-icon size="x-small" class="mr-1">fa-puzzle-piece</v-icon>
              {{ alert.module }}
              <span v-if="alert.category" class="mx-2">|</span>
              <span v-if="alert.category">{{ alert.category }}</span>
            </div>
          </v-col>
          
          <v-col cols="12" md="4" class="text-right">
            <alert-actions
              :alert="alert"
              @acknowledge="$emit('acknowledge', alert)"
              @escalate="$emit('escalate', alert)"
              @dismiss="$emit('dismiss', alert)"
            ></alert-actions>
          </v-col>
        </v-row>
      </v-card-text>
    </v-card>
  `,
  props: {
    alert: {
      type: Object,
      required: true
    }
  },
  data() {
    return {
      isHovered: false
    };
  },
  computed: {
    cardClasses() {
      return {
        'mb-3': true,
        'alert-acknowledged': this.alert.acknowledged,
        'alert-escalated': this.alert.escalated,
        'alert-dismissed': this.alert.dismissed
      };
    },
    severityColor() {
      const severity = (this.alert.severityLabel || '').toLowerCase();
      if (severity.includes('high') || severity.includes('critical')) return 'error';
      if (severity.includes('medium')) return 'warning';
      return 'info';
    },
    severityTextColor() {
      return 'white';
    }
  },
  methods: {
    formatNetworkInfo() {
      const src = this.alert.sourceIp ? 
        `${this.alert.sourceIp}${this.alert.sourcePort ? ':' + this.alert.sourcePort : ''}` : 
        'Unknown';
      const dst = this.alert.destIp ? 
        `${this.alert.destIp}${this.alert.destPort ? ':' + this.alert.destPort : ''}` : 
        'Unknown';
      return `${src} → ${dst}`;
    },
    
    formatTimestamp() {
      if (!this.alert.timestamp) return 'Unknown time';
      
      const date = new Date(this.alert.timestamp);
      const now = new Date();
      const diffMs = now - date;
      const diffMins = Math.floor(diffMs / 60000);
      const diffHours = Math.floor(diffMs / 3600000);
      const diffDays = Math.floor(diffMs / 86400000);
      
      if (diffMins < 1) return 'Just now';
      if (diffMins < 60) return `${diffMins} minute${diffMins !== 1 ? 's' : ''} ago`;
      if (diffHours < 24) return `${diffHours} hour${diffHours !== 1 ? 's' : ''} ago`;
      if (diffDays < 7) return `${diffDays} day${diffDays !== 1 ? 's' : ''} ago`;
      
      return date.toLocaleString();
    }
  }
  }
});

// Register CSS
if (!document.getElementById('alert-card-styles')) {
  const style = document.createElement('style');
  style.id = 'alert-card-styles';
  style.textContent = `
    .alert-acknowledged {
      opacity: 0.8;
    }
    .alert-escalated {
      border-left: 4px solid var(--v-warning-base);
    }
    .alert-dismissed {
      opacity: 0.6;
    }
  `;
  document.head.appendChild(style);
}