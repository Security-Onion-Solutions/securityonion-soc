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
      @click="handleClick"
      style="cursor: pointer"
    >
      <v-card-text>
        <v-row align="center">
          <v-col cols="auto" v-if="selectionMode">
            <v-checkbox
              :model-value="selected"
              @update:model-value="$emit('select', alert)"
              @click.stop
              density="compact"
              hide-details
            ></v-checkbox>
          </v-col>
          <v-col :cols="selectionMode ? '' : '12'" :md="selectionMode ? '7' : '8'">
            <!-- Alert Header -->
            <div class="d-flex align-center mb-2">
              <v-chip
                v-if="alert['rule.category']"
                size="small"
                variant="outlined"
                color="blue-grey"
                class="mr-2"
              >
                <v-icon start size="x-small">fa-tag</v-icon>
                {{ alert['rule.category'] }}
              </v-chip>
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
              >
                <v-icon start size="x-small">fa-briefcase</v-icon>
                Escalated
              </v-chip>
            </div>
            
            <!-- Rule Name -->
            <div class="text-h6 mb-1">{{ alert.ruleName }}</div>
            
            <!-- Network Info or Host Info -->
            <div class="text-body-2 mb-2">
              <v-icon size="small" class="mr-1">{{ getInfoIcon() }}</v-icon>
              {{ formatConnectionInfo() }}
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
    },
    selectionMode: {
      type: Boolean,
      default: false
    },
    selected: {
      type: Boolean,
      default: false
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
        'alert-escalated': this.alert.escalated
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
    handleClick() {
      // Always emit click for showing details
      // Selection is handled by the checkbox itself
      this.$emit('click', this.alert);
    },
    getInfoIcon() {
      // Check if this is a host-based alert (YARA/Sigma/OSSEC)
      if (this.isHostBasedAlert()) {
        return 'fa-laptop';
      }
      return 'fa-network-wired';
    },
    isHostBasedAlert() {
      // Check multiple indicators for host-based alerts
      return this.alert.isHostBased || 
             (!this.alert.sourceIp && !this.alert.destIp) ||
             (this.alert.module === 'yara' || this.alert.module === 'sigma' || this.alert.module === 'ossec');
    },
    formatConnectionInfo() {
      // For host-based alerts, show agent and host info
      if (this.isHostBasedAlert()) {
        // Check both flattened and event_data nested fields
        const agentName = this.alert.rawData?.['agent.name'] || 
                         this.alert.rawData?.['observer.name'] || 
                         this.alert.rawData?.['event_data.agent.name'] ||
                         this.alert.rawData?.['event_data.observer.name'] ||
                         'Unknown Agent';
        const hostName = this.alert.rawData?.['host.name'] || 
                        this.alert.rawData?.['event_data.host.name'] ||
                        '';
        
        // For YARA/Strelka alerts, show file info if available
        if (this.alert.module === 'strelka' || this.alert.module === 'yara') {
          const fileName = this.alert.rawData?.['file.name'];
          const fileHash = this.alert.rawData?.['hash.md5'] || this.alert.rawData?.['hash.sha256'];
          
          if (fileName) {
            // Extract just the filename from the path
            const shortName = fileName.split('/').pop();
            return `Agent: ${agentName} • File: ${shortName}`;
          } else if (fileHash) {
            return `Agent: ${agentName} • Hash: ${fileHash.substring(0, 12)}...`;
          }
        }
        
        if (hostName) {
          return `Agent: ${agentName} • Host: ${hostName}`;
        }
        return `Agent: ${agentName}`;
      }
      
      // For network alerts, show source → destination
      return this.formatNetworkInfo();
    },
    formatNetworkInfo() {
      let src = this.alert.sourceIp ? 
        `${this.alert.sourceIp}${this.alert.sourcePort ? ':' + this.alert.sourcePort : ''}` : 
        'Unknown';
      let dst = this.alert.destIp ? 
        `${this.alert.destIp}${this.alert.destPort ? ':' + this.alert.destPort : ''}` : 
        'Unknown';
      
      // Add hostnames if reverse lookup is enabled
      if (this.$root.enableReverseLookup) {
        const srcHostname = this.$root.pickHostname(this.alert.sourceIp);
        const dstHostname = this.$root.pickHostname(this.alert.destIp);
        
        if (srcHostname) {
          src += ` (${srcHostname})`;
        }
        if (dstHostname) {
          dst += ` (${dstHostname})`;
        }
      }
      
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
  `;
  document.head.appendChild(style);
}