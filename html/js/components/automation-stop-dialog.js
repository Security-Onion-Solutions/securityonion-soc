// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

loadPageTemplate('component-automation-stop-dialog', 'pages/automation-stop-dialog.html');

// The confirmation Stop opens on Agent Studio and Agent Monitor. automationEnabled is null once
// the automation has been deleted, which leaves nothing to turn off.
components.push({
  name: "automation-stop-dialog", component: {
    template: '#component-automation-stop-dialog',
    props: {
      modelValue: { type: Boolean, default: false },
      automationName: { type: String, default: '' },
      automationEnabled: { type: Boolean, default: null },
    },
    emits: ['stop', 'update:modelValue'],
    data() {
      return {
        i18n: this.$root?.i18n || {},
      };
    },
    methods: {
      title() {
        return this.$root.replaceActionVar(this.i18n.automationStopDialogTitle, 'name', this.automationName);
      },
      canTurnOff() {
        return this.automationEnabled === true;
      },
      cancel() {
        this.$emit('update:modelValue', false);
      },
      stop(disable) {
        this.$emit('stop', { disable });
        this.$emit('update:modelValue', false);
      },
    },
  }
});
