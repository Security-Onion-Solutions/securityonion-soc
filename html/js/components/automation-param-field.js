// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

loadPageTemplate('component-automation-param-field', 'pages/automation-param-field.html');

// One paramSchema property of an automation kind; edits write into `params`.
components.push({
  name: "automation-param-field", component: {
    template: '#component-automation-param-field',
    props: {
      field: { type: Object, required: true },
      params: { type: Object, required: true },
      readonly: { type: Boolean, default: false },
    },
    methods: {
      label() {
        return this.field.required ? this.field.label + ' *' : this.field.label;
      },
      // A blank runs with the default, so keep it visible.
      placeholder() {
        return this.field.default === undefined ? '' : String(this.field.default);
      },
    },
  }
});
