// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

// Simple Alerts page methods: rendering a detection's rule text. Highlighting uses the
// Prism grammars the detection page already relies on, so the colors come from the
// prism-custom stylesheet that app.js swaps with the theme. Merged into the component's
// methods by simplealerts.js.

globalThis.SimpleAlertsRules = (function() {
  // event.module names the detection engine; both its own name and the rule language
  // it carries appear in the wild, so map from either.
  const LANGUAGE_BY_MODULE = {
    'suricata': 'suricata',
    'sigma': 'yaml',
    'elastalert': 'yaml',
    'yara': 'yara',
    'strelka': 'yara',
  };

  return {
    ruleLanguage(alert) {
      if (!alert) return null;
      return LANGUAGE_BY_MODULE[String(alert.module || '').toLowerCase()] || null;
    },

    hasRuleText(alert) {
      return !!(alert && alert.ruleText);
    },

    // Rule source must render exactly as written, so markup in it is escaped rather
    // than sanitized: sanitizing would drop an <img> tag's attributes but still render
    // the tag, silently changing what the rule appears to say.
    escapeRuleText(text) {
      return String(text)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
    },

    // Returns highlighted markup for v-html. Prism escapes the source it is given; the
    // result is sanitized as well, since rule text is operator-supplied content.
    highlightRule(alert) {
      if (!this.hasRuleText(alert)) return '';

      const language = this.ruleLanguage(alert);
      const grammar = language && typeof Prism !== 'undefined' ? Prism.languages[language] : null;
      if (!grammar) {
        // No grammar for this engine; render it literally rather than guessing.
        return this.escapeRuleText(alert.ruleText);
      }

      return DOMPurify.sanitize(Prism.highlight(alert.ruleText, grammar, language));
    },

    // Prism's stylesheet keys off a language-* class on the <pre>/<code>.
    ruleLanguageClass(alert) {
      const language = this.ruleLanguage(alert);
      return language ? 'language-' + language : '';
    },
  };
})();
