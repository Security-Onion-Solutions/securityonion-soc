// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

loadPageTemplate('page-colors', 'pages/colors.html');

routes.push({ path: '/colors', name: 'colors', component: {
  template: '#page-colors',
  data() { return {
    i18n: this.$root.i18n,
    themeNames: ['dark', 'light'],

    // Foreground text tokens rendered as class "text-<token>", grouped by where they occur.
    // Colors that production only applies to icons belong in iconGroups instead — WCAG's
    // 4.5:1 text rule doesn't apply to icon glyphs.
    textGroups: {
      // Status/semantic text; modern.css remaps success/primary/error/info/warning to
      // the alt* variants.
      semantic: ['text', 'success', 'primary', 'error', 'info', 'warning'],
      // getContextColor() — context-length stop-light text in the assistant drawer.
      context: ['success', 'amber', 'warning', 'error'],
      // App bar text on nav_background.
      nav: ['nav'],
    },

    // Foreground colors rendered as <v-icon :color>, matching production's icon-only usage.
    iconGroups: {
      // colorSeverity() — severity coloring on hunt/alert row bell icons.
      severity: ['yellow', 'orange-darken-1', 'red-lighten-1', 'red-darken-4', 'icon'],
      // getToolStatusColor() — tool status icons on assistant tool cards (tool-use-card.html).
      toolStatus: ['info', 'warning', 'success', 'error'],
      // Static v-icon colors on the hunt action menus (hunt.html).
      actions: ['green-darken-1', 'red-lighten-1', 'blue-darken-1', 'purple-lighten-1',
                'pink-lighten-3', 'yellow-darken-2', 'orange-darken-2'],
    },

    // Chip color tokens passed to <v-chip :color> exactly as production does, with the
    // v-chip variants each group renders with in production. lightRemap mirrors any
    // per-theme color substitution the producing function makes.
    chipGroups: {
      // colorNodeStatus()/colorJobStatus(); 'gray' is returned verbatim by those functions.
      // Tonal on jobs.html, flat on grid.html/gridmembers.html.
      status: { colors: ['success', 'error', 'warning', 'info', 'gray'], variants: ['tonal', 'flat'] },
      // getToolStatusColor() — assistant tool chips are flat (tool-use-card.html).
      toolStatus: { colors: ['info', 'warning', 'success', 'error'], variants: ['flat'] },
      // colorLicenseStatus() — flat in the footer (index.html), tonal on terms.html.
      license: { colors: ['white', 'success', 'error', 'warning', 'info'], variants: ['flat', 'tonal'] },
      // colorizeChip() TLP/PAP passthrough; in the light theme it substitutes white->secondary,
      // red->error, and green->success, so those pairs never render in light mode.
      tlp: { colors: ['red', 'amber', 'green', 'white'], variants: ['tonal', 'outlined'],
             lightRemap: { white: 'secondary', red: 'error', green: 'success' } },
      // colorType()/colorFlag() for packets (job.html); 'accent' omitted (undefined in both themes).
      packet: { colors: ['cyan', 'teal-lighten-2', 'secondary', 'primary', 'success', 'error', 'warning'], variants: ['tonal'] },
      // Hunt sortBy chip (hunt.html).
      hunt: { colors: ['secondary'], variants: ['tonal'] },
    },

    // Static v-btn color= attributes, plus the dynamic hunt button colors (hunt.html).
    buttonColors: ['primary', 'error', 'warning', 'success', 'text_button', 'light-green', 'icon'],
    alertTypes: ['info', 'warning', 'error'],

    // Surfaces (theme color names, rendered as "bg-<name>") and which foreground groups
    // realistically appear on each. Per-surface progress lists mirror formatLinearColor()
    // on grid.html tables and the secondary-lighten-1 bar in the assistant drawer.
    // linkColor mirrors .v-footer a (app.css), which forces the link color on
    // nav_background with !important; the page applies it as an inline style since
    // there is no v-footer here and utility classes lose to the global link rule.
    // row_stripe/row_hover are intentionally not surfaces here: they are subtle shades of
    // table_background, and repeating every foreground on each shade just multiplies
    // marginal findings; they still appear in the all-theme-colors swatch section.
    //
    // exceptions lists combinations this page generates that never occur in production, so
    // axe violations on them would be meaningless. Entries are "kind:value" where kind is
    // text, icon, chip, button, alert, or progress. Chip values are "color/variant"
    // (matched after the light-theme remap); a segment of '*' or an omitted trailing
    // segment matches anything: 'chip:purple/outlined' excepts one chip, 'chip:purple'
    // all purple chips, 'chip:*/outlined' all outlined chips.
    surfaces: [
      { name: 'background',        text: ['semantic'],            icons: ['actions'],    chips: ['license', 'tlp', 'hunt'], buttons: true, alerts: true, links: true, labelChip: true, primaryButtonIcon: true,
        exceptions: [
          // Flat chips here would be license chips, but flat license chips only render
          // in the footer (index.html) — the nav_background section covers them.
          'chip:*/flat',
          // Success-colored text only appears on drawer_background stat pills: the
          // assistant context stoplight (getContextColor) and the hunt detection engine
          // status (getDetectionEngineStatusClass).
          'text:success',
        ] },
      { name: 'nav_background',    text: ['nav'],                                        chips: ['license'],                links: true, linkColor: 'nav_background_link', gridSelector: true,
        exceptions: [
          // The footer license chips are always flat (index.html); the tonal license
          // chip lives on terms.html, covered by the background section.
          'chip:*/tonal',
        ] },
      // drawer_background: every generated combo is real in the assistant/nav drawers.
      { name: 'drawer_background', text: ['semantic', 'context'], icons: ['toolStatus'], chips: ['toolStatus'],             links: true, progress: ['secondary-lighten-1'],
        exceptions: [] },
      { name: 'table_background',  text: ['semantic'],            icons: ['severity'],   chips: ['status', 'packet'],       links: true, progress: ['success', 'info', 'warning', 'error'],
        exceptions: [
          // Tables only color icons, chips, and progress bars; semantic *text* never
          // renders there. 'text' (default) stays, and 'primary' stays because the nav
          // drawer's active v-list item is primary text on a v-list, which CSS paints
          // table_background (app.css .v-list-item--active, modern.css .v-list).
          'text:success', 'text:error', 'text:info', 'text:warning',
          // colorType() returns Vuetify-2-style "teal lighten-2" (job.js), which Vuetify 3
          // ignores — production DHCP packet chips actually render colorless. Fix job.js
          // to 'teal-lighten-2' and remove this exception to restore coverage.
          'chip:teal-lighten-2/tonal',
        ] },
    ],
  }},
  methods: {
    flattenGroups(groups, names) {
      const seen = new Set();
      const out = [];
      (names || []).forEach((name) => {
        (groups[name] || []).forEach((token) => {
          if (!seen.has(token)) {
            seen.add(token);
            out.push(token);
          }
        });
      });
      return out;
    },
    // True when the surface's exceptions list matches kind:value. Values with multiple
    // segments (chip color/variant) match per-segment; '*' or an omitted trailing
    // segment matches anything.
    excluded(surface, kind, value) {
      const valueParts = value.split('/');
      return (surface.exceptions || []).some((entry) => {
        const sep = entry.indexOf(':');
        if (sep === -1 || entry.slice(0, sep) !== kind) return false;
        const entryParts = entry.slice(sep + 1).split('/');
        if (entryParts.length > valueParts.length) return false;
        return valueParts.every((part, i) =>
          i >= entryParts.length || entryParts[i] === '*' || entryParts[i] === part);
      });
    },
    textTokensFor(surface) {
      return this.flattenGroups(this.textGroups, surface.text)
        .filter((token) => !this.excluded(surface, 'text', token));
    },
    // Each surface section is framed in the opposite theme's background color so the
    // container itself always contrasts strongly with its parent, keeping contrast
    // scanners focused on the foreground samples instead of background-on-background
    // seams. Rendered as an inline style since the frame must not inherit the current
    // theme's CSS variables.
    oppositeBackground(themeName) {
      const opposite = themeName === 'dark' ? 'light' : 'dark';
      const theme = this.$root.theme || {};
      const themes = (theme.themes && theme.themes.value) || theme.themes || {};
      const colors = (themes[opposite] && themes[opposite].colors) || {};
      return colors.background || (opposite === 'dark' ? '#000000' : '#ffffff');
    },
    iconTokensFor(surface) {
      return this.flattenGroups(this.iconGroups, surface.icons)
        .filter((token) => !this.excluded(surface, 'icon', token));
    },
    // Returns { color, variant } pairs, deduped, covering every variant each chip group
    // uses in production, with per-theme color substitutions applied.
    chipsFor(surface, themeName) {
      const seen = new Set();
      const out = [];
      (surface.chips || []).forEach((name) => {
        const group = this.chipGroups[name];
        if (!group) return;
        group.variants.forEach((variant) => {
          group.colors.forEach((color) => {
            if (themeName === 'light' && group.lightRemap && group.lightRemap[color]) {
              color = group.lightRemap[color];
            }
            const key = color + '/' + variant;
            if (!seen.has(key) && !this.excluded(surface, 'chip', key)) {
              seen.add(key);
              out.push({ color: color, variant: variant });
            }
          });
        });
      });
      return out;
    },
    buttonsFor(surface) {
      return this.buttonColors.filter((color) => !this.excluded(surface, 'button', color));
    },
    alertsFor(surface) {
      return this.alertTypes.filter((type) => !this.excluded(surface, 'alert', type));
    },
    progressFor(surface) {
      return (surface.progress || []).filter((color) => !this.excluded(surface, 'progress', color));
    },
    // Enumerates the configured theme color names so colors added to the theme in app.js
    // show up in the swatch section without editing this page. Skips the on-* and
    // lighten/darken keys Vuetify derives from the configured colors, plus theme keys
    // that are only ever used as foregrounds in the app, never as backgrounds.
    themeColorNames(themeName) {
      const foregroundOnly = ['altprimary', 'altsuccess', 'altinfo', 'alterror',
                              'text', 'icon', 'nav', 'nav_background_link', 'text_button',
                              'button_icon_color'];
      const theme = this.$root.theme || {};
      const themes = (theme.themes && theme.themes.value) || theme.themes || {};
      const colors = (themes[themeName] && themes[themeName].colors) || {};
      return Object.keys(colors)
        .filter((name) => !name.startsWith('on-') && !/-(lighten|darken)-\d+$/.test(name))
        .filter((name) => !foregroundOnly.includes(name));
    },
  }
}});
