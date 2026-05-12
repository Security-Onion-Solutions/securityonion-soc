// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

const routes = [];
const components = [];
const iconSets = [];
const templatePromises = [];
const directives = [];

const LICENSE_STATUS_ACTIVE = "active";
const LICENSE_STATUS_EXCEEDED = "exceeded";
const LICENSE_STATUS_EXPIRED = "expired";
const LICENSE_STATUS_INVALID = "invalid";
const LICENSE_STATUS_PENDING = "pending";
const LICENSE_STATUS_UNPROVISIONED = "unprovisioned";

const SECURITYONION_PRO = "Security Onion Pro";

const LICENSE_EXPIRES_SOON_DAYS = 45;

const SUBGRID_DISABLED_ROUTES = ['home','settings','assistant','aimetrics'];
const LOCAL_GRID_ID = ''

const USER_PASSWORD_LENGTH_MIN = 8;
const USER_PASSWORD_LENGTH_MAX = 72;
const USER_PASSWORD_INVALID_RX = /["'$&!]/;

const MAX_OVERRIDE_NOTE_LENGTH = 150;

const SYSTEM_USER_ID = '00000000-0000-0000-0000-000000000000';
const AGENT_USER_ID = '00000000-0000-0000-0000-000000000001';

function moveAriaToPrismTextarea(wrapperEl) {
  const textarea = wrapperEl.querySelector('.prism-editor__textarea');
  if (!textarea) return;
  ['aria-label', 'aria-labelledby', 'aria-describedby'].forEach((attr) => {
    const value = wrapperEl.getAttribute(attr);
    if (value) {
      textarea.setAttribute(attr, value);
      wrapperEl.removeAttribute(attr);
    }
  });
}

if (typeof global !== 'undefined') {
  global.routes = routes;
  global.components = components;
  global.iconSets = iconSets;
  global.templatePromises = templatePromises;
  global.directives = directives;
  global.MAX_OVERRIDE_NOTE_LENGTH = MAX_OVERRIDE_NOTE_LENGTH;
}

$(document).ready(function () {
  Promise.all(templatePromises).then(() => {
    const _i18n = i18n.getLocalizedTranslations(navigator.language);
    
    let iSets = {};
    for (const iconSet of iconSets) {
      const comp = Vue.defineComponent(iconSet.component);
      iSets[iconSet.name] = { component: comp };
    }

    const vuetify = Vuetify.createVuetify({
      defaults: {
        VCheckbox: {
          trueIcon: 'mb-1 fa-square-check',
          falseIcon: 'mb-1 fa-regular fa-square',
          indeterminateIcon: 'mb-1 fa-square-minus'
        },
        VChip: {
          closeIcon: 'fa-xmark va-baseline',
        },
        VCombobox: {
          menuIcon: 'fas fa-caret-down',
          variant: 'outlined',
        },
        VDataTable: {
          firstIcon: 'fa-backward-step',
          prevIcon: 'fa-chevron-left',
          nextIcon: 'fa-chevron-right',
          lastIcon: 'fa-forward-step',
        },
        VFileInput: {
          prependIcon: 'fa-paperclip',
          variant: 'outlined',
        },
        VIcon: {
          class: 'fa',
        },
        VSelect: {
          variant: 'outlined',
          density: 'compact',
          menuIcon: 'fas fa-caret-down',
        },
        VSwitch: {
          color: 'primary'
        },
        VTextarea: {
          variant: 'outlined',
          density: 'compact',
        },
        VTextField: {
          variant: 'outlined',
          density: 'compact',
          clearIcon: 'fas fa-circle-xmark',
        },
        VToolbar: {
          class: 'theme-background-lighten-1',
        },
        VTreeview: {
          collapseIcon: '',
          expandIcon: 'fas fa-caret-right',
        },
      },
      icons: {
        defaultSet: 'fa',
        sets: {
          fa: {
            component: Vuetify.components.VClassIcon,
          },
          ...iSets,
        }
      },
      theme: {
        defaultTheme: 'dark',
        variations: {
          colors: ['primary', 'secondary', 'drawer_background', 'background'],
          lighten: 3,
          darken: 3,
        },
        themes: {
          light: {
            dark: false,
            colors: {
              success: '#3A833C',
              lightsuccess: '#3A833C',
              primary: '#0B78D0',
              lightprimary: '#096DBC',
              secondary: '#424242',
              info: '#0B78D0',
              error: '#EB0000',
              lighterror: '#EB0000',
              nav_background: '#000000',
              nav: '#ffffff',
              table_background: '#fafafa',
              drawer_background: '#f0f0f0',
              background: '#ffffff',
              text: '#000000',
              icon: '#7f7f7f',
              button_icon_color: '#ffffff',
              row_stripe: '#e6e6e6',
              row_hover: '#e2e2e2',
              text_button: '#e4e4e4',
            },
          },
          dark: {
            dark: true,
            colors: {
              success: '#3A833C',
              lightsuccess: '#49A74B',
              primary: '#007CAD',
              lightprimary: '#039CD8',
              secondary: '#2C3347',
              info: '#0B78D0',
              error: '#EB0000',
              lighterror: '#FF5757',
              nav_background: '#000000',
              nav: '#ffffff',
              table_background: '#222a3f',
              drawer_background: '#252B3B',
              background: '#0B1019',
              text: '#ffffff',
              icon: '#8B96A8',
              button_icon_color: '#ffffff',
              row_stripe: '#2d2d2d',
              row_hover: '#2a3452',
              text_button: '#3f4452',
            },
          },
        },
      },
    });
    const router = VueRouter.createRouter({ routes, history: VueRouter.createWebHashHistory() });

    const comp = {
      el: '#app',
      router: router,
      data: () => {
        return {
          timestamp: Date.now(),
          theme: Vuetify.useTheme(),
          i18n: _i18n,
          loading: false,
          loadingCancelCallback: null,
          error: false,
          warning: false,
          info: false,
          tip: false,
          disclaimer: false,
          errorMessage: "",
          warningMessage: "",
          infoMessage: "",
          tipMessage: "",
          disclaimerMessage: "",
          disclaimerTitle: "",
          disclaimerClose: "",
          disclaimerStorageKey: "",
          tipTimeout: 6000,
          currentTipTimeout: 6000,
          warningTimeout: 30000,
          errorTimeout: 120000,
          toolbar: null,
          wsUrl: (location.protocol == 'https:' ? 'wss://' : 'ws://') + location.host + location.pathname + 'ws',
          apiUrl: location.origin + location.pathname + 'api/',
          authUrl: '/auth/self-service/',
          settingsUrl: null,
          version: '0.0.0',
          elasticVersion: '0.0.0',
          papi: null,
          connectionTimeout: 300000,
          wsConnectionTimeout: 15000,
          socket: null,
          subscriptions: [],
          parameters: {},
          parametersLoaded: false,
          parameterCallback: null,
          parameterSection: null,
          chartsInitialized: false,
          editorInitialized: false,
          mermaidInitialized: false,
          tools: [],
          casesEnabled: false,
          detectionsEnabled: false,
          subtitle: '',
          connected: false,
          reconnecting: false,
          users: [],
          cacheRefreshIntervalMs: 300000,
          loadServerSettingsTime: 0,
          user: null,
          username: '',
          maximizedParent: null,
          maximizedOrigWidth: null,
          maximizedOrigHeight: null,
          maximizedCancelFn: null,
          licenseKey: null,
          licenseStatus: null,
          ip2host: {},
          securitySettingsAlreadyChecked: false,
          forceUserOtp: false,
          subgrids: [],
          gridInfo: {},
          selectedGridId: LOCAL_GRID_ID,
          subgridSelectorEnabled: false,
          statusByGridId: {},
          exportNodeId: null,
          customReports: {},
          FEAT_RPT: 'rpt',
          FEAT_TTR: 'ttr',
          FEAT_OAI: 'oai',
          validators: {
            required: value => !!value || _i18n.required,
            number: value => (!isNaN(+value) && Number.isInteger(parseFloat(value))) || _i18n.required,
            hours: value => (!value || /^\d{1,4}(\.\d{1,4})?$/.test(value)) || _i18n.invalidHours,
            shortLengthLimit: value => (value.length < 100) || _i18n.required,
            longLengthLimit: value => (encodeURI(value).split(/%..|./).length - 1 < 10000000) || _i18n.required,
            noteLengthLimit: value => (value.length <= MAX_OVERRIDE_NOTE_LENGTH) || _i18n.ruleMaxLen,
            fileNotEmpty: value => (value == null || value.size > 0) || _i18n.fileEmpty,
            fileRequired: value => (value != null && value.length != 0) || _i18n.required,
            cidrFormat: value => (!value ||
              /^!?\$[a-z_][a-z0-9_]*$/i.test(value) ||
              /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\/(3[0-2]|[12]\d|\d)$/.test(value) ||
              /^((([0-9a-f]{1,4}:){7}([0-9a-f]{1,4}|:))|(([0-9a-f]{1,4}:){6}(:[0-9a-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9a-f]{1,4}:){5}(((:[0-9a-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9a-f]{1,4}:){4}(((:[0-9a-f]{1,4}){1,3})|((:[0-9a-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9a-f]{1,4}:){3}(((:[0-9a-f]{1,4}){1,4})|((:[0-9a-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9a-f]{1,4}:){2}(((:[0-9a-f]{1,4}){1,5})|((:[0-9a-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9a-f]{1,4}:){1}(((:[0-9a-f]{1,4}){1,6})|((:[0-9a-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9a-f]{1,4}){1,7})|((:[0-9a-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*(\/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8]))$/i.test(value)
            ) || _i18n.invalidCidrOrVar,
            lowercase: value => !value || value.toLowerCase() == value || _i18n.lowercaseRequired,
            minPassLen: value => (!value || value.length >= USER_PASSWORD_LENGTH_MIN) || _i18n.ruleMinLen,
            maxPassLen: value => (!value || value.length <= USER_PASSWORD_LENGTH_MAX) || _i18n.ruleMaxLen,
            badPassChars: value => (!value || !value.match(USER_PASSWORD_INVALID_RX)) || _i18n.rulePassBadChars,
            minLength: limit => value => (value && value.length >= limit) || _i18n.ruleMinLen,
            maxLength: limit => value => (!value || value.length < limit) || _i18n.ruleMaxLen,
            fileSizeLimit: (maxBytes, formatFn) => value =>
              (value == null || value.size < maxBytes) || _i18n.fileTooLarge.replace("{maxUploadSizeBytes}", formatFn(maxBytes)),
            matches: expected => value => (!!value && value == expected) || _i18n.passwordMustMatch,
          },
          ruleValidators: {
            sigma: [
              { pattern: /^id:\s*[^$]+?$/m, message: _i18n.invalidDetectionElastAlertMissingID, match: false },
            ],
            suricata: [
              { pattern: /\n/, message: _i18n.invalidDetectionSuricataNewLine, match: true },
              { pattern: /sid:\s?(["']?)\d+\1;/, message: _i18n.invalidDetectionSuricataMissingSID, match: false },
            ],
            yara: [
              { pattern: /^rule\s+{/, message: _i18n.invalidDetectionStrelkaMissingRuleName, match: true },
              { pattern: /^rule\s+[a-zA-Z_][a-zA-Z0-9_]*/, message: _i18n.invalidDetectionStrelkaInvalidRuleName, match: false },
              { pattern: /condition:/m, message: _i18n.invalidDetectionStrelkaMissingCondition, match: false },
            ],
          },
        }
      },
      watch: {
        '$vuetify.theme.current.dark': 'saveTheme',
        'toolbar': 'saveToolbar',
        '$route': [
          'onLocationUpdated',
          'closeDisclaimerOnNav'
        ],
        'selectedGridId': 'onGridSelected',
      },
      methods: {
        getMetricsUrl() {
          for (var i = 0; i < this.tools.length; i++) {
            const tool = this.tools[i];
            if (tool.name == "toolInfluxDb") {
              return tool.link;
            }
          }
          return "/";
        },
        target(def) {
          if (localStorage['settings.flags.testing'] === 'true') {
            return "_self";
          }
          return def;
        },
        onGridSelected() {
          const params = { ...this.$route.query };
          params.gridId = this.selectedGridId;
          this.$router.push({ path: this.$route.path, query: params });
        },
        checkSubgridSelectorEnabled(loc) {
          if (SUBGRID_DISABLED_ROUTES.includes(loc.name)) {
            this.selectedGridId = LOCAL_GRID_ID;
            this.subgridSelectorEnabled = false;
          } else {
            this.subgridSelectorEnabled = true;
          }
          return this.subgridSelectorEnabled;
        },
        onLocationUpdated(newLocation, oldLocation) {
          if (!this.checkSubgridSelectorEnabled(newLocation)) return;
          const gridId = newLocation.query['gridId'];
          if (gridId) {
            this.selectedGridId = gridId;
          }
        },
        formatActionContent(content, event, field, value, uriEncode = true) {
          if (!content) return null;

          content = this.replaceActionVar(content, "eventId", event["soc_id"], uriEncode)
          content = this.replaceActionVar(content, "field", field, uriEncode)
          content = this.replaceActionVar(content, "value", value, uriEncode)
          content = this.replaceActionVar(content, "eventJson", JSON.stringify(event))
          content = this.replaceActionVar(content, "gridId", this.selectedGridId, uriEncode)

          const fields = this.getDynamicActionFieldNames(content);
          const route = this;
          if (fields && fields.length > 0) {
            fields.forEach(function(field) {
              value = event[field];
              content = route.replaceActionVar(content, ":" + field, value, uriEncode)
            });
          }
          return content;
        },
        performAction(event, action) {
          if (action && !action.background) return true;
          const options = action.options ? action.options : { mode: 'no-cors' };
          options.method = action.method;
          if (action.method != 'GET') {
            options.body = action.bodyFormatted;
          }
          action.target = localStorage['settings.flags.testing'] !== 'true' ? action.target : '_self';
          const route = this;
          fetch(action.linkFormatted, options)
          .then(data => {
            var link = action.backgroundSuccessLinkFormatted;
            if (link) {
              if (data.status != null) {
                link = route.replaceActionVar(link, "responseCode", data.status, true)
              }
              if (data.statusText != null) {
                link = route.replaceActionVar(link, "responseStatus", data.statusText, true)
              }
              window.open(link, action.target);
            } else {
              route.$root.showTip(route.i18n.actionSuccess + route.$root.localizeMessage(action.name));
            }
          })
          .catch((error) => {
            var link = action.backgroundFailureLinkFormatted;
            if (link) {
              link = route.replaceActionVar(link, "error", error.message, true)
              window.open(link, action.target);
            } else {
              route.$root.showTip(route.i18n.actionFailure + route.$root.localizeMessage(action.name));
            }
          });
          return true;
        },
        base64encode(content) {
          try {
            content = btoa(content);
          } catch (e) {
            console.log("Failed to base64 encode content: " + e);
          }
          return content;
        },
        escape(content) {
          if (content.replace) {
            try {
              content = content.replace(/\\/g, "\\\\");
              content = content.replace(/\"/g, "\\\"");
            } catch (e) {
              console.log("Failed to escape content: " + e);
            }
          }
          return content
        },
        processAncestors(content) {
          content = content.toString();
          if (content.replace) {
            try {
              content = content.replace(/,/g, "\" OR process.entity_id:\"");
            } catch (e) {
              console.log("Failed to set process ancestors for content: " + e);
            }
          }
          return content
        },
        replaceActionVar(content, field, value, uriEncode) {
          if (value === undefined || value == null) return content;

          var encode = function(input) {
            if (uriEncode) {
              return encodeURIComponent(input);
            }
            return input;
          };

          content = content.replaceAll("{" + field + "}", encode(value));
          if (content.indexOf("{" + field + "|base64}") !== -1)
            content = content.replaceAll("{" + field + "|base64}", encode(this.base64encode(value)));
          content = content.replaceAll("{" + field + "|escape}", encode(this.escape(value)));
          if (content.indexOf("{" + field + "|escape|base64}") !== -1)
            content = content.replaceAll("{" + field + "|escape|base64}", encode(this.base64encode(this.escape(value))));
          content = content.replaceAll("{" + field + "|processAncestors}", encode(this.processAncestors(value)));
          return content;
        },
        copyToClipboard(data, style) {
          // Convert entire item into text
          if (style == 'json') {
            data = JSON.stringify(data);
          } else if (style == 'kvp') {
            var text = "";
            for (const prop in data) {
              text += prop + ": " + data[prop] + "\n";
            }
            data = text;
          }

          navigator.clipboard.writeText(data);
        },
        findEligibleActionLinkForEvent(action, event) {
          if (action && action.links) {
            for (var idx = 0; idx < action.links.length; idx++) {
              const link = action.links[idx];

              if (this.isActionLinkEligibleForEvent(link, event)) {
                return link;
              }
            }
          }
          return null;
        },
        isActionLinkEligibleForEvent(link, event) {
          var eligible = true;
          eligible &= (link.indexOf("{eventId}") == -1 || event['soc_id']);
          const fields = this.getDynamicActionFieldNames(link);
          if (fields && fields.length > 0) {
            fields.forEach(function(field) {
              value = event[field];
              eligible &= value != undefined && value != null;
            });
          }
          return eligible;
        },
        getDynamicActionFieldNames(url) {
          const fields = [];
          const matches = url.matchAll(/\{:([@a-zA-Z0-9_.]+?)(\|.*?)?\}/g);
          for (const match of matches) {
            if (match.length > 1) {
              fields.push(match[1]);
            }
          }
          return fields;
        },
        log(msg) {
          console.log(moment().format() + " | " + msg);
        },
        redirectIfAuthCompleted() {
          if (!location.pathname.startsWith("/login")) {
            destUri = this.getCookie("AUTH_REDIRECT");
            if (destUri) {
              this.deleteCookie("AUTH_REDIRECT");
              if (destUri != "/" &&
                  !destUri.includes(".?v=") &&
                  !destUri.endsWith(".ico") &&
                  !destUri.endsWith(".js") &&
                  !destUri.endsWith(".css") &&
                  !destUri.endsWith(".png") &&
                  !destUri.endsWith(".svg") &&
                  !destUri.endsWith(".jpg") &&
                  !destUri.endsWith(".gif")) {
                this.log("Redirecting to auth destination: " + destUri);
                location.pathname = destUri;
                return true;
              }
            }
          }
          return false;
        },
        redirectRoute() {
          const redirectPage = this.getRedirectPage();
          if (redirectPage) {
            location.hash = '#' + redirectPage;
            this.removeSearchParam('r');
          }
        },
        isLicenseExpiringSoon() {
          if (this.licenseStatus == LICENSE_STATUS_ACTIVE && this.licenseKey.expiration) {
            const now = Date.now();
            const exp = Date.parse(this.licenseKey.expiration);
            const timeToExpirationMs = exp - now;
            const minTimeToExpirationMs = LICENSE_EXPIRES_SOON_DAYS * 24 * 60 * 60 * 1000;
            return timeToExpirationMs < minTimeToExpirationMs;
          }
          return false;
        },
        async loadServerSettings(background) {
          // This version element ensures we're passed the login screen.
          if (document.getElementById("version")) {
            const now = Date.now()
            if (now - this.loadServerSettingsTime > this.cacheRefreshIntervalMs) {
              this.loadServerSettingsTime = now;
              try {
                // Do not allow subgrid override for this API call.
                const response = await this.papi.get('info', {params: { gridId: LOCAL_GRID_ID}});
                if (response) {
                  this.papi.defaults.headers.common['X-Srv-Token'] = response.data.srvToken;
                  this.version = response.data.version;
                  this.mgmtMac = response.data.mgmtMac;
                  this.license = response.data.license;
                  this.licenseKey = response.data.licenseKey;

                  // Fill in empty data for older licenses
                  if (this.licenseKey && !this.licenseKey.subgrids) {
                    this.licenseKey.subgrids = 0;
                  }

                  this.licenseStatus = response.data.licenseStatus;

                  if (this.licenseStatus == LICENSE_STATUS_EXCEEDED) {
                    this.showWarning(this.i18n.licenseExceeded);
                  } else if (this.licenseStatus == LICENSE_STATUS_PENDING) {
                    this.showWarning(this.i18n.licensePending);
                  } else if (this.licenseStatus == LICENSE_STATUS_EXPIRED) {
                    this.showWarning(this.i18n.licenseExpired);
                  } else if (this.licenseStatus == LICENSE_STATUS_INVALID) {
                    this.showWarning(this.i18n.licenseInvalid);
                  }
                  this.parameters = response.data.parameters;
                  this.elasticVersion = response.data.elasticVersion;
                  this.timezones = response.data.timezones;
                  this.subgrids = response.data.subgrids;
                  this.exportNodeId = response.data.parameters.exportNodeId;
                  this.customReports = response.data.customReports;

                  this.user = await this.getUserById(response.data.userId);
                  if (this.user) {
                    this.username = this.user.email;
                  }

                  if (this.parameterCallback != null) {
                    this.parameterCallback(this.parameters[this.parameterSection]);
                    this.parameterCallback = null;
                  }
                  this.parametersLoaded = true;
                  if (this.parameters.webSocketTimeoutMs > 0) {
                    this.wsConnectionTimeout = this.parameters.webSocketTimeoutMs;
                  }
                  if (this.parameters.apiTimeoutMs > 0) {
                    this.connectionTimeout = this.parameters.apiTimeoutMs;
                  }
                  if (this.parameters.cacheExpirationMs > 0) {
                    this.cacheRefreshIntervalMs = this.parameters.cacheExpirationMs;
                  }
                  if (this.parameters.tipTimeoutMs > 0) {
                    this.tipTimeout = this.parameters.tipTimeoutMs;
                  }
                  if (this.parameters.tools && this.parameters.tools.length > 0) {
                    this.tools = this.parameters.tools;
                    if (this.parameters.inactiveTools) {
                      const inactive = this.parameters.inactiveTools;
                      for (var i = 0; i < this.tools.length; i++) {
                        const tool = this.tools[i];
                        tool.enabled = !inactive.includes(tool.name);
                      }
                    }
                  }
                  this.casesEnabled = this.parameters.casesEnabled;
                  this.detectionsEnabled = this.parameters.detectionsEnabled;

                  this.checkUserSecuritySettings(response.data);

                  this.subscribe("status", this.updateStatus);
                  this.subscribe('import', (url) => {
                    if (url === 'no-changes') {
                      this.showInfo(this.i18n.gridMemberImportNoChanges);
                    } else if (url) {
                      const u = new URL(url);
                      if (u.host.toUpperCase() == window.location.host.toUpperCase()) {
                        url = u.hash;
                      }
                      const content = this.i18n.gridMemberImportSuccess.replace('{url}', url);
                      this.showInfo(content);
                    }
                  });
                  this.subscribe('detection-sync', (report) => {
                    const eng = this.correctCasing(report.engine);

                    switch (report.status) {
                      case 'success':
                        this.showInfo(this.i18n.syncSuccess.replace('{engine}', eng));
                        break;
                      case 'partial':
                        this.showWarning(this.i18n.syncPartialSuccess.replace('{engine}', eng));
                        break;
                      case 'error':
                        this.showError(this.i18n.syncFailure.replace('{engine}', eng));
                        break;
                      }
                  });

                  this.gridInfo[LOCAL_GRID_ID] = response.data;
                  await this.loadSubgridInfo();
                }
              } catch (error) {
                if (!background) {
                  // Only show the error on initial startup, otherwise the error
                  // will appear without the user having initiated it and will
                  // lead to confusion. There's already a connectivity indicator
                  // on the nav bar for the purpose of showing connection state.
                  this.showError(error);
                }
              }
            }
          }
        },
        async loadSubgridInfo() {
          if (!this.subgrids) return;
          var deferredError;
          for (var idx = 0; idx < this.subgrids.length; idx++) {
            const grid = this.subgrids[idx];
            try {
              const gridResponse = await this.papi.get('info', {params: { gridId: grid.id}});
              if (gridResponse) {
                this.gridInfo[grid.id] = gridResponse.data;
              }
            } catch (error) {
              deferredError = error
            }
          }
          if (deferredError) {
            throw deferredError;
          }
        },
        getSelectedGridInfo() {
          const gridInfo = this.gridInfo[this.selectedGridId];
          return gridInfo;
        },
        getCustomReports() {
          return this.customReports || {};
        },
        checkUserSecuritySettings(infoResponse) {
          // Only force OTP on initial login, otherwise risk user losing data
          // on a case comment, etc. This only applies if the ForceUserOtp
          // setting was enabled after a user had already been logged in. Users
          // that login after that setting is enabled will repeatedly be taken
          // back to the settings until the user complies.
          if (this.securitySettingsAlreadyChecked) return;

          this.forceUserOtp = infoResponse.forceUserOtp;
          if (this.forceUserOtp) {
            // Check if already on settings screen
            if (location.hash.indexOf("/settings") == -1) {
              location.hash = "/settings?tab=security";

              // Do not set the securitySettingsAlreadyChecked here because we need it to continue
              // redirecting the user until they comply.
            }
          } else {
            // Do not attempt to force security settings for the remainder of this session.
            this.securitySettingsAlreadyChecked = true;
          }
        },
        getAuthFlowId() {
          return this.getSearchParam('flow');
        },
        getRedirectPage() {
          return this.getSearchParam('r');
        },
        getSearchParam(param) {
          const searchParams = new URLSearchParams(window.location.search);
          const value = searchParams.get(param);
          return value;
        },
        removeSearchParam(param) {
          const searchParams = new URLSearchParams(window.location.search);
          searchParams.delete(param);
          window.location.search = searchParams.toString();
        },
        loadParameters(section, callback) {
          if (this.parametersLoaded) {
            callback(this.parameters[section])
          } else {
            this.parameterSection = section;
            this.parameterCallback = callback;
          }
        },
        async logout() {
          try {
            const response = await this.$root.authApi.get('logout/browser');
            location.href = response.data.logout_url;
          } catch (error) {
            this.$root.showError(this.i18n.logoutFailure);
          }
        },
        toggleTheme() {
          this.theme.change(this.theme.global.current.dark ? 'light' : 'dark');
          this.timestamp = Date.now();
          this.updateEditorTheme();
        },
        setFavicon() {
          const colorSchemeString = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches
            ? '-dark'
            : '';

          const svgFavicon = document.querySelector('.so-favicon[type="image/svg+xml"]'),
                pngFavicon = document.querySelector('.so-favicon[type="image/png"]');

          if (pngFavicon && svgFavicon) {
            const ext = ".svg";
            var iconIndex = svgFavicon.href.lastIndexOf("/");
            var tagIndex = svgFavicon.href.indexOf("-", iconIndex);
            const extIndex = svgFavicon.href.indexOf(ext, iconIndex);
            if (tagIndex > extIndex) tagIndex = -1;
            const baseText = svgFavicon.href.substring(0, tagIndex !== -1 ? tagIndex : extIndex);
            const queryParam = svgFavicon.href.substring(extIndex + ext.length);

            const attention = this.isAttentionNeeded() ? '-attention' : ''
            pngFavicon.href = `${baseText}${colorSchemeString}${attention}.png${queryParam}`;
            svgFavicon.href = `${baseText}${colorSchemeString}${attention}.svg${queryParam}`;
          }
        },
        setSubtitle(subtitle) {
          this.subtitle = subtitle;
          this.updateTitle();
        },
        updateTitle() {
          var title = "";
          title += this.isAttentionNeeded() ? "! " : "";
          title += "Security Onion";
          if (this.subtitle && this.subtitle.length > 0) {
            title += " - " + this.subtitle;
          }
          document.title = title;
        },
        drawAttention(elementId) {
          var element = $(elementId);
          if (element && element.removeClass) {
            element.removeClass('waggle');
            setTimeout(function() {
              element.addClass('waggle');
            }, 100);
          }
        },
        isLicenseUnprovisioned() {
          return this.licenseStatus == null || this.licenseStatus == LICENSE_STATUS_UNPROVISIONED;
        },
        isLicensed(feat) {
          return this.licenseKey != null && this.licenseStatus == LICENSE_STATUS_ACTIVE &&
              (!this.licenseKey.features.length || this.licenseKey.features.indexOf(feat) != -1);
        },
        colorLicenseStatus(value) {
          if (value == LICENSE_STATUS_ACTIVE) {
            if (this.licenseKey.name != SECURITYONION_PRO) {
              return "white";
            }
            return 'success';
          }
          if (value == LICENSE_STATUS_EXCEEDED) return "error";
          if (value == LICENSE_STATUS_EXPIRED) return "warning";
          if (value == LICENSE_STATUS_INVALID) return "error";
          if (value == LICENSE_STATUS_PENDING) return "warning";
          return "info";
        },
        makeHeader(label, value) {
          return { text: label, value: value };
        },
        formatDateTime(date) {
          return this.formatDate(date, this.i18n.dateTimeFormat, this.i18n.dateUnknown);
        },
        formatLocalTimestamp(date, tz) {
          var utcTime = moment.utc(date);
          var localTime = utcTime.tz(tz);
          return localTime.format(this.i18n.timestampFormat);
        },
        formatTimestamp(date) {
          return this.formatDate(date, this.i18n.timestampFormat, this.i18n.dateUnknown);
        },
        formatDate(date, format, dflt) {
          var formatted = dflt;
          if (date) {
            const dateObj = moment(String(date));
            if (dateObj.isAfter('1000-01-01')) {
              formatted = dateObj.format(format);
            }
          }
          return formatted;
        },
        formatUTCDate(date) {
          let formatted = '';
          if (date) {
            const dateObj = moment.utc(String(date));
            if (dateObj.isAfter('1000-01-01')) {
              formatted = dateObj.format(this.i18n.dateFormat);
            }
          }
          return formatted;
        },
        formatDuration(duration) {
          if (duration != null) {
            return moment.duration(duration,"s").humanize();
          }
        },
        formatLongDuration(durationMs) {
          const totalSeconds = durationMs / 1000;
          const minutes = totalSeconds / 60;
          const hours = minutes / 60;
          const days = hours / 24;
          if (days >= 1) {
            return `${days.toFixed(1)}${this.i18n.dDays}`;
          }
          if (hours >= 1) {
            return `${hours.toFixed(1)}${this.i18n.hHours}`;
          }
          return `${Math.round(minutes)}${this.i18n.mMinutes}`;
        },
        formatHours(hours) {
          return this.formatDecimal2(hours);
        },
        formatDecimal1(num) {
          return this.formatDecimalPlaces(num, 1);
        },
        formatDecimal2(num) {
          return this.formatDecimalPlaces(num, 2);
        },
        formatDecimalPlaces(num, places) {
          if (!num) {
            num = 0.0;
          }
          return num.toFixed(places);
        },
        formatCount(count) {
          return Number(count).toLocaleString();
        },
        formatCountMK(count) {
          let modifiedCount = count;
          let suffix = '';
          let countStr;
          if (Math.abs(count) >= 1000000) {
            modifiedCount /= 1000000;
            countStr = this.formatDecimal1(modifiedCount).toLocaleString();
            suffix = this.i18n.mMillion;
          } else if (Math.abs(count) >= 1000) {
            modifiedCount /= 1000;
            countStr = this.formatDecimal1(modifiedCount).toLocaleString();
            suffix = this.i18n.kThousand;
          } else {
            countStr = this.formatCount(modifiedCount);
          }
          return countStr + suffix;
        },
        formatStringArray(strArray) {
          if (strArray != null && strArray.length > 0) {
            return strArray.join(", ");
          }
          return "";
        },
        formatMarkdown(str, handleMermaid=false) {
          marked.setOptions({
            renderer: new marked.Renderer(),
            smartLists: true,
            breaks: true
          })
          if (!handleMermaid) {
            marked.use({
              tokenizer: {
                url(src) {
                  // Blank function disables bare url tokenization
                }
              }
            })
            var md = str;
            if (str) {
              md = marked.parse(str);
              md = DOMPurify.sanitize(md);
            }
            return md;
          } else {
            marked.use({
              tokenizer: {
                url(src) {
                  // Blank function disables bare url tokenization
                }
              },
              renderer: {
                code: function (code) {
                  if (code.lang == 'mermaid') {
                    return `<pre class="mermaid">${code.text}</pre>`;
                  }
                  return `<pre>${code.text}</pre>`;
                }
              }
            });
            var md = str;
            if (str) {
              this.initializeMermaid();
              md = marked.parse(str);
              md = DOMPurify.sanitize(md);
            }
            return md;
          }
        },
        initializeMermaid() {
          if (typeof mermaid !== 'undefined' && !this.mermaidInitialized) {
            mermaid.initialize({
              startOnLoad: false,
              theme: this.$vuetify && this.$vuetify.theme.current.dark ? 'dark' : 'default',
              securityLevel: 'strict',
              fontFamily: 'inherit'
            });
            this.mermaidInitialized = true;
          }
        },
        renderMermaid() {
          if (typeof mermaid !== 'undefined' && this.mermaidInitialized) {
            mermaid.run();
          }
        },
        performMermaidRegexes(text) {
          // removes double blank lines from mermaid charts
          text = text.replace(/(?<=```mermaid(?:(?!```)[\s\S])*?)\n\s*\n(?=(?:(?!```)[\s\S])*```)/g, '\n');
          // converts non-separator colons to ratio characters in mermaid charts
          text = text.replace(/(?<=```mermaid(?:(?!```)[\s\S])*?)(?<!\s):(?=(?:(?!```)[\s\S])*```)/g, '\u2236');
          return text
        },
        colorSeverity(value) {
          if (value == "low_false") return "yellow";
          if (value == "medium_false") return "orange-darken-1";
          if (value == "high_false") return "red-lighten-1";
          if (value == "critical_false") return "red-darken-4";
          return "icon";
        },
        isNodeInSubgrid(node) {
          return node.gridId != null && node.gridId.trim().length > 0;
        },
        hasSubgrids() {
          return this.subgrids != null && this.subgrids.length > 0;
        },
        getSelectedGrid() {
          return this.subgrids.find((grid) => { return grid.id == this.selectedGridId });
        },
        adjustSubgridColVisibility(headers, size = "d-sm-table-cell") {
          this.updateColumnClass(headers, this.i18n.gridId, this.hasSubgrids());
        },
        updateColumnClass(headers, title, visible, size = "d-sm-table-cell") {
          const column = headers.find(function(item) {
            return item.title == title
          });
          if (!column) return;
          if (!visible) {
            column.align = ' d-none';
          } else {
            column.align = ' d-none ' + size;
          }
        },
        generateDatePickerPreselects() {
          var preselects = {};
          preselects[this.i18n.datePreselectToday] = [moment().startOf('day'), moment().endOf('day')];
          preselects[this.i18n.datePreselectYesterday] = [moment().subtract(1, 'days').startOf('day'), moment().subtract(1, 'days').endOf('day')];
          preselects[this.i18n.datePreselectThisWeek] = [moment().startOf('week'), moment().endOf('week')];
          preselects[this.i18n.datePreselectLastWeek] = [moment().subtract(1, 'week').startOf('week'), moment().subtract(1, 'week').endOf('week')];
          preselects[this.i18n.datePreselectThisMonth] = [moment().startOf('month'), moment().endOf('month')];
          preselects[this.i18n.datePreselectLastMonth] = [moment().subtract(1, 'month').startOf('month'), moment().subtract(1, 'month').endOf('month')];
          preselects[this.i18n.datePreselectPrevious3d] = [moment().subtract(3, 'days').startOf('day'), moment().subtract(1, 'days').endOf('day')];
          preselects[this.i18n.datePreselectPrevious4d] = [moment().subtract(4, 'days').startOf('day'), moment().subtract(1, 'days').endOf('day')];
          preselects[this.i18n.datePreselectPrevious7d] = [moment().subtract(7, 'days').startOf('day'), moment().subtract(1, 'days').endOf('day')];
          preselects[this.i18n.datePreselectPrevious30d] = [moment().subtract(30, 'days').startOf('day'), moment().subtract(1, 'days').endOf('day')];
          preselects[this.i18n.datePreselect3dToNow] = [moment().subtract(3, 'days'), moment()];
          preselects[this.i18n.datePreselect4dToNow] = [moment().subtract(4, 'days'), moment()];
          preselects[this.i18n.datePreselect7dToNow] = [moment().subtract(7, 'days'), moment()];
          preselects[this.i18n.datePreselect30dToNow] = [moment().subtract(30, 'days'), moment()];
          return preselects;
        },
        applyDateRangePickerAriaLabels(picker) {
          const $c = picker.container;
          $c.find('.drp-calendar.left .hourselect').attr('aria-label', this.i18n.ariaPickerStartHour);
          $c.find('.drp-calendar.left .minuteselect').attr('aria-label', this.i18n.ariaPickerStartMinute);
          $c.find('.drp-calendar.left .secondselect').attr('aria-label', this.i18n.ariaPickerStartSecond);
          $c.find('.drp-calendar.left .ampmselect').attr('aria-label', this.i18n.ariaPickerStartAmPm);
          $c.find('.drp-calendar.right .hourselect').attr('aria-label', this.i18n.ariaPickerEndHour);
          $c.find('.drp-calendar.right .minuteselect').attr('aria-label', this.i18n.ariaPickerEndMinute);
          $c.find('.drp-calendar.right .secondselect').attr('aria-label', this.i18n.ariaPickerEndSecond);
          $c.find('.drp-calendar.right .ampmselect').attr('aria-label', this.i18n.ariaPickerEndAmPm);
        },
        localizeMessage(origMsg, vars = null) {
          if (!origMsg) return "";
          var msg = origMsg;
          if (msg.response && msg.response.data) {
            msg = msg.response.data;
            if (msg.error && msg.error.reason) {
              msg = msg.error.reason;
            }
          }

          // Remove encapsulating quotes
          if (msg.startsWith != undefined && msg.startsWith("\"") && msg.endsWith("\"")) {
            msg = msg.substring(1, msg.length - 1);
          }

          var localized = this.i18n[msg];
          if (!localized) {
            if (origMsg.message) {
              msg = origMsg.message;
            }
            if (msg.length > 200) {
              msg = msg.substring(0, 200) + "...";
            }
            localized = msg;
          }

          if (vars && typeof vars == 'object') {
            return localized.replace(/\{(\w+)\}/g, function(match, key) {
              return vars[key] !== undefined ? vars[key] : match;
            });
          }
  
          return localized;
        },
        tryLocalize(msg) {
          const localized = this.localizeMessage(msg);
          if (localized) {
            return localized;
          }

          return msg;
        },
        correctCasing(origMsg) {
          const msg = (origMsg+'').toLowerCase();
          var localized = this.i18n['cc_'+msg];
          if (!localized) {
            return origMsg;
          }

          return localized;
        },
        showError(msg) {
          if (msg.name == "CanceledError") {
            this.showTip(this.i18n.requestCanceled);
            return;
          }
          this.error = true;
          this.errorMessage = this.localizeMessage(msg);
          if (this.debug && msg && msg.stack) {
            console.log(msg.stack);
          }
        },
        showWarning(msg, skipLocalization) {
          this.warning = true;
          if (skipLocalization) {
            this.warningMessage = msg;
          } else {
            this.warningMessage = this.localizeMessage(msg);
          }
        },
        showInfo(msg) {
          this.info = true;
          this.infoMessage = msg;
        },
        showTip(msg, timeout) {
          this.error = false;
          this.warning = false;
          this.info = false;

          this.tip = true;
          this.tipMessage = msg;
          if (timeout) {
            this.currentTipTimeout = timeout;
          } else {
            this.currentTipTimeout = this.tipTimeout;
          }
        },
        showDisclaimer(msg, title, closeButton, storageKey) {
          const saved = localStorage.getItem(storageKey);
          if (saved !== 'true') {
            this.disclaimer = true;
            this.disclaimerMessage = msg;
            this.disclaimerTitle = title;
            this.disclaimerClose = closeButton;
            this.disclaimerStorageKey = storageKey;
          }
        },
        acceptDisclaimer() {
          localStorage.setItem(this.disclaimerStorageKey, 'true');
          this.disclaimer = false;
        },
        closeDisclaimerOnNav() {
          if (this.disclaimer) this.disclaimer = false;
        },
        startLoading(cancelCallback = null) {
          this.loading = true;
          this.error = false;
          this.warning = false;
          this.info = false;
          this.loadingCancelCallback = cancelCallback;
        },
        stopLoading() {
          this.loading = false;
        },
        saveToolbar() {
          localStorage['settings.app.navbar'] = this.toolbar;
        },
        saveTheme() {
          localStorage['settings.app.dark'] = this.$vuetify.theme.current.dark;
        },
        saveLocalSettings() {
          this.saveTheme();
          this.saveToolbar();
        },
        loadLocalSettings() {
          if (localStorage['settings.app.dark'] != undefined) {
            this.theme.change(localStorage['settings.app.dark'] == 'true' ? 'dark' : 'light');
            this.updateEditorTheme();
          }
          if (localStorage['settings.app.navbar'] != undefined) {
            this.toolbar = localStorage['settings.app.navbar'] == "true";
          }
        },
        updateEditorTheme() {
          var link = $('link[href^="css/external/prism-custom-"]')[0];
          if (link) {
            if (this.$vuetify.theme.current.dark) {
              link.href = "css/external/prism-custom-dark-v1.29.0.css";
            } else {
              link.href = "css/external/prism-custom-light-v1.29.0.css";
            }
          }
        },
        subscribe(kind, fn) {
          this.ensureConnected();
          var list = this.subscriptions[kind];
          if (list == undefined) {
            list = [];
            this.subscriptions[kind] = list;
          }
          if (list.indexOf(fn) == -1) {
            list.push(fn);
          }
        },
        unsubscribe(kind, fn) {
          var list = this.subscriptions[kind];
          if (list != undefined) {
            var idx = list.indexOf(fn);
            if (idx > -1) {
              list.splice(idx, 1);
            }
          }
        },
        publish(kind, obj) {
          var listeners = this.subscriptions[kind];
          if (listeners) {
            listeners.forEach(function(listener) {
              listener(obj);
            });
          }
        },
        ensureConnected() {
          if (this.socket == null) {
            this.connected = false;
            this.reconnecting = false;
            this.openWebsocket();
            window.setInterval(this.openWebsocket, this.wsConnectionTimeout);
          }
        },
        openWebsocket() {
          if (!this.socket || this.socket.readyState == WebSocket.CLOSED ) {
            const vm = this;
            this.connected = false;
            this.reconnecting = true;
            this.log("WebSocket connecting to " + this.wsUrl);
            this.socket = new WebSocket(this.wsUrl);
            this.socket.onopen = function(evt) {
              vm.log("WebSocket connected");
              vm.connected = true;
              vm.reconnecting = false;
              vm.loadServerSettingsTime = 0; // Force reload of server settings in case new SOC config changed
              vm.updateStatus();
            };
            this.socket.onclose = function(evt) {
              vm.log("WebSocket closed, will attempt to reconnect");
              vm.socket = null;
              vm.connected = false;
              vm.reconnecting = false;
              vm.updateStatus();
            };
            this.socket.onmessage = function(evt) {
              var msg = JSON.parse(evt.data);
              vm.publish(msg.Kind, msg.Object);
            };
            this.socket.onerror = function(evt) {
              vm.log("WebSocket failure: " + evt.data);
            };
          } else {
            this.connected = true;
            this.reconnecting = false;
            try {
              this.socket.send('{ "Kind": "Ping" }');
              this.updateStatus();
            } catch (e) {
              this.log("Failed to ping manager");
              try {
                this.socket.close();
              } catch (ce) {
              }
              this.socket = null;
            }
          }
        },
        showLogin() {
          location.href = this.authUrl + "login/browser";
        },
        checkForUnauthorized(response) {
          if (response) {
            const redirectCookie = this.getCookie('AUTH_REDIRECT');
            if ((response.headers && response.headers['content-type'] == "text/html") ||
                (response.status == 401 && response.request.responseURL && response.request.responseURL.indexOf('/api/') == -1) ||
                (response.request.responseURL && response.request.responseURL.indexOf("/login/banner.md") == -1 && redirectCookie != null && redirectCookie.length > 0)) {
              this.deleteCookie('AUTH_REDIRECT');
              this.showLogin();
              return null
            }
          }
          return response;
        },
        apiRequestCallback(request) {
          if (this.selectedGridId && (!request.params || !('gridId' in request.params))) {
            if (!request.params) {
              request.params = {};
            }
            request.params["gridId"] = this.selectedGridId;
          }
          if (request.params && 'gridId' in request.params && request.params.gridId == LOCAL_GRID_ID) {
            delete request.params.gridId;
          }
          return request;
        },
        apiRequestFailedCallback(error) {
          return error;
        },
        apiSuccessCallback(response) {
          return this.checkForUnauthorized(response);
        },
        apiFailureCallback(error) {
          if (error.response && error.response.status >= 502 && error.response.status <= 504) {
            reconnecting = true;
          } else { 
            this.checkForUnauthorized(error.response);
          }
          throw error;
        },
        createApi(baseUrl) {
          const ax = axios.create({
            baseURL: baseUrl,
            timeout: this.connectionTimeout,
          });
          ax.interceptors.request.use(this.apiRequestCallback, this.apiRequestFailedCallback);
          ax.interceptors.response.use(this.apiSuccessCallback, this.apiFailureCallback);
          return ax;
        },
        setupApi() {
          this.papi = this.createApi(this.apiUrl);
        },
        setupAuth() {
          this.authApi = axios.create({
            baseURL: this.authUrl,
            timeout: this.connectionTimeout,
            withCredentials: true,
          });
          this.settingsUrl = this.authUrl + 'settings/browser';
        },
        setCookie(name, value, ageSecs) {
          let maxAge = "";
          if (ageSecs) {
            maxAge = ";Max-Age=" + ageSecs;
          }
          document.cookie = name + "=" + value + maxAge + ";Path=/";
        },
        getCookie(name) {
          let cookies = document.cookie.split(';');
          for (let i = 0; i < cookies.length; i++) {
              let cookie = cookies[i].trim();
              let pair = cookie.split("=", 2);
              if (pair.length == 2 && pair[0] == name) {
                return pair[1];
              }
          }
          return null;
        },
        deleteCookie(name) {
          this.setCookie(name, "", -1);
        },
        registerChart(chartType, chartName) {
          const app = Vue.getCurrentInstance().appContext.app;
          app.component(chartName, {
            extends: chartType,
            props: {
              data: { type: Object },
              options: { type: Object }
            },
            data() {
              return {
                chartData: this.data,
                chartOptions: this.options,
              };
            },
            setup(props, context) {
              return chartType.setup(props, context);
            },
          });
        },
        initializeCharts() {
          if (this.chartsInitialized) return;
          this.registerChart(VueChartJs.Bar, 'bar-chart');
          this.registerChart(VueChartJs.Line, 'line-chart');
          this.registerChart(VueChartJs.Pie, 'pie-chart');

          // Sankey is a separate third-party lib, so use the VueChartJs helper to add the custom chart
          const Sankey = VueChartJs.createTypedChart('sankey', Chart.controllers['sankey']);
          this.registerChart(Sankey, 'sankey-chart');

          this.chartsInitialized = true;
        },
        registerEditor() {
          const app = Vue.getCurrentInstance().appContext.app;
          app.component('prism-editor', PrismEditor.PrismEditor);
          app.directive('aria-textarea', {
            mounted(el) { moveAriaToPrismTextarea(el); },
            updated(el) { moveAriaToPrismTextarea(el); },
          });
        },
        initializeEditor() {
          if (this.editorInitialized) return;
          this.registerEditor();

          this.editorInitialized = true;
        },
        getColor(colorName, percent = 0) {
          percent = this.$root.$vuetify && this.$root.$vuetify.theme.current.dark ? percent * -1 : percent;
          var color = colorName;
          if (this.$root.$vuetify && this.$root.$vuetify.theme.current.colors[colorName]) {
            color = this.$root.$vuetify.theme.current.colors[colorName];
          }
          var R = parseInt(color.substring(1,3),16);
          var G = parseInt(color.substring(3,5),16);
          var B = parseInt(color.substring(5,7),16);

          R = parseInt(R * (100 + percent) / 100);
          G = parseInt(G * (100 + percent) / 100);
          B = parseInt(B * (100 + percent) / 100);

          R = (R<255)?R:255;
          G = (G<255)?G:255;
          B = (B<255)?B:255;

          var RR = ((R.toString(16).length==1)?"0"+R.toString(16):R.toString(16));
          var GG = ((G.toString(16).length==1)?"0"+G.toString(16):G.toString(16));
          var BB = ((B.toString(16).length==1)?"0"+B.toString(16):B.toString(16));

          return "#"+RR+GG+BB;
        },
        truncate(value, max) {
          const ellipses = "...";
          if (value.length > max + ellipses.length) {
            const half = max / 2;
            value = value.substring(0, half - 1) + ellipses + value.substring(value.length - half);
          }
          return value;
        },
        getAllGrids() {
          const grids = [{id: LOCAL_GRID_ID, name: this.i18n.gridLocal}];
          this.subgrids.forEach((grid) => {
            grid.name = grid.id;
            grids.push(grid);
          });
          return grids;
        },
        getAvatar(user) {
          if (user && user.length > 0) {
            return user.charAt(0).toLocaleUpperCase();
          }
          return this.i18n.na;
        },
        async getActiveUsers() {
          const users = await this.getUsers();
          return users.filter(user => user.status != 'locked');
        },
        async getAllUsers() {
          const allUsers = [];
          const allGrids = this.getAllGrids();
          for (idx in allGrids) {
            const grid = allGrids[idx];
            try {
              const response = await this.papi.get('users/', { params: { gridId: grid.id }});
              allUsers.push(...response.data);
            } catch (error) {
              this.showError(error);
            }
          }
          if (allUsers) {
            this.users = allUsers;
          }
          return this.users;
        },
        async getUsers() {
          // Returns selected subgrid's users
          try {
            const response = await this.papi.get('users/');
            return response.data;
          } catch (error) {
            this.showError(error);
          }
          return [];
        },
        async getUserById(id) {
          const nowTime = new Date().time;
          if (this.users.length == 0 || (nowTime - this.usersLoadedTime > this.cacheRefreshIntervalMs)) {
            await this.getAllUsers();
            this.usersLoadedTime = nowTime;
          }
          return this.getUserByIdViaCache(id);
        },
        getUserByIdViaCache(id) {
          if (this.users) {
            for (var idx = 0; idx < this.users.length; idx++) {
              const user = this.users[idx];
              if (user.id == id) {
                return user;
              }
            }
          }
          return null;
        },
        getUserDisplayName(user) {
          if (!user) {
            return "";
          }
          return user.email;
        },
        async populateUserDetails(obj, idField, outputField) {
          if (obj[idField] && obj[idField].length > 0) {
            const id = obj[idField];
            if (id === SYSTEM_USER_ID || id === AGENT_USER_ID || id === "agent") {
              obj[outputField] = this.i18n.systemUser;
              return
            }

            const user = await this.$root.getUserById(id);
            if (user) {
              const displayName = this.getUserDisplayName(user);
              if (Vue.isRef(obj[outputField])) {
                obj[outputField].value = displayName;
              } else {
                obj[outputField] = displayName;
              }
            } else {
              obj[outputField] = id;
            }
          }
        },
        isClientAdmin(user = null) {
          return this.isUserAdmin(user);
        },
        isUserAdmin(user = null) {
          return this.userHasRole("superuser", user);
        },
        isMyUser(user) {
          return user != null && this.user != null && user.id == this.user.id;
        },
        userHasRole(role, user = null) {
          if (!user) {
            user = this.user;
          }

          if (!user) return false;

          return user.roles.indexOf(role) != -1;
        },
        updateStatus(status) {
          if (status) {
            this.statusByGridId[status.gridId] = status;
          }
          this.setFavicon();
          this.updateTitle();
          this.loadServerSettings(true);
        },
        getDetectionEngines() {
          return ['elastalert', 'strelka', 'suricata'];
        },
        getDetectionEngineStatusClass(engine) {
          switch (this.getDetectionEngineStatus(engine)) {
            case "MigrationFailure": return "text-warning";
            case "SyncFailure": return "text-warning";
            case "IntegrityFailure": return "text-warning";
            case "Blocked": return "text-warning";
            case "Healthy": return "text-success";
          }
          return "text-normal";
        },
        getDetectionEngineStatus(engine) {
          const status = this.getCurrentStatus();
          if (!status || !status.detections || !status.detections[engine]) {
            return "Unknown";
          }

          const engineStatus = this.statusByGridId[this.selectedGridId].detections[engine];

          // Order is important in this if/else block. Certain status should take priority. For example,
          // If a sync failure and integrity failure both occurred then show the integrity failure, because
          // if it got to the integrity check then the sync finished but the integrity check failed.
          if (engineStatus.blocked) {
            return "Blocked";
          } else if (engineStatus.migrating) {
            return "Migrating";
          } else if (engineStatus.importing && engineStatus.syncing) {
            return "Importing";
          } else if (engineStatus.migrationFailure) {
            return "MigrationFailure";
          } else if (engineStatus.integrityFailure) {
            return "IntegrityFailure";
          } else if (engineStatus.syncFailure) {
            return "SyncFailure";
          } else if (engineStatus.importing && !engineStatus.syncing) {
            return "ImportPending";
          } else if (engineStatus.syncing) {
            return "Syncing";
          }
          return "Healthy";
        },
        isDetectionEngineStatusUnhealthy(engine) {
          switch (this.getDetectionEngineStatus(engine)) {
            case "Migrating":
            case "Importing":
            case "ImportPending":
            case "Pending":
            case "Syncing":
            case "Healthy":
            case "Unknown":
              return false;
          }
          return true;
        },
        getCurrentStatus() {
          return this.statusByGridId[this.selectedGridId];
        },
        getSubgridIcon(gridId) {
          if (this.isGridAttentionNeeded(gridId)) {
            return 'fa-exclamation';
          } else if (this.isGridDetectionsUpdating(gridId)) {
            return 'fa-hourglass-half';
          }
          return '';
        },
        getSubgridColor(gridId) {
          if (this.isGridAttentionNeeded(gridId)) {
            return 'warning';
          }
          return '';
        },
        isGridDetectionsUnhealthy(gridId) {
          const status = this.statusByGridId[gridId];
          if (status != null && status.detections != null &&
            ( status.detections.elastalert.integrityFailure ||
              status.detections.suricata.integrityFailure ||
              status.detections.strelka.integrityFailure ||
              status.detections.elastalert.syncFailure ||
              status.detections.suricata.syncFailure ||
              status.detections.strelka.syncFailure ||
              status.detections.elastalert.migrationFailure ||
              status.detections.suricata.migrationFailure ||
              status.detections.strelka.migrationFailure )) {
            return true;
          }
          return false;
        },
        isDetectionsUnhealthy() {
          for (gridId in this.statusByGridId) {
            if (this.isGridDetectionsUnhealthy(gridId)) {
              return true;
            }
          }
          return false;
        },
        isGridDetectionsUpdating(gridId) {
          const status = this.statusByGridId[gridId];
          return status != null && status.detections != null &&
            !this.isGridDetectionsUnhealthy(gridId) &&
            ( status.detections.elastalert.importing === true ||
              status.detections.elastalert.migrating === true ||
              status.detections.elastalert.syncing === true ||
              status.detections.strelka.importing === true ||
              status.detections.strelka.migrating === true ||
              status.detections.strelka.syncing === true ||
              status.detections.suricata.importing === true ||
              status.detections.suricata.migrating === true ||
              status.detections.suricata.syncing === true );
        },
        isDetectionsUpdating() {
          for (gridId in this.statusByGridId) {
            if (this.isGridDetectionsUpdating(gridId)) {
              return true;
            }
          }
          return false;
        },
        isGridUnhealthy(gridId) {
          const status = this.statusByGridId[gridId];
          if (status && status.grid && status.grid.unhealthyNodeCount > 0) {
            return true;
          }
          return false;
        },
        isUnhealthy() {
          for (gridId in this.statusByGridId) {
            if (this.isGridUnhealthy(gridId)) {
              return true;
            }
          }
          return false;
        },
        isNewGridAlert(gridId) {
          const status = this.statusByGridId[gridId];
          if (status && status.alerts && status.alerts.newCount  > 0) {
            return true;
          }
          return false;
        },
        isNewAlert() {
          for (gridId in this.statusByGridId) {
            if (this.isNewGridAlert(gridId)) {
              return true;
            }
          }
          return false;
        },
        isGridAttentionNeeded(gridId) {
          return this.isNewGridAlert(gridId) || this.isGridUnhealthy(gridId) || this.isGridDetectionsUnhealthy(gridId);
        },
        isAttentionNeeded() {
          return this.isNewAlert() || this.isUnhealthy() || this.isDetectionsUnhealthy() || !this.connected || this.reconnecting;
        },
        isMaximized() {
          return this.maximizedTarget != null;
        },
        maximizeById(targetId, escapeFn=null) {
          const target = document.getElementById(targetId);
          if (target) {
            return this.maximize(target, escapeFn);
          }
          return false;
        },
        maximize(target, escapeFn=null) {
          this.unmaximize();
          this.maximizedTarget = target;
          this.maximizedOrigWidth = target.style.width;
          this.maximizedOrigHeight = target.style.height;
          target.classList.add("maximized");
          document.documentElement.classList.add("maximized-bg");
          window.scrollTo(0,0);
          this.maximizedCancelFn = escapeFn;
          document.addEventListener('keydown', this.unmaximizeEscapeListener);
          return true;
        },
        unmaximize(userInitiated=false) {
          if (!this.maximizedTarget) return;
          if (userInitiated && this.maximizedCancelFn) {
            if (this.maximizedCancelFn(this.maximizeTarget)) return;
          }
          this.maximizedTarget.classList.remove("maximized");
          document.documentElement.classList.remove("maximized-bg");
          this.maximizedTarget.style.width = this.maximizedOrigWidth;
          this.maximizedTarget.style.height = this.maximizedOrigHeight;
          this.maximizedTarget = null;
          this.maximizedCancelFn = null;
          document.removeEventListener('keydown', this.unmaximizeEscapeListener);
        },
        unmaximizeEscapeListener(event) {
          if (event.code == "Escape") {
            this.unmaximize(true);
          }
          if (typeof event.cancelable !== "boolean" || event.cancelable) {
            event.preventDefault();
          }
        },
        batchLookup(ips, comp) {
          ips = ips.filter(ip => (this.isIPv4(ip) || this.isIPv6(ip)) && !this.ip2host[ip]);
          if (ips.length) {
            ips = [...new Set(ips)];
            ips.forEach(ip => this.ip2host[ip] = []);

            // Do not use subgrid ID for this API call.
            this.papi.put('util/reverse-lookup', ips, {params: { gridId: LOCAL_GRID_ID}}).then(response => {
              for (let entry in response.data) {
                let existing = this.ip2host[entry];
                if (!existing) {
                  existing = [];
                }

                if (response.data && response.data[entry] && response.data[entry].length) {
                  let arr = this.ip2host[entry];
                  if (!arr || !arr.length) {
                    arr = [];
                  }

                  arr.push(...response.data[entry]);
                  this.ip2host[entry] = arr;
                }
              }
              comp.$forceUpdate();
            });
          }
        },
        isIPv4(str) {
          if (typeof str === 'string') {
            return !!str.match(/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/);
          }

          return false;
        },
        isIPv6(str) {
          if (typeof str === 'string') {
            return !!str.match(/^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/i);
          }

          return false;
        },
        isTrue(b) {
          return b === true || ("" + b).toLowerCase() == "true";
        },
        tryResolveAlias(field, value) {
          var alias = this.pickHostname(value);
          if (alias) {
            return alias;
          }

          if (field && field.endsWith('detection.author')) {
            return this.tryLocalize(value);
          }

          alias = this.pickUserInfo(field, value);
          if (alias) {
            return alias;
          }

          return null;
        },
        pickUserInfo(field, value) {
          if (field && field.endsWith('_by')) {
            // try to resolve the username
            const user = this.getUserByIdViaCache(value);
            if (user) {
              return this.getUserDisplayName(user);
            }
          }
          return null;
        },
        pickHostname(ip) {
          const arr = this.ip2host[ip];
          if (arr && arr.length) {
            const names = this.ip2host[ip].filter(host => host != ip);
            if (names.length) {
              return names[0];
            }
          }

          return '';
        },
        dateAwareCompare(field) {
          return (a, b) => {
            return new Date(a[field]) - new Date(b[field]);
          }
        },
        dateToRange(d) {
          const before = moment(d).subtract(1, 'second').format(this.i18n.timePickerFormat);
          const after = moment(d).add(1, 'second').format(this.i18n.timePickerFormat);
          return `${before} - ${after}`;
        },
        async export(params, beginDate, endDate) {
          this.startLoading();
          try {
            const response = await this.papi.post('job/', {
              kind: 'reports',
              nodeId: this.exportNodeId,
              filter: {
                beginTime: beginDate,
                endTime: endDate,
                parameters: params
              }
            });
            if (response && response.data) {
              this.showTip(this.i18n.exportJobEnqueued.replace('{jobId}', response.data.id));
            }
          } catch (error) {
            this.showError(error);
          }
          this.stopLoading();
        },
        verifyRuleSyntax(det) {
          const rules = this.ruleValidators[det.language.toLowerCase()];
          for (let i = 0; i < rules.length; i++) {
            if (rules[i].pattern.test(det.content) === rules[i].match) {
              return rules[i].message;
            }
          }

          return null;
        },
      },
      created() {
        this.log("Initializing application components");
        if (this.redirectIfAuthCompleted()) return;
        if (this.redirectRoute()) return;
        this.setupApi();
        this.setupAuth();
        this.log("Initialization complete");
      },
      mounted() {
        this.setFavicon();

        const universalFuncs = {
          formatUTCDate: this.formatUTCDate,
          formatDateTime: this.formatDateTime,
          formatDuration: this.formatDuration,
          formatHours: this.formatHours,
          formatDecimal1: this.formatDecimal1,
          formatDecimal2: this.formatDecimal2,
          formatCount: this.formatCount,
          formatMarkdown: this.formatMarkdown,
          formatTimestamp: this.formatTimestamp,
          colorSeverity: this.colorSeverity,
          dateToRange: this.dateToRange,
        };

        // Register these functions globally
        Object.keys(universalFuncs).forEach(key => {
          app.config.globalProperties[key] = universalFuncs[key];
        });

        window.matchMedia('(prefers-color-scheme: dark)').addListener(() => this.setFavicon());
        this.loadServerSettings(false);
        this.loadLocalSettings();
        $('#app')[0].style.display = "block";

        router.isReady().then(() => {
          this.onLocationUpdated(this.$route, null);
        });
      },
    };

    const app = Vue.createApp(comp);
    app.use(vuetify);
    app.use(router);

    for (let i = 0; i < components.length; i++) {
      app.component(components[i].name, components[i].component);
    }

    for (let i = 0; i < directives.length; i++) {
      app.directive(directives[i].name, directives[i].directive);
    }

    app.mount('#app');
  });
});

const cacheBuster = document.currentScript ? new URL(document.currentScript.src).search : '';
function loadPageTemplate(templateId, templatePath) {
  const promise = new Promise((resolve, reject) => {
    const page = $("<template>", {id: templateId});
    page.load(templatePath + cacheBuster, function(response, status) {
      if (status === "success") {
        $('body').append(page);
        resolve();
      } else {
        reject(new Error(`Failed to load template: ${templatePath}`));
      }
    });
  });

  templatePromises.push(promise);
  return promise;
}
