// Copyright 2019 Jason Ertel (jertel). All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
const routes = [];

$(document).ready(function() {
  const vmMain = new Vue({
    el: '#app',
    vuetify: new Vuetify({
      icons: {
        iconfont: 'fa',
      },
      theme: {
        dark: true,
        options: {
          customProperties: true,
        },
        themes: {
          light: {
            nav_background: '#12110d',
            nav: '#ffffff',
            background: '#f2f2f2',
          },
          dark: {
            nav_background: '#12110d',
            nav: '#ffffff',
            background: '#242424',
          },
        },
      },
    }),
    router: new VueRouter({ routes }),
    data: {
      timestamp: Date.now(),
      i18n: i18n.getLocalizedTranslations(navigator.language),
      loading: false,
      error: false,
      info: false,
      errorMessage: "",
      infoMessage: "",
      toolbar: null,
      wsUrl: (location.protocol == 'https:' ?  'wss://' : 'ws://') + location.host + location.pathname + 'ws',
      apiUrl: location.origin + location.pathname + 'api/',
      authUrl: '/auth/self-service/browser/flows/',
      version: '0.0',
      versionLink: 'https://github.com/security-onion-solutions/securityonion-soc/releases/',
      papi: null,
      connectionTimeout: 5000,
      socket: null,
      subscriptions: [],
    },
    watch: {
      '$vuetify.theme.dark': 'saveLocalSettings',
    },
    methods: {
      log(msg) {
        console.log(msg);
      },
      redirectIfAuthCompleted() {
        if (!location.pathname.startsWith("/login")) {
          destUri = this.getCookie("AUTH_REDIRECT");
          if (destUri && destUri != "/") {
            this.log("Redirecting to auth destination: " + destUri);
            this.deleteCookie("AUTH_REDIRECT");
            location.pathname = destUri;
            return true;
          }
        }
        return false;
      },
      async loadInfo() {
        if (document.getElementById("versionLink")) {
          try {
            const response = await this.papi.get('info');
            this.version = response.data.version;
            this.versionLink = "https://github.com/security-onion-solutions/securityonion-soc/releases/tag/" + this.version;
            this.license = response.data.license;
          } catch (error) {
            this.showError(error);
          }
        }
      },
      toggleTheme() {
        this.$vuetify.theme.dark = !this.$vuetify.theme.dark
        this.timestamp=Date.now();
      },
      makeHeader(label, value) {
        return { text: label, value: value };
      },
      formatDateTime(date) {
        var formatted = this.i18n.dateUnknown;
        if (date) {
          const dateObj = moment(String(date));
          if (dateObj.isAfter('1000-01-01')) {
            formatted = dateObj.format(this.i18n.dateTimeFormat);
          }
        }
        return formatted;
      },
      formatTimestamp(date) {
        var formatted = this.i18n.dateUnknown;
        if (date) {
          const dateObj = moment(String(date));
          if (dateObj.isAfter('1000-01-01')) {
            formatted = dateObj.format(this.i18n.timestampFormat);
          }
        }
        return formatted;
      },
      formatDuration(duration) {
        if (duration) {
          return moment.duration(duration,"s").humanize();
        }
      },
      showError(msg) {
        this.error = true;
        this.errorMessage = msg;
      },
      showInfo(msg) {
        this.info = true;
        this.infoMessage = msg;
      },
      startLoading() {
        this.loading = true;
        this.error = false;
        this.info = false;
      },
      stopLoading() {
        this.loading = false;
      },
      saveLocalSettings() {
        localStorage['settings.app.dark'] = this.$vuetify.theme.dark;
      },
      loadLocalSettings() {
        if (localStorage['settings.app.dark'] != undefined) {
          this.$vuetify.theme.dark = localStorage['settings.app.dark'] == "true";
        }
      },
      subscribe(kind, fn) {
        this.ensureConnected();
        var list = this.subscriptions[kind];
        if (list == undefined) {
          list = [];
          this.subscriptions[kind] = list;
        }
        list.push(fn);
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
          this.openWebsocket();
          window.setInterval(this.openWebsocket, this.connectionTimeout);    
        }
      },
      openWebsocket() {
        if (this.socket == null || this.socket.readyState == WebSocket.CLOSED) {
          const vm = this;
          this.log("WebSocket connecting to " + this.wsUrl);
          this.socket = new WebSocket(this.wsUrl);
          this.socket.onopen = function(evt) {
            vm.log("WebSocket connected");
          };
          this.socket.onclose = function(evt) {
            vm.log("WebSocket closed, will attempt to reconnect");
            vm.socket = null;
          };
          this.socket.onmessage = function(evt) {
            var msg = JSON.parse(evt.data);
            vm.publish(msg.Kind, msg.Object);
          };
          this.socket.onerror = function(evt) {
            vm.log("WebSocket failure: " + evt.data);
          };
        }
      },
      showLogin() {
        location.href = this.authUrl + "login";
      },
      apiSuccessCallback(response) {
        return response;
      },
      apiFailureCallback(error) {
        if (error.response.status === 401) {
          this.showLogin();
        }
        throw error;
      },
      setupApi() {
        this.papi = axios.create({
          baseURL: this.apiUrl,
          timeout: this.connectionTimeout,
        });
        this.papi.interceptors.response.use(this.apiSuccessCallback, this.apiFailureCallback);
      },
      setupAuth() {
        this.authApi = axios.create({
          baseURL: this.authUrl,
          timeout: this.connectionTimeout,
          withCredentials: true,
        });
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
      }
    },
    created() {
      this.log("Initializing");
      if (this.redirectIfAuthCompleted()) return;
      this.loadLocalSettings();
      Vue.filter('formatDateTime', this.formatDateTime);
      Vue.filter('formatDuration', this.formatDuration);
      Vue.filter('formatTimestamp', this.formatTimestamp);
      $('#app')[0].style.display = "block";
      this.setupApi();
      this.setupAuth();
      this.loadInfo();
      this.log("Initialization complete");
    },
  });
});
