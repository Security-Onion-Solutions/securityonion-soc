// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

////////////////////////////////////
// Mock jQuery
////////////////////////////////////
global.$ = function(doc) {
  return doc;
};
global.document.ready = function(fn) { fn(); };
global.window.scrollTo = jest.fn();
////////////////////////////////////
// Mock Vue
////////////////////////////////////
var app = null;
global.Vue = function(obj) {
  app = this;
  app.$root = this;
  app.$vuetify = {
    theme: {
      dark: false,
      currentTheme: {}
    }
  };
  app.debug = true;
  Object.assign(app, obj.data, obj.methods);
  this.ensureConnected = jest.fn();
};
global.Vue.delete = function(data, i) {
  data.splice(i, 1);
};
global.Vue.set = function(array, idx, value) {
  array[idx] = value;
};
global.Vue.filter = () => { };
global.Vuetify = function(obj) {};
global.VueRouter = function(obj) {};

////////////////////////////////////
// Test Helper Functions
////////////////////////////////////
global.getApp = function() {
  return app;
}

global.initComponentData = function(comp) {
  return comp.data();
}

global.getComponent = function(name) {
  var comp = null;
  for (var i = 0; i < global.routes.length; i++) {
    if (global.routes[i].name == name) {
      comp = global.routes[i].component;
      break;
    }
  }

  comp.$root = app;

  // Run callback function passed to nextTick
  comp.$nextTick = (fun) => { fun(); }

  // Setup route mock data
  comp.$route = { params: {}};
  comp.$router = [];

  const data = global.initComponentData(comp);
  Object.assign(comp, data, comp.methods, comp.computed);

  return comp;
}

////////////////////////////////////
// Mock API calls
////////////////////////////////////
global.resetPapi = function() {
  app.papi = {
                defaults: {
                  headers: {
                    common: {}
                  }
                }
              };
  return global;
}

global.mockPapi = function(method, mockedResponse, error) {
  mock = app.papi[method];
  if (!mock) {
    mock = jest.fn();
    app.papi[method] = mock;
  }
  if (error) {
    mock.mockImplementation(() => {
      throw error;
    });
  } else {
    mock.mockReturnValueOnce(mockedResponse);
  }
  return mock
}

global.resetAuthApi = function() {
  app.authApi = {
                defaults: {
                  headers: {
                    common: {}
                  }
                }
              };
  return global;
}

global.mockAuthApi = function(method = "get", mockedResponse, error) {
  mock = app.authApi[method];
  if (!mock) {
    mock = jest.fn();
    app.authApi[method] = mock;
  }
  if (error) {
    mock.mockImplementation(() => {
      throw error;
    });
  } else {
    mock.mockReturnValueOnce(mockedResponse);
  }
  return mock
}

global.mockShowError = function(logError = false) {
  const mock = jest.fn().mockImplementation(err => { if (logError) console.log(err.stack ? err.stack : err) });
  app.showError = mock;
  return mock;
}

////////////////////////////////////
// Import SO app modules
////////////////////////////////////
require('./i18n.js');
require('./app.js');

global.JobStatusPending = 0;
global.JobStatusCompleted = 1;
global.JobStatusIncomplete = 2;
global.JobStatusDeleted = 3;

////////////////////////////////////
// Import external dependencies
////////////////////////////////////
global.moment = require('./external/moment-2.29.4.min.js');
global.marked = require('./external/marked-11.1.0.min.js');
global.DOMPurify = require('./external/purify-3.0.6.min.js');
global.jsyaml = require('./external/js-yaml.4.1.0.min.js');
global.LZString = require('./external/lz-string.1.5.0.min.js');

// polyfill for out of date packages we can't import
moment.tz = {
	guess: () => 'Etc/UTC',
}
