// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
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
console.warn = () => { };
////////////////////////////////////
// Mock Vue Internals (not exported)
////////////////////////////////////
class RefImpl {
  constructor(value, __v_isShallow) {
    this.__v_isShallow = __v_isShallow;
    this.dep = void 0;
    this.__v_isRef = true;
    this._rawValue = __v_isShallow ? value : toRaw(value);
    this._value = __v_isShallow ? value : toReactive(value);

    // Wrap _value in a Proxy (handling primitives correctly)
    this._value = new Proxy(isObject(this._value) ? this._value : { value: this._value }, {
      get: (target, prop, receiver) => {
        if (prop === 'value') {
          return target.value;
        }
        return Reflect.get(target, prop, receiver);
      },
      set: (target, prop, value, receiver) => {
        if (prop === 'value') {
          target.value = value;
          return true;
        }
        return Reflect.set(target, prop, value, receiver);
      }
    });
  }
  toJSON() {
    return this.value;
  }
  get value() {
    return this._value;
  }
  set value(newVal) {
    const useDirectValue = this.__v_isShallow || isShallow(newVal) || isReadonly(newVal);
    newVal = useDirectValue ? newVal : toRaw(newVal);
    if (hasChanged(newVal, this._rawValue)) {
      this._rawValue = newVal;
      this._value = useDirectValue ? newVal : toReactive(newVal);
    }
  }
}
const hasChanged = (value, oldValue) => !Object.is(value, oldValue);
const toReactive = (value) => isObject(value) ? reactive(value) : value;
const isObject = (val) => val !== null && typeof val === "object";
function isReadonly(value) {
  return !!(value && value["__v_isReadonly"]);
}
function isShallow(value) {
  return !!(value && value["__v_isShallow"]);
}
function toRaw(observed) {
  const raw = observed && observed["__v_raw"];
  return raw ? toRaw(raw) : observed;
}
function createRef(rawValue, shallow) {
  if (isRef(rawValue)) {
    return rawValue;
  }
  return new RefImpl(rawValue, shallow);
}
function isRef(r) {
  return !!(r && r.__v_isRef === true);
}
function ref(value) {
  return createRef(value, false);
}

////////////////////////////////////
// Mock Vue
////////////////////////////////////
var app = null;
global.Vue = {};
global.Vue.createApp = function(obj) {
  app = this;
  app.$root = this;
  app.$vuetify = {
    theme: {
      current: {
        colors: [],
        dark: false,
      }
    }
  };
  app.debug = true;
  Object.assign(app, obj.data(), obj.methods);
  this.ensureConnected = jest.fn();

  app.use = () => { };
  app.config = { globalProperties: {} };
  app.mount = () => { };

  app.i18n = global.i18n.getLocalizedTranslations('en-US');

  return app;
};
global.Vue.ref = ref;
global.Vue.isRef = isRef;
global.Vuetify = {
  components: { VClassIcon: {} },
  createVuetify: () => { },
  useTheme: () => { return { global: { name: 'dark' } } },
};
global.VueRouter = {
  createRouter: () => { },
  createWebHashHistory: () => { },
};

////////////////////////////////////
// Test Helper Functions
////////////////////////////////////
global.getApp = function() {
  return app;
}

global.initComponentData = function(comp) {
  return comp.data();
}

global.initComponentProps = function (comp) {
  if (!comp.props) return {};

  let props = {};
  if (comp.props instanceof Object) {
    for (let prop in comp.props) {
      const def = comp.props[prop];
      if (def.default !== undefined) {
        props[prop] = def.default;
      } else if (def.type !== undefined) {
        props[prop] = new def.type();
      } else {
        props[prop] = new def();
      }
    }
  }

  return props;
}

global.initComponentSetup = function (comp, props) {
  if (!comp.setup) return {};

  return comp.setup(props, { emit: jest.fn() });
}

global.getComponent = function(name) {
  var comp = null;
  for (var i = 0; i < global.routes.length; i++) {
    if (global.routes[i].name == name) {
      comp = global.routes[i].component;
      break;
    }
  }

  for (var i = 0; i < global.components.length; i++) {
    if (global.components[i].name == name) {
      comp = global.components[i].component;
      break;
    }
  }

  comp.$root = app;

  // Run callback function passed to nextTick
  comp.$nextTick = (fun) => { fun(); }

  // Setup route mock data
  comp.$route = { path: '', query: {}, params: {} };
  const arr = [];
  arr._push = arr.push;
  comp.$router = arr;
  comp.$router.push = (obj) => {
    arr._push(obj);
    return { then: () => { } }
  }
  comp.$router.currentRoute = { value: '' };

  const data = global.initComponentData(comp);
  const props = global.initComponentProps(comp);
  const setup = global.initComponentSetup(comp, props);
  Object.assign(comp, data, comp.methods, comp.computed, props, setup);

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

// stub Promise.all so it's synchronous
const orig = Promise.all;
Promise.all = () => {
  return {
    then: (f) => { f(); },
  }
};

require('./app.js');

// restore Promise.all
Promise.all = orig;

global.FEAT_TTR = 'ttr';
global.JobStatusPending = 0;
global.JobStatusCompleted = 1;
global.JobStatusIncomplete = 2;
global.JobStatusDeleted = 3;

////////////////////////////////////
// Import external dependencies
////////////////////////////////////

// Mock moment dependency location so we can load moment-timezone properly
jest.mock('moment', () => {
  return require('./external/moment-2.30.1.min.js');
}, { virtual: true });

global.moment = require('./external/moment-timezone-with-data-0.5.47.min.js');

moment.tz.setDefault('UTC');

global.marked = require('./external/marked-15.0.12.min.js');
global.DOMPurify = require('./external/purify-3.2.6.min.js');
global.jsyaml = require('./external/js-yaml.4.1.0.min.js');
global.LZString = require('./external/lz-string.1.5.0.min.js');
global.loadPageTemplate = jest.fn();
