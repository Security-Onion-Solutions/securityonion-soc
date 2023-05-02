// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2023 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

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
	app.papi = {};
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

global.mockShowError = function(logError = false) {
	const mock = jest.fn().mockImplementation(err => { if (logError) console.log(err.stack) });
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
global.marked = require('./external/marked-4.3.0.min.js');
global.DOMPurify = require('./external/purify-3.0.2.min.js');
