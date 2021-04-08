// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

// Place common test setup fixtures here for re-use across SOC JS tests.

global.btoa = function(content) {
	return Buffer.from(content, 'binary').toString('base64');
};
global.routes = [];

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
	comp.$root = { i18n: {} };

	const data = global.initComponentData(comp);
	Object.assign(comp, data, comp.methods);

	return comp;
}