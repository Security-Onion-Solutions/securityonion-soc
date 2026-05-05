// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js');
require('./fix-group-role.js');

const entry = directives.find(d => d.name === 'fixGroupRole');

test('directive is registered with mounted and updated hooks', () => {
	expect(entry).toBeDefined();
	expect(typeof entry.directive.mounted).toBe('function');
	expect(typeof entry.directive.updated).toBe('function');
});

test('mounted sets role=listitem on a v-list-group host element', () => {
	const el = document.createElement('div');
	el.classList.add('v-list-group');
	entry.directive.mounted(el, {});
	expect(el.getAttribute('role')).toBe('listitem');
});

test('mounted does not change role on a host without v-list-group class', () => {
	const el = document.createElement('div');
	entry.directive.mounted(el, {});
	expect(el.getAttribute('role')).toBeNull();
});

test('mounted rewrites nested v-list-group__items[role="group"] to role="list"', () => {
	const el = document.createElement('div');
	el.classList.add('v-list-group');
	el.innerHTML = `
		<div class="v-list-group__items" role="group" id="a"></div>
		<div class="wrapper">
			<div class="v-list-group__items" role="group" id="b"></div>
		</div>
	`;
	entry.directive.mounted(el, {});
	expect(el.querySelector('#a').getAttribute('role')).toBe('list');
	expect(el.querySelector('#b').getAttribute('role')).toBe('list');
});

test('mounted ignores .v-list-group__items without role="group"', () => {
	const el = document.createElement('div');
	el.classList.add('v-list-group');
	el.innerHTML = `<div class="v-list-group__items" role="menu" id="a"></div>`;
	entry.directive.mounted(el, {});
	expect(el.querySelector('#a').getAttribute('role')).toBe('menu');
});

test('mounted rewrites .v-list-item[role="link"] descendants to role="listitem"', () => {
	const el = document.createElement('div');
	el.innerHTML = `
		<div class="v-list-item" role="link" id="a"></div>
		<div class="wrapper">
			<div class="v-list-item" role="link" id="b"></div>
		</div>
		<div class="v-list-item" role="listitem" id="c"></div>
		<div class="v-list-item" role="option" id="d"></div>
	`;
	entry.directive.mounted(el, {});
	expect(el.querySelector('#a').getAttribute('role')).toBe('listitem');
	expect(el.querySelector('#b').getAttribute('role')).toBe('listitem');
	expect(el.querySelector('#c').getAttribute('role')).toBe('listitem');
	expect(el.querySelector('#d').getAttribute('role')).toBe('option');
});

test('mounted rewrites .v-list-group__header[role="option"] activators to role="button" and strips aria-selected', () => {
	const el = document.createElement('div');
	el.innerHTML = `
		<div class="v-list-item v-list-group__header" role="option" aria-selected="false" id="a"></div>
		<div class="v-list-item v-list-group__header" role="listitem" id="b"></div>
		<div class="v-list-item" role="option" aria-selected="false" id="c"></div>
	`;
	entry.directive.mounted(el, {});
	expect(el.querySelector('#a').getAttribute('role')).toBe('button');
	expect(el.querySelector('#a').hasAttribute('aria-selected')).toBe(false);
	expect(el.querySelector('#b').getAttribute('role')).toBe('listitem');
	expect(el.querySelector('#c').getAttribute('role')).toBe('option');
	expect(el.querySelector('#c').getAttribute('aria-selected')).toBe('false');
});

test('mounted leaves unrelated children untouched', () => {
	const el = document.createElement('div');
	el.classList.add('v-list-group');
	el.innerHTML = `<span id="a" role="button">x</span>`;
	entry.directive.mounted(el, {});
	expect(el.getAttribute('role')).toBe('listitem');
	expect(el.querySelector('#a').getAttribute('role')).toBe('button');
});

test('updated behaves identically to mounted', () => {
	const el = document.createElement('div');
	el.classList.add('v-list-group');
	el.innerHTML = `
		<div class="v-list-group__items" role="group" id="a"></div>
		<div class="v-list-item" role="link" id="b"></div>
	`;
	entry.directive.updated(el, {});
	expect(el.getAttribute('role')).toBe('listitem');
	expect(el.querySelector('#a').getAttribute('role')).toBe('list');
	expect(el.querySelector('#b').getAttribute('role')).toBe('listitem');
});

test('is idempotent when invoked twice', () => {
	const el = document.createElement('div');
	el.classList.add('v-list-group');
	el.innerHTML = `
		<div class="v-list-group__items" role="group" id="a"></div>
		<div class="v-list-item" role="link" id="b"></div>
	`;
	entry.directive.mounted(el, {});
	entry.directive.mounted(el, {});
	expect(el.getAttribute('role')).toBe('listitem');
	expect(el.querySelector('#a').getAttribute('role')).toBe('list');
	expect(el.querySelector('#b').getAttribute('role')).toBe('listitem');
});
