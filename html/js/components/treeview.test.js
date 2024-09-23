// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js');
require('./treeview.js');

let comp;

beforeEach(() => {
  comp = getComponent("TreeView");
});

test('mounted', () => {
	// depth = 0
	comp.selected = ['a.x.y'];
	comp.deepSearchFindings = ['a', 'b', 'c'];
	comp.items = [
		{ id: 'a' },
		{ id: 'b' },
		{ id: 'c' },
	];
	comp.mounted();
	expect(comp.selectedId).toBe('a.x.y');
	expect(comp.items[0].open).toBe(true);
	expect(comp.items[1].open).toBe(undefined);
	expect(comp.items[2].open).toBe(undefined);
	expect(comp.whitelist).toStrictEqual(['a', 'b', 'c']);

	// depth = 1
	comp.selected = ['a.x.y'];
	comp.items = [
		{ id: 'a.h' },
		{ id: 'a.x' },
		{ id: 'a.m' },
	];
	comp.mounted();
	expect(comp.selectedId).toBe('a.x.y');
	expect(comp.items[0].open).toBe(undefined);
	expect(comp.items[1].open).toBe(true);
	expect(comp.items[2].open).toBe(undefined);
	expect(comp.whitelist).toStrictEqual(['a', 'b', 'c']);
});

test('deepSearch', () => {
	let nodes = new Map();
	nodes.set('fOo', true);

	let otherNodes = new Map();
	otherNodes.set('fu', 'foo');

	comp.depth = 0;
	comp.search = 'foO';
	comp.leaves = [
		{ id: 'a.x.y', name: 'FOO' },
		{ id: 'b.m', nodeValues: nodes },
		{ id: 'c.i', value: 'fool' },
		{ id: 'd.p.q.e', title: 'The Great Foo' },
		{ id: 'e', description: 'foo bar' },
		{ id: 'h._foo' },
		{ id: 'g', name: 'fu', nodeValues: otherNodes, value: 'fu', title: 'fu', description: 'fu' },
	];
	comp.deepSearch();
	expect(comp.whitelist).toStrictEqual(['a.x.y', 'b.m', 'c.i', 'd.p.q.e', 'e', 'h._foo']);

	// only the root node executes the search
	comp.depth = 1;
	comp.deepSearch();
	expect(comp.whitelist).toStrictEqual([]);
});

test('filter', () => {
	let result = comp.filter({ id: 'foobar' });
	expect(result).toBe(true);

	comp.search = 'a.b.c';
	comp.whitelist = ['exception.x'];

	result = comp.filter({ id: 'a' });
	expect(result).toBe(true);

	result = comp.filter({ id: 'a.b' });
	expect(result).toBe(true);

	result = comp.filter({ id: 'a.b.c' });
	expect(result).toBe(true);

	result = comp.filter({ id: 'a.b.c.d' });
	expect(result).toBe(true);

	result = comp.filter({ id: 'foo' });
	expect(result).toBe(false);

	result = comp.filter({ id: 'b.c' });
	expect(result).toBe(false);

	result = comp.filter({ id: 'exception' });
	expect(result).toBe(true);

	result = comp.filter({ id: 'exception.x' })
	expect(result).toBe(true);

	result = comp.filter({ id: 'exception.x.y' })
	expect(result).toBe(false);

	result = comp.filter({ id: 'a.exception' });
	expect(result).toBe(false);
});

test('click', () => {
	comp.emit = jest.fn();
	let item = { id: 'a', children: [{ id: 'a.b' }] };

	comp.click(item);
	expect(item.open).toBe(true);

	comp.click(item);
	expect(item.open).toBe(false);

	comp.click(item);
	expect(item.open).toBe(true);

	item.children = null;

	comp.click(item);
	expect(item.open).toBe(true);
	expect(comp.selectedId).toBe('a');
	expect(comp.emit).toHaveBeenCalledWith('update:selected', ['a']);

	comp.click(item);
	expect(item.open).toBe(true);
	expect(comp.selectedId).toBe('');
	expect(comp.emit).toHaveBeenCalledWith('update:selected', []);
});

test('calcGutter', () => {
	let expected = ['0px', '32px', '64px', '96px', '128px', '160px'];
	for (let i = 0; i < expected.length; i++) {
		comp.depth = i;
		expect(comp.calcGutter()).toBe(expected[i]);
	}
});

test('toggle', () => {
	let item = {};
	comp.toggle(item);
	expect(item.open).toBe(true);
	comp.toggle(item);
	expect(item.open).toBe(false);
	comp.toggle(item);
	expect(item.open).toBe(true);
});

test('passthrough', () => {
	comp.emit = jest.fn();

	comp.passthrough(['a']);
	expect(comp.selectedId).toBe('a');
	expect(comp.emit).toHaveBeenCalledWith('update:selected', ['a']);
});
