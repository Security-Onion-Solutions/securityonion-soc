// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js');
require('./colors.js');

const comp = getComponent("colors");

test('textTokensFor flattens and dedupes groups', () => {
    const tokens = comp.textTokensFor({ text: ['semantic', 'context'] });
    expect(tokens).toContain('warning');
    expect(tokens).toContain('amber');
    // 'success' is in both groups but must only appear once
    expect(tokens.filter(t => t === 'success')).toHaveLength(1);

    expect(comp.textTokensFor({})).toEqual([]);
});

test('oppositeBackground returns the other theme\'s background color', () => {
    comp.$root.theme = { themes: {
        dark: { colors: { background: '#0b1019' } },
        light: { colors: { background: '#ffffff' } },
    }};
    expect(comp.oppositeBackground('dark')).toBe('#ffffff');
    expect(comp.oppositeBackground('light')).toBe('#0b1019');
});

test('oppositeBackground falls back to black/white when the theme is unavailable', () => {
    comp.$root.theme = null;
    expect(comp.oppositeBackground('dark')).toBe('#ffffff');
    expect(comp.oppositeBackground('light')).toBe('#000000');
});

test('iconTokensFor resolves icon groups', () => {
    expect(comp.iconTokensFor({ icons: ['severity'] }))
        .toEqual(['yellow', 'orange-darken-1', 'red-lighten-1', 'red-darken-4', 'icon']);
    expect(comp.iconTokensFor({})).toEqual([]);
});

test('chipsFor returns color/variant pairs for every production variant', () => {
    const chips = comp.chipsFor({ chips: ['status'] }, 'dark');
    expect(chips).toContainEqual({ color: 'gray', variant: 'tonal' });
    expect(chips).toContainEqual({ color: 'gray', variant: 'flat' });
    expect(chips).toHaveLength(comp.chipGroups.status.colors.length * 2);

    expect(comp.chipsFor({ chips: ['hunt'] }, 'dark')).toEqual([{ color: 'secondary', variant: 'tonal' }]);
    expect(comp.chipsFor({}, 'dark')).toEqual([]);
});

test('chipsFor dedupes color/variant pairs across groups', () => {
    const chips = comp.chipsFor({ chips: ['status', 'toolStatus'] }, 'dark');
    // toolStatus flat chips overlap with the flat status chips
    expect(chips.filter(c => c.color === 'success' && c.variant === 'flat')).toHaveLength(1);
});

test('chipsFor applies the light-theme remap like colorizeChip does', () => {
    const dark = comp.chipsFor({ chips: ['tlp'] }, 'dark');
    expect(dark).toContainEqual({ color: 'white', variant: 'tonal' });
    expect(dark).toContainEqual({ color: 'amber', variant: 'outlined' });
    expect(dark).toContainEqual({ color: 'red', variant: 'outlined' });

    const light = comp.chipsFor({ chips: ['tlp'] }, 'light');
    expect(light.filter(c => c.color === 'white')).toHaveLength(0);
    expect(light.filter(c => c.color === 'red')).toHaveLength(0);
    expect(light.filter(c => c.color === 'green')).toHaveLength(0);
    // amber passes through untouched; grey/orange never render in either theme
    expect(light).toContainEqual({ color: 'amber', variant: 'tonal' });
    expect(light).toContainEqual({ color: 'amber', variant: 'outlined' });
    ['grey', 'orange'].forEach((color) => {
        expect(dark.filter(c => c.color === color)).toHaveLength(0);
        expect(light.filter(c => c.color === color)).toHaveLength(0);
    });
    // the remapped colors have no existing entries to collapse into
    expect(light.filter(c => c.color === 'secondary' && c.variant === 'tonal')).toHaveLength(1);
    expect(light.filter(c => c.color === 'secondary' && c.variant === 'outlined')).toHaveLength(1);
    expect(light.filter(c => c.color === 'error' && c.variant === 'tonal')).toHaveLength(1);
    expect(light.filter(c => c.color === 'error' && c.variant === 'outlined')).toHaveLength(1);
    expect(light.filter(c => c.color === 'success' && c.variant === 'tonal')).toHaveLength(1);
    expect(light.filter(c => c.color === 'success' && c.variant === 'outlined')).toHaveLength(1);
});

test('themeColorNames filters on-, variation, and foreground-only keys', () => {
    comp.$root.theme = { themes: { dark: { colors: {
        primary: '#007CAD',
        'on-primary': '#fff',
        'primary-lighten-1': '#333',
        'primary-darken-2': '#111',
        altprimary: '#4FC3F7',
        nav_background_link: '#039FDD',
        text: '#EEE',
        icon: '#CCC',
        row_hover: '#2a3452',
    }}}};
    expect(comp.themeColorNames('dark')).toEqual(['primary', 'row_hover']);
    expect(comp.themeColorNames('missing')).toEqual([]);
});

test('excluded matches exact combinations', () => {
    const surface = { exceptions: ['chip:purple/outlined', 'text:warning'] };
    expect(comp.excluded(surface, 'chip', 'purple/outlined')).toBe(true);
    expect(comp.excluded(surface, 'chip', 'purple/tonal')).toBe(false);
    expect(comp.excluded(surface, 'chip', 'red/outlined')).toBe(false);
    expect(comp.excluded(surface, 'text', 'warning')).toBe(true);
    // kind must match, not just the value
    expect(comp.excluded(surface, 'icon', 'warning')).toBe(false);
});

test('excluded matches wildcard and prefix entries', () => {
    // omitted trailing segment matches all variants
    expect(comp.excluded({ exceptions: ['chip:purple'] }, 'chip', 'purple/outlined')).toBe(true);
    expect(comp.excluded({ exceptions: ['chip:purple'] }, 'chip', 'purple/tonal')).toBe(true);
    expect(comp.excluded({ exceptions: ['chip:purple'] }, 'chip', 'red/tonal')).toBe(false);
    // explicit '*' segment
    expect(comp.excluded({ exceptions: ['chip:purple/*'] }, 'chip', 'purple/flat')).toBe(true);
    expect(comp.excluded({ exceptions: ['chip:*/outlined'] }, 'chip', 'green/outlined')).toBe(true);
    expect(comp.excluded({ exceptions: ['chip:*/outlined'] }, 'chip', 'green/tonal')).toBe(false);
    // entries with more segments than the value never match
    expect(comp.excluded({ exceptions: ['text:warning/extra'] }, 'text', 'warning')).toBe(false);
});

test('excluded handles missing or empty exceptions', () => {
    expect(comp.excluded({}, 'text', 'warning')).toBe(false);
    expect(comp.excluded({ exceptions: [] }, 'text', 'warning')).toBe(false);
});

test('textTokensFor and iconTokensFor drop excepted tokens', () => {
    const tokens = comp.textTokensFor({ text: ['semantic'], exceptions: ['text:warning'] });
    expect(tokens).not.toContain('warning');
    expect(tokens).toContain('success');

    const icons = comp.iconTokensFor({ icons: ['severity'], exceptions: ['icon:yellow'] });
    expect(icons).not.toContain('yellow');
    expect(icons).toContain('icon');
});

test('chipsFor drops excepted color/variant pairs', () => {
    const exact = comp.chipsFor({ chips: ['status'], exceptions: ['chip:gray/flat'] }, 'dark');
    expect(exact).not.toContainEqual({ color: 'gray', variant: 'flat' });
    expect(exact).toContainEqual({ color: 'gray', variant: 'tonal' });

    const allGray = comp.chipsFor({ chips: ['status'], exceptions: ['chip:gray'] }, 'dark');
    expect(allGray.filter(c => c.color === 'gray')).toHaveLength(0);
    expect(allGray).toContainEqual({ color: 'success', variant: 'flat' });

    const allFlat = comp.chipsFor({ chips: ['status'], exceptions: ['chip:*/flat'] }, 'dark');
    expect(allFlat.filter(c => c.variant === 'flat')).toHaveLength(0);
    expect(allFlat).toHaveLength(comp.chipGroups.status.colors.length);
});

test('chipsFor matches exceptions after the light-theme remap', () => {
    // amber remaps to orange in the light theme, so an orange exception removes it there
    const light = comp.chipsFor({ chips: ['tlp'], exceptions: ['chip:orange/outlined'] }, 'light');
    expect(light.filter(c => c.color === 'orange' && c.variant === 'outlined')).toHaveLength(0);
    // in the dark theme amber renders as amber and is unaffected
    const dark = comp.chipsFor({ chips: ['tlp'], exceptions: ['chip:orange/outlined'] }, 'dark');
    expect(dark).toContainEqual({ color: 'amber', variant: 'outlined' });
    expect(dark.filter(c => c.color === 'orange' && c.variant === 'outlined')).toHaveLength(0);
});

test('buttonsFor, alertsFor, and progressFor filter their exceptions', () => {
    expect(comp.buttonsFor({})).toEqual(comp.buttonColors);
    expect(comp.buttonsFor({ exceptions: ['button:light-green'] })).not.toContain('light-green');

    expect(comp.alertsFor({})).toEqual(comp.alertTypes);
    expect(comp.alertsFor({ exceptions: ['alert:info'] })).toEqual(['warning', 'error']);

    expect(comp.progressFor({})).toEqual([]);
    expect(comp.progressFor({ progress: ['success', 'error'], exceptions: ['progress:error'] }))
        .toEqual(['success']);
});

test('configured exceptions exclude the audited non-production combos', () => {
    const surface = (name) => comp.surfaces.find(s => s.name === name);

    // background: flat license chips only exist in the footer (nav_background section)
    const backgroundChips = comp.chipsFor(surface('background'), 'dark');
    expect(backgroundChips.length).toBeGreaterThan(0);
    expect(backgroundChips.filter(c => c.variant === 'flat')).toHaveLength(0);

    // nav_background: footer license chips are always flat, never tonal
    const navChips = comp.chipsFor(surface('nav_background'), 'dark');
    expect(navChips.length).toBeGreaterThan(0);
    expect(navChips.filter(c => c.variant === 'tonal')).toHaveLength(0);

    // background: success text only occurs on drawer_background stat pills
    const backgroundText = comp.textTokensFor(surface('background'));
    expect(backgroundText).not.toContain('success');
    expect(backgroundText).toEqual(expect.arrayContaining(['text', 'primary', 'error', 'info', 'warning']));

    // table_background: semantic text never renders in tables except default/primary
    expect(comp.textTokensFor(surface('table_background'))).toEqual(['text', 'primary']);

    // table_background: production "teal lighten-2" is invalid in Vuetify 3, renders colorless
    const tableChips = comp.chipsFor(surface('table_background'), 'dark');
    expect(tableChips.filter(c => c.color === 'teal-lighten-2')).toHaveLength(0);
    expect(tableChips).toContainEqual({ color: 'cyan', variant: 'tonal' });
});

test('every surface references only defined groups', () => {
    comp.surfaces.forEach((surface) => {
        (surface.text || []).forEach(g => expect(comp.textGroups[g]).toBeDefined());
        (surface.icons || []).forEach(g => expect(comp.iconGroups[g]).toBeDefined());
        (surface.chips || []).forEach(g => expect(comp.chipGroups[g]).toBeDefined());
        if (surface.progress) {
            expect(Array.isArray(surface.progress)).toBe(true);
            expect(surface.progress.length).toBeGreaterThan(0);
        }
        (surface.exceptions || []).forEach(e =>
            expect(e).toMatch(/^(text|icon|chip|button|alert|progress):/));
    });
});
