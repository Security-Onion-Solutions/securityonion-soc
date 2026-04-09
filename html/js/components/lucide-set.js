// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

function toPascalCase(str) {
  return str.replace(/(^|[-_])(\w)/g, (_, __, c) => c.toUpperCase());
}

if (typeof global !== 'undefined') {
	global.toPascalCase = toPascalCase;
}

const LUCIDE_ICON_DEFAULT_SIZE = 24;

iconSets.push({
	name: "lucide", component: {
		name: 'LucideIcon',
		props: {
			icon: { type: String, required: true },
			color: { type: String, default: 'currentColor' },
			title: { type: String, default: null },
		},
		setup(props) {
			return () => {
				const key = toPascalCase(props.icon);
				const iconData = window.lucide[key];

				if (!iconData) {
					console.warn(`[Lucide] Icon not found: "${key}"`);
					return Vue.h('span', { style: `width:${LUCIDE_ICON_DEFAULT_SIZE}px;height:${LUCIDE_ICON_DEFAULT_SIZE}px;` });
				}
            
				const svgProps = {
					viewBox: `0 0 ${LUCIDE_ICON_DEFAULT_SIZE} ${LUCIDE_ICON_DEFAULT_SIZE}`,
					width: `${LUCIDE_ICON_DEFAULT_SIZE}`,
					height: `${LUCIDE_ICON_DEFAULT_SIZE}`,
					stroke: props.color,
					'stroke-linecap': 'round',
					fill: 'none',
					style: `display:block;vertical-align:middle;width:${LUCIDE_ICON_DEFAULT_SIZE}px;height:${LUCIDE_ICON_DEFAULT_SIZE}px;`,
				};
				const childVNodes = [];

				if (props.title) {
					childVNodes.push(Vue.h('title', props.title));
				}

				for (let i = 0; i < iconData.length; i++) {
					const data = iconData[i];
					const attr = data[0];
					const value = data[1];

					if (typeof value === 'object') {
						// e.g. "path" -> { d: "M..." }  means a child element, not an SVG attr
						childVNodes.push(Vue.h(attr, value));
					} else {
						svgProps[attr] = value;
					}
				}

				return Vue.h('svg', svgProps, childVNodes);
			};
		},
	}
});