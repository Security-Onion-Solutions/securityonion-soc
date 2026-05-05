function fix(el) {
	if (el.classList.contains('v-list-group')) {
		el.setAttribute('role', 'listitem');
	}
	el.querySelectorAll('.v-list-group__items[role="group"]').forEach(node => {
		node.setAttribute('role', 'list');
	});
	el.querySelectorAll('.v-list-item[role="link"]').forEach(node => {
		node.setAttribute('role', 'listitem');
	});
	el.querySelectorAll('.v-list-group__header[role="option"]').forEach(node => {
		node.setAttribute('role', 'button');
		node.removeAttribute('aria-selected');
	});
}

directives.push({
	name: 'fixGroupRole', directive: {
		mounted(el, binding) {
			fix(el);
		},
		updated(el, binding) {
			fix(el);
		},
	}
});