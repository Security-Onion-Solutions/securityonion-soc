function fix(el) {
	el.setAttribute('role', 'listitem');
	el.querySelectorAll('.v-list-group__items[role="group"]').forEach(node => {
		node.setAttribute('role', 'list');
	})
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