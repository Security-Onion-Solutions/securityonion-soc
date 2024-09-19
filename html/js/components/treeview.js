components.push({
	name: "TreeView", component: {
		props: {
			'items': {
				type: Array,
				default: [],
			},
			'depth': {
				type: Number,
				default: 0,
			},
			'selected': {
				type: Array,
				default: [],
			},
			'search': String,
			'item-title': Function,
			'setting-modified': Function,
			'setting-modified-per-node': Function,
			'i18n': Object,
			'deep-search-findings': Array,
		},
		emits: ['update:selected'],
		watch: {
			selected: function() {
				this.selectedId = this.selected[0];
				this.openSelected();
			},
			items: function () {
				if (this.depth === 0) {
					this.leaves = [];
					this.collectLeaves(this.items);
				}
			},
			'deepSearchFindings': function () {
				this.whitelist = this.deepSearchFindings || [];
			},
			search: 'deepSearch',
		},
		setup(_, { emit }) {
			return { emit };
		},
		template: '#component-treeview',
		data() { return {
			selectedId: '',
			leaves: [],
			whitelist: [],
		}},
		mounted() {
			this.selectedId = this.selected[0];
			this.openSelected();

			if (this.depth === 0) {
				this.leaves = [];
				this.collectLeaves(this.items);
			}

			this.whitelist = this.deepSearchFindings || [];
		},
		methods: {
			collectLeaves(items) {
				for (let i = 0; i < items.length; i++) {
					if (items[i].children) {
						this.collectLeaves(items[i].children);
					} else {
						this.leaves.push(items[i]);
					}
				}
			},
			openSelected() {
				if (!this.selectedId) return;
				for (let i = 0; i < this.items.length; i++) {
					if (this.selectedId.startsWith(this.items[i].id)) {
						this.items[i].open = true;
					}
				}
			},
			toggle(item) {
				item.open = !item.open;
			},
			click(item, index) {
				if (item.children) {
					this.toggle(item);
				} else {
					this.selectedId = item.id;
					this.emit('update:selected', [item.id]);
				}
			},
			calcGutter() {
				const dim = this.depth * 32;
				return `${dim}px`;
			},
			passthrough(item) {
				this.selectedId = item[0];
				this.emit('update:selected', item);
			},
			filter(item) {
				if (!this.search) return true;

				return this.whitelist.some(id => id.startsWith(item.id)) ||
					this.search.toLowerCase().startsWith(item.id.toLowerCase()) ||
					item.id.toLowerCase().startsWith(this.search.toLowerCase());
			},
			deepSearch() {
				if (this.depth === 0) {
					this.whitelist = [];

					if (this.search) {
						this.leaves.forEach(leaf => {
							if ((leaf?.name && leaf?.name.toLowerCase().indexOf(this.search) > -1) ||
									(leaf?.id && leaf?.id.toLowerCase().indexOf(this.search) > -1) ||
									(leaf?.value && leaf?.value.toLowerCase().indexOf(this.search) > -1) ||
									(leaf?.nodeValues && [...leaf?.nodeValues.keys()].find(k => k.indexOf(this.search) > -1)) ||
									(leaf?.title && leaf?.title.toLowerCase().indexOf(this.search) > -1) ||
									(leaf?.description && leaf?.description.toLowerCase().indexOf(this.search) > -1)) {
								this.whitelist.push(leaf.id);
							}
						});
					}
				}
			},
			getSettingName(item) {
				return this.itemTitle(item);
			},
			isSettingModified(setting) {
				return this.settingModified(setting);
			},
			isSettingModifiedPerNode(setting) {
				return this.settingModifiedPerNode(setting);
			},
		},
	}
});