components.push({
	name: "TreeView", component: {
		props: {
			'item-title': {
				type: Function,
				required: true,
			},
			'setting-modified': {
				type: Function,
				required: true,
			},
			'setting-modified-per-node': {
				type: Function,
				required: true,
			},
			'items': {
				type: Array,
				default: [],
				required: true,
			},
			'depth': {
				type: Number,
				default: 0,
			},
			'selected': {
				type: Array,
				default: [],
			},
			'leaves': {
				type: Array,
				default: [],
			},
			'search': String,
			'i18n': Object,
			'deep-search-findings': Array,
		},
		emits: ['update:selected'],
		watch: {
			'deepSearchFindings': function () {
				this.whitelist = this.deepSearchFindings || [];
			},
			selected: 'processSelected',
			search: 'deepSearch',
		},
		setup(_, { emit }) {
			return { emit };
		},
		template: '#component-treeview',
		data() { return {
			selectedId: '',
			whitelist: [],
		}},
		mounted() {
			this.processSelected();

			this.whitelist = this.deepSearchFindings || [];
		},
		methods: {
			processSelected() {
				this.selectedId = this.selected[0];
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
			click(item) {
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
				this.whitelist = [];
				if (this.depth === 0) {

					if (this.search) {
						const s = this.search.toLowerCase();
						this.leaves.forEach(leaf => {
							if ((leaf?.name && leaf?.name.toLowerCase().indexOf(s) > -1) ||
									(leaf?.id && leaf?.id.toLowerCase().indexOf(s) > -1) ||
									(leaf?.value && leaf?.value.toLowerCase().indexOf(s) > -1) ||
									(leaf?.nodeValues && [...leaf?.nodeValues.keys()].find(k => k.toLowerCase().indexOf(s) > -1)) ||
									(leaf?.title && leaf?.title.toLowerCase().indexOf(s) > -1) ||
									(leaf?.description && leaf?.description.toLowerCase().indexOf(s) > -1)) {
								this.whitelist.push(leaf.id);
							}
						});
					}
				}
			},
		},
	}
});