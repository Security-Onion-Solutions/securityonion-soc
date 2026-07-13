// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

loadPageTemplate('component-case-details-col', 'pages/case-details-col.html');

components.push({
	name: "CaseDetailsCol", component: {
		props: {
			caseObj:    { type: Object, required: true },
			presets:    { type: Object, required: true },
			hoursTotal: { type: Number, default: 0 },
		},
		emits: ['save'],
		setup(_, { emit }) {
			return { emit };
		},
		template: '#component-case-details-col',
		data() {
			return {
				i18n: this.$root.i18n,
				userList: [],
				expanded: [0, 1],
				editForm: { valid: true },
			};
		},
		async mounted() {
			this.userList = await this.$root.getActiveUsers();
		},
		beforeUnmount() {
			window.removeEventListener("keyup", this.onEditKeyUp);
		},
		methods: {
			isEdit(roId) {
				return this.editForm.roId == roId;
			},
			async startEdit(focusId, val, roId, field, isMultiline) {
				if (this.editForm.focusId == focusId) {
					return;
				}
				if (await this.stopEdit(true)) {
					this.editForm = { valid: true };
					this.editForm.focusId = focusId;
					this.editForm.orig = val;
					this.editForm.val = val;
					this.editForm.roId = roId;
					this.editForm.field = field;
					this.editForm.isMultiline = isMultiline;
					window.addEventListener("keyup", this.onEditKeyUp);
					this.$nextTick(() => {
						const element = document.getElementById(this.editForm.focusId);
						if (element) {
							element.focus();
						}
					});
				}
			},
			async stopEdit(commit = false) {
				let okToClear = true;
				if (commit && this.editForm && this.editForm.field !== undefined) {
					if (this.editForm.valid) {
						if (this.editForm.orig !== this.editForm.val) {
							this.emit('save', { field: this.editForm.field, value: this.editForm.val });
						}
					} else {
						okToClear = false;
					}
				}
				if (okToClear) {
					this.editForm = { valid: true };
					window.removeEventListener("keyup", this.onEditKeyUp);
				}
				return okToClear;
			},
			onEditKeyUp(event) {
				switch (event.key) {
					case 'Escape': this.stopEdit(); break;
					case 'Enter': if (!this.editForm.isMultiline) this.stopEdit(true); break;
				}
			},
			withDefault(value, deflt) {
				if (value == null || value == undefined || value == "") {
					value = deflt;
				}
				return value;
			},
			getPresets(kind) {
				if (this.presets && this.presets[kind]) {
					return this.presets[kind].labels;
				}
				return [];
			},
			isPresetCustomEnabled(kind) {
				if (this.presets && this.presets[kind]) {
					return this.presets[kind].customEnabled == true;
				}
				return false;
			},
			selectList(field, value) {
				let presets = [...this.getPresets(field)];
				if (this.isPresetCustomEnabled(field) && value) {
					if (Array.isArray(value)) {
						for (let v of value) {
							if (!presets.includes(v)) {
								presets.push(v);
							}
						}
					} else {
						if (!presets.includes(value)) {
							presets.push(value);
						}
					}
				}
				return presets;
			},
			colorizeChip(color) {
				if (typeof color === 'string') {
					color = color.split('+')[0];
				}

				if (!this.$root.$vuetify.theme.current.dark) {
					// light mode
					switch (color) {
						case 'white':
							color = 'secondary';
							break;
						case 'red':
							color = 'error';
							break;
						case 'green':
							color = 'success';
							break;
					}
				}

				return color;
			},
		},
	}
});
