// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

loadPageTemplate('component-detection-panel', 'pages/detection-panel.html');

components.push({
	name: "DetectionPanel", component: {
		props: {
			'detection': {
				type: Object,
				required: true,
			},
			'zone': {
				type: String,
				required: true,
			},
			'ackColor': {
				type: String,
				required: true,
			},
			'alertInfo': {
				type: Object, // { item: obj, groupIndex: ?num }
				required: true,
			},
		},
		emits: ['close', 'ack', 'chooseCase', 'highlightPrevAlertDetection', 'highlightNextAlertDetection'],
		setup(_, { emit }) {
			return { emit };
		},
		template: '#component-detection-panel',
		data() {
			return {
				i18n: this.$root.i18n,
				loading: false,
				extractedSummary: '',
				newOverride: null,
				overrideHeaders: {
					'elastalert': [
						{},
						{ title: this.$root.i18n.enabled, value: 'isEnabled' },
						{ title: this.$root.i18n.type, value: 'type', localize: true },
						{ title: this.$root.i18n.dateCreated, value: 'createdAt', format: true },
						{ title: this.$root.i18n.dateModified, value: 'updatedAt', format: true },
					],
					'strelka': [], // no overrides
					'suricata': [
						{},
						{ title: this.$root.i18n.enabled, value: 'isEnabled' },
						{ title: this.$root.i18n.type, value: 'type', localize: true },
						{ title: this.$root.i18n.trackRegex, value: 'track', altValues: ['regex'] },
						{ title: this.$root.i18n.ipVar, value: 'ip', altValues: ['value', 'countPerSecond'] },
						{ title: this.$root.i18n.dateCreated, value: 'createdAt', format: true },
						{ title: this.$root.i18n.dateModified, value: 'updatedAt', format: true },
					],
				},
				rules: {
					required: value => (value && value.length > 0) || this.$root.i18n.required,
					number: value => (!isNaN(+value) && Number.isInteger(parseFloat(value))) || this.$root.i18n.required,
					cidrFormat: value => (!value ||
						/^!?\$[a-z_][a-z0-9_]*$/i.test(value) || // Suricata variable
						/^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\/(3[0-2]|[12]\d|\d)$/.test(value) || // IPv4 CIDR
						/^((([0-9a-f]{1,4}:){7}([0-9a-f]{1,4}|:))|(([0-9a-f]{1,4}:){6}(:[0-9a-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9a-f]{1,4}:){5}(((:[0-9a-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9a-f]{1,4}:){4}(((:[0-9a-f]{1,4}){1,3})|((:[0-9a-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9a-f]{1,4}:){3}(((:[0-9a-f]{1,4}){1,4})|((:[0-9a-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9a-f]{1,4}:){2}(((:[0-9a-f]{1,4}){1,5})|((:[0-9a-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9a-f]{1,4}:){1}(((:[0-9a-f]{1,4}){1,6})|((:[0-9a-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9a-f]{1,4}){1,7})|((:[0-9a-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*(\/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8]))$/i.test(value) // IPv6 CIDR
					) || this.i18n.invalidCidrOrVar,
				},
				ruleValidators: {
					sigma: [
						{ pattern: /^id:\s*[^$]+?$/m, message: this.$root.i18n.invalidDetectionElastAlertMissingID, match: false },
					],
					suricata: [
						{ pattern: /\n/, message: this.$root.i18n.invalidDetectionSuricataNewLine, match: true },
						{ pattern: /sid:\s?(["']?)\d+\1;/, message: this.$root.i18n.invalidDetectionSuricataMissingSID, match: false },
					],
					yara: [
						{ pattern: /rule\s+[a-zA-Z0-9][a-zA-Z0-9_]*/, message: this.$root.i18n.invalidDetectionStrelkaMissingRuleName, match: false },
						{ pattern: /condition:/m, message: this.$root.i18n.invalidDetectionStrelkaMissingCondition, match: false },
					],
				},
				trackOptions: {
					'threshold': ['by_src', 'by_dst'],
					'suppress': ['by_src', 'by_dst', 'by_either'],
				},
				overrideTypes: {
					'suricata': [
						{ title: this.$root.i18n.modify, value: 'modify' },
						{ title: this.$root.i18n.suppress, value: 'suppress' },
						{ title: this.$root.i18n.threshold, value: 'threshold' },
					],
					'elastalert': [
						{ title: this.$root.i18n.customFilter, value: 'customFilter' },
					],
					'strelka': [],
				},
				thresholdTypes: [
					{ title: this.$root.i18n.threshold, value: 'threshold' },
					{ title: this.$root.i18n.limit, value: 'limit' },
					{ title: this.$root.i18n.both, value: 'both' }
				],
				sidExtract: /\bsid: ?['"]?(.*?)['"]?;/, // option
				origDetect: null,
				curEditTarget: null, // string containing element ID, null if not editing
				origValue: null,
				editField: null,
				curOverrideEditTarget: null,
				origOverrideValue: null,
				overrideEditField: null,
				editOverride: null, // the override we're currently editing
				editForm: { valid: true },
				panels: [0, 1],
				ackExistingDialog: false,
				showUnreviewedAiSummaries: false,
			}
		},
		mounted() {
			this.$root.loadParameters('detection', this.initParams);
			this.prepareDetection();
			this.panels = [0, 1];
		},
		methods: {
			prepareDetection() {
				if (this.detection) {
					this.tagOverrides();
					this.extractSummary();
				}
			},
			initParams(params) {
				this.showUnreviewedAiSummaries = !!params?.['showUnreviewedAiSummaries'];
			},
			ack(alreadyAcceptedDialog) {
				this.emit('ack', [this.alertInfo.item, null, false, null, this.alertInfo.groupIndex, true, alreadyAcceptedDialog]);
			},
			escalate(e) {
				this.emit('chooseCase', [e, this.alertInfo.item, this.alertInfo.groupIndex, true]);
			},
			extractSummary() {
				switch (this.detection.engine) {
					case 'suricata':
						const classTypeMatcher = /classtype:([^;]+);/i;
						const match = this.detection.content.match(classTypeMatcher);

						if (match) {
							this.extractedSummary = match[1];
						} else {
							this.extractedSummary = this.detection.title;
						}

						break;
					case 'elastalert':
						const yaml = jsyaml.load(this.detection.content, { schema: jsyaml.FAILSAFE_SCHEMA });
						if (yaml.description) {
							this.extractedSummary = yaml.description;
							break;
						}
						// else fall through
					default:
						if (this.detection.description) {
							this.extractedSummary = this.detection.description;
						} else {
							this.extractedSummary = this.detection.title;
						}
						break;
				}
			},
			showAiSummary() {
				return !!(this?.detection?.aiSummary && (this.detection.aiSummaryReviewed || this.showUnreviewedAiSummaries));
			},
			canAddOverride() {
				return this.detection.engine !== 'strelka';
			},
			createNewOverride() {
				this.newOverride = {
					type: null,
					isEnabled: false,
					regex: null,
					value: null,
					track: null,
					count: null,
					seconds: null,
					customFilter: null,
					note: '',
				};
			},
			async addNewOverride() {
				if (!this.newOverride) return;

				if (!this.detection.overrides) {
					this.detection.overrides = [];
				}

				this.newOverride.isEnabled = true;

				this.detection.overrides.push(this.newOverride);

				const saved = await this.saveDetection();
				if (!saved) {
					this.newOverride = this.detection.overrides.pop();
				} else {
					this.newOverride = null;
				}
			},
			cleanupOverrides() {
				if (this.detection.overrides) {
					for (let i = 0; i < this.detection.overrides.length; i++) {
						this.detection.overrides[i] = this.cleanupOverride(this.detection.engine, this.detection.overrides[i]);
					}
				} else {
					this.detection.overrides = [];
				}
			},
			cleanupOverride(engine, o) {
				// ensures an override about to be saved
				// only has the fields relevant to the engine
				// and type selected
				let out = {
					type: o.type,
					isEnabled: o.isEnabled,
				};

				if (o.createdAt) {
					out.createdAt = o.createdAt;
				}

				if (o.updatedAt) {
					out.updatedAt = o.updatedAt;
				}

				if (typeof o.note === 'string') {
					out.note = o.note;
				}

				if (engine === 'elastalert') {
					out.customFilter = o.customFilter;
				} else {
					switch (o.type) {
						case 'modify':
							out.regex = o.regex;
							out.value = o.value;
							break;
						case 'threshold':
							out.thresholdType = o.thresholdType;
							out.track = o.track;
							out.count = parseInt(o.count);
							out.seconds = parseInt(o.seconds);
							break;
						case 'suppress':
							out.track = o.track;
							out.ip = o.ip;
							break;
					}
				}

				return out;
			},
			tagOverrides() {
				if (this.detection.overrides) {
					for (let i = 0; i < this.detection.overrides.length; i++) {
						this.detection.overrides[i].index = i;
					}
				} else {
					this.detection.overrides = [];
				}
			},
			toggleStatus() {
				if (!this.detection.isEnabled) {
					this.ackExistingDialog = true;
				} else {
					this.saveDetection();
				}
			},
			async saveDetection() {
				if (this.curEditTarget !== null) this.stopEdit(true);

				this.ackExistingDialog = false;

				let err;
				switch (this.detection.language.toLowerCase()) {
					case 'yara':
						err = this.validateStrelka();
						break;
					case 'sigma':
						err = this.validateElastAlert();
						break;
					case 'suricata':
						err = this.validateSuricata();
						break;
				}

				if (err) {
					this.$root.showError(err);
					this.revertEnabled();

					return;
				}

				this.cleanupOverrides();

				try {
					this.loading = true;

					let response = await this.$root.papi.put('/detection', this.detection, {
						validateStatus: (s) => (s >= 200 && s < 300)
					});

					this.extractDetection(response);

					switch (response.status) {
						case 205:
							this.$root.showWarning(this.i18n.WARN_STATUS_EFFECTED_BY_FILTER, true);
							break;
						case 206:
							this.$root.showWarning(this.i18n.disabledFailedSync);
							break;
						default:
							this.$root.showTip(this.i18n.saveSuccess);
							break;
					}

					return true;
				} catch (error) {
					switch (error.response.status) {
						case 409:
							this.$root.showWarning(this.i18n.publicIdConflictErr);
							break;
						default:
							this.$root.showError(error);
							break;
					}

					this.revertEnabled();
				} finally {
					this.loading = false;
				}
			},
			revertEnabled() {
				const route = this;
				this.$nextTick(() => {
					route.detection.isEnabled = route.origDetect.isEnabled;
				});
			},
			extractDetection(response) {
				this.detection = response.data;
				delete this.detection.kind;

				this.tagOverrides();
				this.origDetect = Object.assign({}, this.detection);
				// Don't await the user details -- takes too long for the task scheduler to
				// complete all these futures when looping across hundreds of records. Let
				// the UI update as they finish, for a better user experience.
				this.$root.populateUserDetails(this.detection, "userId", "userName");
			},
			async startEdit(target, field) {
				if (this.curEditTarget === target) return;
				if (this.curEditTarget !== null) await this.stopEdit(false);
				if (this.detection.isCommunity && field !== 'isEnabled') return;

				this.curEditTarget = target;
				this.origValue = this.detection[field];
				this.editField = field;

				this.$nextTick(() => {
					const el = document.getElementById(target + '-edit');
					if (el) {
						el.focus();
						el.select();
					}
				});
			},
			isEdit(target) {
				return this.curEditTarget === target;
			},
			stopEdit(commit) {
				if (!commit) {
					this.detection[this.editField] = this.origValue;
				}

				this.curEditTarget = null;
				this.origValue = null;
				this.editField = null;

				if (commit) {
					this.saveDetection().then(() => {
						this.curEditTarget = null;
					});
				}
			},
			verifyRuleSyntax() {
				const rules = this.ruleValidators[this.detection.language.toLowerCase()];
				for (let i = 0; i < rules.length; i++) {
					if (rules[i].pattern.test(this.detection.content) === rules[i].match) {
						return rules[i].message;
					}
				}

				return null;
			},
			validateStrelka() {
				try {
					let err = this.verifyRuleSyntax();
					if (err) {
						return err;
					}

					return null;
				} catch (e) {
					return e;
				}
			},
			validateElastAlert() {
				try {
					let err = this.verifyRuleSyntax();
					if (err) {
						return err;
					}

					const id = this.extractElastAlertPublicID();
					if (this.detection.publicId && this.detection.publicId !== id) {
						throw this.i18n.idMismatchErr;
					}

					return null;
				} catch (e) {
					return e;
				}
			},
			validateSuricata() {
				try {
					let err = this.verifyRuleSyntax();
					if (err) {
						return err;
					}

					const sid = this.extractSuricataPublicID();

					if (this.detection.publicId !== sid) {
						// sid doesn't match metadata
						return this.i18n.invalidDetectionSuricataSIDMismatch;
					}
				} catch (e) {
					return e;
				}

				// normalize quotes
				this.detection.content = this.detection.content.replaceAll('”', '"');
				this.detection.content = this.detection.content.replaceAll('“', '"');

				return null;
			},
			extractSuricataPublicID() {
				const results = this.sidExtract.exec(this.detection.content);
				if (results === null || results.length < 2) {
					throw this.i18n.sidMissingErr;
				}

				return results[1];
			},
			extractElastAlertPublicID() {
				const yaml = jsyaml.load(this.detection.content, {schema: jsyaml.FAILSAFE_SCHEMA});
				return yaml['id'];
			},
			pickValue(item, field) {
				let value = '';
				if (field.value in item) {
					value = item[field.value];
				} else if (field.altValues) {
					for (let i = 0; i < field.altValues.length; i++) {
						if (field.altValues[i] === 'countPerSecond') {
							value = `${item.count} / ${item.seconds}`;
							break;
						} else if (item[field.altValues[i]]) {
							value = item[field.altValues[i]];
							break;
						}
					}
				}

				if (field.localize) {
					value = this.$root.tryLocalize(value);
				}

				return value;
			},
			async startOverrideEdit(target, override, field) {
				if (this.curOverrideEditTarget === target) return;
				if (this.curOverrideEditTarget !== null) await this.stopOverrideEdit(false);

				this.curOverrideEditTarget = target;
				this.origOverrideValue = override[field];
				this.overrideEditField = field;
				this.editOverride = override;

				this.$nextTick(() => {
					const el = document.getElementById(target + '-edit');
					if (el) {
						el.focus();
						el.select();
					}
				});
			},
			isOverrideEdit(target) {
				return this.curOverrideEditTarget === target;
			},
			stopOverrideEdit(commit, saveFunc) {
				saveFunc = saveFunc || this.saveDetection;
				if (commit && this.$refs[this.curOverrideEditTarget].hasError) return;

				if (!commit) {
					this.editOverride[this.overrideEditField] = this.origOverrideValue;
				} else {
					this.$nextTick(async () => {
						await saveFunc(false);
						this.curOverrideEditTarget = null;
					});
				}

				this.curOverrideEditTarget = null;
				this.origOverrideValue = null;
				this.overrideEditField = null;
				this.editOverride = null;
			},
			isFieldValid(refName) {
				const ref = this.$refs[refName];
				if (ref) {
					if (ref?.classList) {
						return !ref.classList.contains('v-input--error');
					}

					return false;
				}

				return true;
			},
			async saveOverrideNote(item) {
				try {
					this.loading = true;
					await this.$root.papi.put('/detection/' + this.detection.id + '/override/' + item.index + '/note', { note: item.note });
				} catch (error) {
					this.$root.showError(error);
				} finally {
					this.loading = false;
				}
			},
			deleteOverride(item) {
				this.detection.overrides = this.detection.overrides.filter(o => o !== item);
				this.saveDetection(false);
			},
			closeDetectionPanel() {
				this.emit('close');
			}
		},
	}
});
