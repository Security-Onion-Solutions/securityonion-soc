// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

function debounce(fn, wait) {
	let timer;
	return (...args) => {
		if(timer) {
			clearTimeout(timer); // clear any pre-existing timer
		}

		const context = this; // get the current context
		timer = setTimeout(()=>{
			fn.apply(context, args); // call the function if time expires
		}, wait);
	}
}

routes.push({ path: '/detection/:id', name: 'detection', component: {
	template: '#page-detection',
	data() {
		return {
			i18n: this.$root.i18n,
			presets: {},
			severityTranslations: {},
			params: {},
			detect: null,
			origDetect: null,
			curEditTarget: null, // string containing element ID, null if not editing
			origValue: null,
			editField: null,
			curOverrideEditTarget: null,
			origOverrideValue: null,
			overrideEditField: null,
			editOverride: null, // the override we're currently editing
			editForm: { valid: true },
			commentsForm: { valid: true, value: '' },
			rules: {
				required: value => (value && value.length > 0) || this.$root.i18n.required,
				number: value => (!isNaN(+value) && Number.isInteger(parseFloat(value))) || this.$root.i18n.required,
				hours: value => (!value || /^\d{1,4}(\.\d{1,4})?$/.test(value)) || this.$root.i18n.invalidHours,
				minLength: limit => value => (value && value.length >= limit) || this.$root.i18n.ruleMinLen,
				shortLengthLimit: value => (value.length < 100) || this.$root.i18n.required,
				longLengthLimit: value => (encodeURI(value).split(/%..|./).length - 1 < 10000000) || this.$root.i18n.required,
				fileSizeLimit: value => (value == null || value.size < this.maxUploadSizeBytes) || this.$root.i18n.fileTooLarge.replace("{maxUploadSizeBytes}", this.$root.formatCount(this.maxUploadSizeBytes)),
				fileNotEmpty: value => (value == null || value.size > 0) || this.$root.i18n.fileEmpty,
				fileRequired: value => (value != null) || this.$root.i18n.required,
				cidrFormat: value => (!value ||
					/^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\/(3[0-2]|[12]\d|\d)$/.test(value) || // IPv4 CIDR
					/^((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*(\/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8]))$/.test(value) // IPv6 CIDR
				) || this.i18n.invalidCidr,
			},
			panel: [0, 1, 2],
			activeTab: '',
			sidExtract: /\bsid: ?['"]?(.*?)['"]?;/, // option
			severityExtract: /\bsignature_severity ['"]?(.*?)['"]?[,;]/, // metadata
			sortBy: 'createdAt',
			sortDesc: false,
			expanded: [],
			overrideHeaders: [
				{ text: 'Enabled', value: 'isEnabled' },
				{ text: 'Type', value: 'type' },
				{ text: 'Track', value: 'track' },
				{ text: 'Created', value: 'createdAt', format: true },
				{ text: 'Updated', value: 'updatedAt', format: true },
			],
			zone: moment.tz.guess(),
			newOverride: null,
			thresholdTypes: [
				{ value: 'threshold', text: 'Threshold' },
				{ value: 'limit', text: 'Limit' },
				{ value: 'both', text: 'Both' }
			],
			historyTableOpts: {
				sortBy: 'updateTime',
				sortDesc: false,
				search: '',
				headers: [
					{ text: this.$root.i18n.actions, width: '10.0em' },
					{ text: this.$root.i18n.username, value: 'owner' },
					{ text: this.$root.i18n.time, value: 'updateTime' },
					{ text: this.$root.i18n.kind, value: 'kind' },
					{ text: this.$root.i18n.operation, value: 'operation' },
				],
				itemsPerPage: 10,
				footerProps: { 'items-per-page-options': [10, 50, 250, 1000] },
				count: 500,
				expanded: [],
				loading: false,
			},
			extractedSummary: '',
			extractedReferences: [],
			extractedLogic: '',
			history: [],
			extractedCreated: '',
			extractedUpdated: '',
			comments: [],
			commentsTable: {
				showAll: false,
				sortBy: 'createTime',
				sortDesc: false,
				search: '',
				headers: [
					{ text: this.$root.i18n.username, value: 'owner' },
					{ text: this.$root.i18n.dateCreated, value: 'createTime' },
					{ text: this.$root.i18n.dateModified, value: 'updateTime' },
					{ text: this.$root.i18n.commentDescription, value: 'description' },
				],
				itemsPerPage: 10,
				footerProps: { 'items-per-page-options': [10, 50, 250, 1000] },
				count: 500,
				expanded: [],
				loading: false,
			},
			renderAbbreviatedCount: 30,
			curCommentEditTarget: null,
			origComment: null,
			showSigmaDialog: false,
			convertedRule: '',
			confirmDeleteDialog: false,
			showDirtySourceDialog: false,
	}},
	created() {
		this.onDetectionChange = debounce(this.onDetectionChange, 300);
	},
	watch: {
	},
	mounted() {
		this.$watch(
			() => this.$route.params,
			(to, prev) => {
				this.loadData();
			});
		this.$root.loadParameters('detection', this.initDetection);
	},
	methods: {
		async initDetection(params) {
			this.params = params;
			this.presets = params['presets'];
			this.renderAbbreviatedCount = params["renderAbbreviatedCount"];
			this.severityTranslations = params['severityTranslations'];

			if (this.$route.params.id === 'create') {
				this.detect = this.newDetection();
			} else {
				await this.loadData();
			}

			this.origDetect = Object.assign({}, this.detect);

			this.loadUrlParameters();
		},
		loadUrlParameters() {
			this.$nextTick(() => {
				if (this.$route.query.tab) {
					this.activeTab = this.$route.query.tab;
				}
			});
		},
		newDetection() {
			return {
				title: this.i18n.detectionDefaultTitle,
				description: this.i18n.detectionDefaultDescription,
				author: '',
				publicId: '',
				severity: this.getDefaultPreset('severity'),
				content: '',
				isEnabled: false,
				isReporting: false,
				engine: '',
			}
		},
		async loadData() {
			this.$root.startLoading();

			try {
				const response = await this.$root.papi.get('detection/' + encodeURIComponent(this.$route.params.id));
				this.extractDetection(response);
			} catch (error) {
				if (error.response != undefined && error.response.status == 404) {
					this.$root.showError(this.i18n.notFound);
				} else {
					this.$root.showError(error);
				}
			}

			this.$root.stopLoading();
		},
		extractDetection(response) {
			this.detect = response.data;
			delete this.detect.kind;

			this.tagOverrides();
			this.loadAssociations();
			this.origDetect = Object.assign({}, this.detect);
			// Don't await the user details -- takes too long for the task scheduler to
			// complete all these futures when looping across hundreds of records. Let
			// the UI update as they finish, for a better user experience.
			this.$root.populateUserDetails(this.detect, "userId", "userName");
		},
		loadAssociations() {
			this.extractSummary();
			this.extractReferences();
			this.extractLogic();
			this.extractDetails();
			this.loadHistory();
			this.loadComments();
		},
		extractSummary() {
			switch (this.detect.engine) {
				case 'suricata':
					const classTypeMatcher = /classtype:([^;]+);/i;
					const match = this.detect.content.match(classTypeMatcher);

					if (match) {
						this.extractedSummary = match[1];
					} else {
						this.extractedSummary = this.detect.title;
					}

					break;
				default:
					if (this.detect.description) {
						this.extractedSummary = this.detect.description;
					} else {
						this.extractedSummary = this.detect.title;
					}
					break;
			}
		},
		extractReferences() {
			this.extractedReferences = [];

			switch (this.detect.engine) {
				case 'suricata':
					this.extractSuricataReferences();
					break;
				case 'strelka':
					this.extractStrelkaReferences();
					break;
				case 'elastalert':
					this.extractElastAlertReferences();
					break;
			}
		},
		extractSuricataReferences() {
			const refFinder = /reference:([^;]*),([^;]*);/ig;
			const matches = [...this.detect.content.matchAll(refFinder)];

			this.extractedReferences = [];
			// ensure the value has a protocol
			for (let i = 0; i < matches.length; i++) {
				if (matches[i][1] === 'url') {
					this.extractedReferences.push({ type: matches[i][1], text: matches[i][2], link: this.fixProtocol(matches[i][2]) });
				} else {
					this.extractedReferences.push({ type: matches[i][1], text: matches[i][2] });
				}
			}
		},
		extractStrelkaReferences() {
			const refFinder = /reference\d*\s*=\s*['"]([^'"]*)['"]/ig;
			const matches = [...this.detect.content.matchAll(refFinder)];

			this.extractedReferences = [];
			for (let i = 0; i < matches.length; i++) {
				if (this.isValidUrl(matches[i][1])) {
					this.extractedReferences.push({ type: "url", text: matches[i][1], link: this.fixProtocol(matches[i][1]) });
				} else {
					this.extractedReferences.push({ type: "text", text: matches[i][1] });
				}
			}
		},
		extractElastAlertReferences() {
			const yaml = jsyaml.load(this.detect.content, {schema: jsyaml.FAILSAFE_SCHEMA});
			if (!yaml['references']) {
				return;
			}

			this.extractedReferences = yaml['references'].map(r => {
				if (this.isValidUrl(r)) {
					return { type: "url", text: r, link: this.fixProtocol(r) };
				} else {
					return { type: "text", text: r };
				}
			});
		},
		isValidUrl(urlString) {
	  	var urlPattern = new RegExp('^(https?:\\/\\/)?'+ // validate protocol
		'((([a-z\\d]([a-z\\d-]*[a-z\\d])*)\\.)+[a-z]{2,}|'+ // validate domain name
		'((\\d{1,3}\\.){3}\\d{1,3}))'+ // validate OR ip (v4) address
		'(\\:\\d+)?(\\/[-a-z\\d%_.~+]*)*'+ // validate port and path
		'(\\?[;&a-z\\d%_.~+=-]*)?'+ // validate query string
		'(\\#[-a-z\\d_]*)?$','i'); // validate fragment locator
	  return !!urlPattern.test(urlString);
		},
		fixProtocol(url) {
			if (!url.startsWith('http://') && !url.startsWith('https://')) {
				url = 'http://' + url;
			}

			return url;
		},
		extractLogic() {
			this.extractedLogic = '';

			switch (this.detect.engine) {
				case 'suricata':
					this.extractSuricataLogic();
					break;
				case 'strelka':
					this.extractStrelkaLogic();
					break;
				case 'elastalert':
					this.extractElastAlertLogic();
					break;
			}
		},
		extractSuricataLogic() {
			const suricataParser = /^\w+\s+(.*?)\((.*)\)$/gi;
			const matches = suricataParser.exec(this.detect.content.trim());

			if (!matches) {
				return;
			}

			const head = matches[1];

			let meta = matches[2].split(';').filter(opt => {
				opt = opt.trim();
				if (!opt) return false;

				const key = opt.split(':', 2)[0].trim().toLowerCase();
				return ['msg', 'reference', 'metadata', 'sid', 'rev', 'classtype'].indexOf(key) === -1;
			}).map(opt => opt.trim());

			this.extractedLogic = [head.trim(), ...meta].join('\n\n');
		},
		extractStrelkaLogic() {
			// from strings to the end of the rule
			let logicStart = this.detect.content.indexOf('strings:');
			let ruleStop = this.detect.content.lastIndexOf('}');

			if (logicStart === -1) {
				// no strings section? look for conditions
				logicStart = this.detect.content.indexOf('condition:');
			}

			// back up to the beginning of the strings line
			while (this.detect.content[logicStart] !== '\n') {
				logicStart--;
			}
			logicStart++;

			// cut out the part we want
			const dump = this.detect.content.substring(logicStart, ruleStop);

			// begin unindenting
			let lines = dump.split('\n');

			// check if the first line begins with whitespace
			const ws = dump[0];
			if (ws !== ' ' && ws !== '\t') {
				// does not begin with whitespace, no indentation to remove
				this.extractedLogic = dump.trim();
				return;
			}

			// find the line with the least whitespace, don't count blank lines
			let min = 1000000;
			for (let i = 0; i < lines.length; i++) {
				if (lines[i].length === 0) continue;
				let linemin = 0;
				for (let j = 0; j < lines[i].length; j++) {
					if (lines[i][j] === ws) {
						linemin++;
					} else {
						break;
					}
				}

				if (linemin < min) {
					min = linemin;
				}
			}

			if (min === 0) {
				// the line with the least amount of whitespace is already 0
				this.extractedLogic = dump.trim();
				return;
			}

			// remove the minimum amount of whitespace from each line
			this.extractedLogic = lines.map(l => l.length >= min ? l.substring(min) : l).join('\n');
		},
		extractElastAlertLogic() {
			const yaml = jsyaml.load(this.detect.content, { schema: jsyaml.FAILSAFE_SCHEMA });
			const logSource = yaml['logsource'];
			const detection = yaml['detection'];

			this.extractedLogic = jsyaml.dump({ logsource: logSource, detection: detection }).trim();
		},
		extractDetails() {
			this.extractedCreated = this.extractedUpdated = '';

			switch (this.detect.engine) {
				case 'suricata':
					this.extractSuricataDetails();
					break;
				case 'strelka':
					this.extractStrelkaDetails();
					break;
				case 'elastalert':
					this.extractElastAlertDetails();
					break;
			}
		},
		extractSuricataDetails() {
			const metadataExtractor = /metadata:([^;]+);/i;
			const match = this.detect.content.match(metadataExtractor);

			if (!match) {
				return;
			}

			const metadata = match[1].split(',').map(opt => opt.trim());
			const ymd = /\d{4}[-_]\d{1,2}[-_]\d{1,2}/;
			const leading0 = /^0/;

			for (let i = 0; i < metadata.length; i++) {
				let md = metadata[i];

				if (md.indexOf('created_at') > -1) {
					let date = md.match(ymd);
					if (date) {
						this.extractedCreated = date[0];
					}
				}

				if (md.indexOf('updated_at') > -1) {
					let date = md.match(ymd);
					if (date) {
						this.extractedUpdated = date[0];
					}
				}
			}
		},
		extractStrelkaDetails() {
			const dateExtractor = /^\s*date\s*=\s*"(.*)"/im;
			const dateMatch = dateExtractor.exec(this.detect.content);

			if (dateMatch) {
				this.extractedCreated = dateMatch[1];
			}
		},
		extractElastAlertDetails() {
			const yaml = jsyaml.load(this.detect.content, { schema: jsyaml.FAILSAFE_SCHEMA });

			this.extractedCreated = yaml['date'];
			this.extractedUpdated = yaml['modified'];
		},
		async loadHistory() {
			const id = this.$route.params.id;

			const response = await this.$root.papi.get(`detection/${id}/history`);
			if (response && response.data) {
				this.history = response.data;

				for (var i = 0; i < this.history.length; i++) {
					this.$root.populateUserDetails(this.history[i], "userId", "owner");
				}
			}
		},
		getDefaultPreset(preset) {
			if (this.presets) {
				const presets = this.presets[preset];
				if (presets && presets.labels && presets.labels.length > 0) {
					return presets.labels[0];
				}
			}
			return "";
		},
		getPresets(kind) {
			if (this.presets && this.presets[kind]) {
				switch (kind) {
					case 'severity':
					case 'engine':
					case 'language':
						return this.translateOptions(this.presets[kind].labels);
					default:
						return this.presets[kind].labels;
				}
			}
			return [];
		},
		getTrackOptions(type) {
			switch (type) {
				case 'threshold':
					return ['by_src', 'by_dst'];
				case 'suppress':
					return ['by_src', 'by_dst', 'by_either'];
			}

			return [];
		},
		translateOptions(opts) {
			return opts.map(opt => this.$root.correctCasing(opt))
		},
		requestRules(rules) {
			if (this.detect.isCommunity) {
				return [];
			}

			return rules;
		},
		isPresetCustomEnabled(kind) {
			if (this.presets && this.presets[kind]) {
				return this.presets[kind].customEnabled == true;
			}
			return false;
		},
		isNew() {
			return this.$route.params.id === 'create';
		},
		isDetectionSourceDirty() {
			return this.detect.content != this.origDetect.content;
		},
		cancelDetection() {
			if (this.isNew()) {
				this.$router.push({name: 'detections'});
			} else {
				this.detect = Object.assign({}, this.origDetect);
			}

			this.showDirtySourceDialog = false;
		},
		async startEdit(target, field) {
			if (this.curEditTarget === target) return;
			if (this.curEditTarget !== null) await this.stopEdit(false);
			if (this.detect.isCommunity && field !== 'isEnabled') return;

			this.curEditTarget = target;
			this.origValue = this.detect[field];
			this.editField = field;

			this.$nextTick(() => {
				const el = document.getElementById(target + '-edit');
				if (el) {
					el.focus();
					el.select();
				}
			});
		},
		async startCommentEdit(target, focusId, comment) {
			if (this.curCommentEditTarget === target) return;
			if (this.curCommentEditTarget !== null) this.resetForm();

			this.commentsForm.value = comment.value;
			this.curCommentEditTarget = target;
			this.origComment = comment;

			this.$nextTick(() => {
				const el = document.getElementById(focusId);
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
				this.detect[this.editField] = this.origValue;
			}

			this.curEditTarget = null;
			this.origValue = null;
			this.editField = null;

			if (commit && !this.isNew()) {
					this.saveDetection(false).then(() => {
						this.curEditTarget = null;
					});
			}
		},
		revertEnabled() {
			const route = this;
			this.$nextTick(() => {
				route.detect.isEnabled = route.origDetect.isEnabled;
			});
		},
		async saveDetection(createNew, skipSourceCheck) {
			if (this.curEditTarget !== null) this.stopEdit(true);
			if (!this.isNew() && !skipSourceCheck && this.isDetectionSourceDirty()) {
				this.showDirtySourceDialog = true;
				this.revertEnabled();
				return;
			}

			this.showDirtySourceDialog = false;

			if (this.isNew()) {
				this.$refs.detection.validate();
				if (!this.editForm.valid) return;
			}

			let err;
			switch (this.detect.engine) {
				case 'strelka':
					err = this.validateStrelka();
					break;
				case 'elastalert':
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
				let response;
				this.$root.startLoading();

				if (createNew) {
					response = await this.$root.papi.post('/detection', this.detect);
				} else {
					response = await this.$root.papi.put('/detection', this.detect, {
						validateStatus: (s) => (s >= 200 && s < 300)
					});
				}

				// get any expanded overrides before updating this.detect
				let index = -1;
				if (this.expanded && this.expanded.length) {
					index = this.expanded[0].index;
				}

				this.extractDetection(response);

				switch (response.status) {
					case 206:
						this.$root.showWarning(this.i18n.disabledFailedSync);
						break;
					default:
						this.$root.showTip(this.i18n.saveSuccess);
						break;
				}

				if (createNew) {
					this.$router.push({ name: 'detection', params: { id: response.data.id } });
				}

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
				this.$root.stopLoading();
			}
		},
		async duplicateDetection() {
			const response = await this.$root.papi.post('/detection/' + encodeURIComponent(this.$route.params.id) + '/duplicate');
			this.extractDetection(response);

			this.$router.push({ name: 'detection', params: { id: response.data.id } });
		},
		deleteDetection() {
			this.confirmDeleteDialog = true;
		},
		cancelDeleteDetection() {
			this.confirmDeleteDialog = false;
		},
		async confirmDeleteDetection() {
			this.cancelDeleteDetection();
			try {
				this.$root.startLoading();
				await this.$root.papi.delete('/detection/' + encodeURIComponent(this.$route.params.id));
				this.$router.push({ name: 'detections' });
				this.$root.showTip(this.i18n.detectionDeleteSuccessful);
			} catch (error) {
				this.$root.showError(error);
			} finally {
				this.$root.stopLoading();
			}
		},
		validateStrelka() {
			return null;
		},
		validateElastAlert() {
			try {
				const id = this.extractElastAlertPublicID();
				if (!id) {
					throw this.i18n.idMissingErr;
				}

				if (this.detect.publicId && this.detect.publicId !== id) {
					throw this.i18n.idMismatchErr;
				}

				return null;
			} catch (e) {
				return e;
			}
		},
		validateSuricata() {
			try {
				const sid = this.extractSuricataPublicID();

				if (this.detect.publicId !== sid) {
					// sid doesn't match metadata
					return this.i18n.sidMismatchErr;
				}
			} catch (e) {
				return e;
			}

			// normalize quotes
			this.detect.content = this.detect.content.replaceAll('”', '"');
			this.detect.content = this.detect.content.replaceAll('“', '"');

			return null;
		},
		extractPublicID() {
			let pid = this.detect.publicId;
			switch (this.detect.engine) {
				case 'suricata':
					try {
						pid = this.extractSuricataPublicID();
					} catch {}
					break;
				case 'elastalert':
					try {
						const id = this.extractElastAlertPublicID();
						if (id) pid = id;
					} catch {}
					break;
			}

			this.detect.publicId = pid;
		},
		extractSeverity() {
			let sev = this.detect.severity;
			switch (this.detect.engine) {
				case 'suricata':
					try {
						sev = this.extractSuricataSeverity();
					} catch {}
					break;
				case 'elastalert':
					try {
						const s = this.extractElastAlertSeverity();
						if (s) sev = s;
					} catch {}
					break;
			}

			this.detect.severity = sev;
		},
		extractSuricataPublicID() {
			const results = this.sidExtract.exec(this.detect.content);
			if (results === null || results.length < 2) {
				throw this.i18n.sidMissingErr;
			}

			return results[1];
		},
		extractSuricataSeverity() {
			const results = this.severityExtract.exec(this.detect.content);

			let sev = (results[1] || '').toLowerCase();
			if (this.severityTranslations[sev]) {
				sev = this.severityTranslations[sev]
			}

			if (!this.presets['severity'].labels.includes(sev)) {
				sev = this.getDefaultPreset('severity');
			}

			return sev;
		},
		extractElastAlertPublicID() {
			const yaml = jsyaml.load(this.detect.content, {schema: jsyaml.FAILSAFE_SCHEMA});
			return yaml['id'];
		},
		extractElastAlertSeverity() {
			const yaml = jsyaml.load(this.detect.content, {schema: jsyaml.FAILSAFE_SCHEMA});
			const level = yaml['level'];

			for (let lvl in this.presets['severity'].labels) {
				if (this.presets['severity'].labels[lvl].toUpperCase() === level.toUpperCase()) {
					return this.presets['severity'].labels[lvl];
				}
			}
		},
		onDetectionChange() {
			if (this.detect.engine) {
				this.extractPublicID();
				this.extractSeverity();
			}
		},
		saveSetting(name, value, defaultValue = null) {
			var item = 'settings.detection.' + name;
			if (defaultValue == null || value != defaultValue) {
				localStorage[item] = value;
			} else {
				localStorage.removeItem(item);
			}
		},
		saveLocalSettings() {
			this.saveSetting('sortDesc', this.sortDesc, true);
			this.saveSetting('itemsPerPage', this.itemsPerPage, this.params['eventItemsPerPage']);
			this.saveSetting('relativeTimeValue', this.relativeTimeValue, this.params['relativeTimeValue']);
			this.saveSetting('relativeTimeUnit', this.relativeTimeUnit, this.params['relativeTimeUnit']);
		},
		sortOverrides(items, index, isDesc) {
			const route = this;
			if (index && index.length > 0) {
				index = index[0];
			}
			if (isDesc && isDesc.length > 0) {
				isDesc = isDesc[0];
			}
			items.sort((a, b) => {
				if (index === "event.severity_label") {
					return route.defaultSort(route.lookupAlertSeverityScore(a[index]), route.lookupAlertSeverityScore(b[index]), isDesc);
				} else {
					return route.defaultSort(a[index], b[index], isDesc);
				}
			});
			return items
		},
		defaultSort(a, b, isDesc) {
			if (!isDesc) {
				return a < b ? -1 : 1;
			}
			return b < a ? -1 : 1;
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
			};
		},
		getOverrideTypes(engine) {
			engine = engine || this.detect.engine;

			switch (engine) {
				case 'suricata':
					return [
						{ value: 'modify', text: 'Modify' },
						{ value: 'suppress', text: 'Suppress' },
						{ value: 'threshold', text: 'Threshold' }
					];
				case 'elastalert':
					return [
						{ value: 'customFilter', text: 'Custom Filter' }
					];
			}

			return [];
		},
		cleanupOverrides() {
			if (this.detect.overrides) {
				for (let i = 0; i < this.detect.overrides.length; i++) {
					this.detect.overrides[i] = this.cleanupOverride(this.detect.engine, this.detect.overrides[i]);
				}
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
		createOverrideTypeChange() {
			// reset the form, but we want the selected type to persist
			const t = this.newOverride.type;
			this.$refs.OverrideCreate.reset();
			this.newOverride.type = t;
		},
		cancelNewOverride() {
			this.$refs.OverrideCreate.reset();
			this.newOverride = null;
		},
		addNewOverride() {
			if (!this.newOverride) return;

			if (!this.detect.overrides) {
				this.detect.overrides = [];
			}

			this.newOverride.isEnabled = true;

			this.detect.overrides.push(this.newOverride);

			this.saveDetection(false);
			this.newOverride = null;
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
		stopOverrideEdit(commit) {
			if (commit && this.$refs[this.curOverrideEditTarget].hasError) return;

			if (!commit) {
				this.editOverride[this.overrideEditField] = this.origOverrideValue;
			} else {
				this.$nextTick(async () => {
					await this.saveDetection(false);
					this.curOverrideEditTarget = null;
				});
			}

			this.curOverrideEditTarget = null;
			this.origOverrideValue = null;
			this.overrideEditField = null;
			this.editOverride = null;
		},
		deleteOverride(item) {
			this.detect.overrides = this.detect.overrides.filter(o => o !== item);
			this.saveDetection(false);
		},
		canAddOverride() {
			return this.detect.engine !== 'strelka';
		},
		canConvert() {
			let lang = this.detect.language || '';
			return lang.toLowerCase() === 'sigma';
		},
		tagOverrides() {
			if (this.detect.overrides) {
				for (let i = 0; i < this.detect.overrides.length; i++) {
					this.detect.overrides[i].index = i;
				}
			} else {
				this.detect.overrides = [];
			}
		},
		prepareForInput(id) {
			const el = document.getElementById(id)
			el.scrollIntoView()
			el.focus();
		},
		async reloadComments(showLoadingIndicator = false) {
			if (showLoadingIndicator) this.$root.startLoading();
			this.comments = [];
			await this.loadComments();
			if (showLoadingIndicator) this.$root.stopLoading();
		},
		async loadComments() {
			try {
				const response = await this.$root.papi.get(`detection/${this.detect.id}/comment`);
				if (response && response.data) {
					for (var idx = 0; idx < response.data.length; idx++) {
						const obj = response.data[idx];

						// Don't await the user details -- takes too long for the task scheduler to
						// complete all these futures when looping across hundreds of records. Let
						// the UI update as they finish, for a better user experience.
						this.$root.populateUserDetails(obj, "userId", "owner");
						if (obj.assigneeId) {
							this.$root.populateUserDetails(obj, "assigneeId", "assignee");
						}

						obj.operation = this.$root.localizeMessage(obj.operation);

						this.comments.push(obj);
					}

					this.resetForm();
				}
			} catch (error) {
				this.$root.showError(error);
			}
		},
		async addComment() {
			if (this.$refs && this.$refs['detection-comment'] && !this.$refs['detection-comment'].validate()) {
				return;
			}

			this.$root.startLoading();
			try {
				let isUpdate = false;
				const form = this.commentsForm;
				form.detectionId = this.detect.id;
				form.id = '';
				if (this.origComment) {
					form.id = this.origComment.id;
					isUpdate = true;
				}
				if (form.value) {
					form.value = form.value.trim();
				}

				let data = JSON.stringify(form);
				delete data.valid;

				let response;
				if (isUpdate) {
					response = await this.$root.papi.put(`detection/comment/${form.id}`, data);
				} else {
					response = await this.$root.papi.post(`detection/${this.detect.id}/comment`, data);
				}

				if (response && response.data) {
					if (isUpdate) {
						this.reloadComments();
					} else {
						await this.$root.populateUserDetails(response.data, "userId", "owner");
						this.comments.push(response.data);
					}

					this.resetForm();
				}

				this.$root.showTip(this.i18n.saveSuccess);
			} catch (error) {
				this.$root.showError(error);
			}

			this.$root.stopLoading();
		},
		resetForm() {
			this.origComment = null;
			if (this.$refs && this.$refs['detection-comment']) this.$refs['detection-comment'].reset();
			this.commentsForm  = { valid: true, value: '' };
		},
		shouldRenderComment(obj, index) {
			var render = true;
			if (!this.commentsTable.showAll && this.renderAbbreviatedCount) {
				const count = this.comments ? this.comments.length : 0;
				const lowerCutoff = Math.floor(this.renderAbbreviatedCount / 2);
				if (count - this.renderAbbreviatedCount > lowerCutoff) {
					const upperCutoff = count - lowerCutoff;
					if (index >= lowerCutoff && index < upperCutoff) {
						render = false;
					}
				}
			}

			return render;
		},
		isEdited(obj) {
			const createTime = Date.parse(obj.createTime);
			const updateTime = Date.parse(obj.updateTime);
			return Math.abs(updateTime - createTime) >= 1000;
		},
		shouldRenderShowAll(index) {
			var render = false;
			if (!this.commentsTable.showAll && this.renderAbbreviatedCount) {
				const count = this.comments ? this.comments.length : 0;
				const lowerCutoff = Math.floor(this.renderAbbreviatedCount / 2);
				if (count - this.renderAbbreviatedCount > lowerCutoff) {
					if (index == lowerCutoff-1) {
						render = true;
					}
				}
			}

			return render;
		},
		getUnrenderedCount() {
			var hiddenCount = 0;
			if (!this.commentsTable.showAll && this.renderAbbreviatedCount) {
				const count = this.comments ? this.comments.length : 0;
				if (count > this.renderAbbreviatedCount) {
					hiddenCount = count - this.renderAbbreviatedCount;
				}
			}

			return hiddenCount;
		},
		renderAllComments() {
			this.commentsTable.showAll = true;
		},
		async deleteComment(obj) {
			const idx = this.comments.indexOf(obj);
			if (idx > -1) {
				this.$root.startLoading();
				try {
					await this.$root.papi.delete(`detection/comment/${obj.id}`);
					this.comments.splice(idx, 1);
				} catch (error) {
					if (error.response != undefined && error.response.status == 404) {
						this.$root.showError(this.i18n.notFound);
					} else {
						this.$root.showError(error);
					}
				}
				this.$root.stopLoading();
			}
		},
		async convertDetection(content) {
			this.$root.startLoading();
			try {
				const response = await this.$root.papi.post('detection/convert', this.detect);
				if (response && response.data) {
					this.convertedRule = response.data.query;
					this.showSigmaDialog = true;
				}
			} catch (error) {
				this.$root.showError(error);
			} finally {
				this.$root.stopLoading();
			}
		},
		cancelConvert() {
			this.convertedRule = '';
			this.showSigmaDialog = false;
		},
		copyConvertToClipboard() {
			this.$root.copyToClipboard(this.convertedRule);
		},
		runQueryInDiscover() {
			let query = `GET /.ds-logs-*/_eql/search
{
	"query": """
	${this.convertedRule}
	"""
}`;
			const compress = LZString.compressToEncodedURIComponent(query);
			const url = `/kibana/app/dev_tools#/console?load_from=data:text/plain,${compress}`;
			window.open(url, '_blank');
		}
	}
}});
