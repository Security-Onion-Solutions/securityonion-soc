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
	data() { return {
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
		rules: {
			required: value => (value && value.length > 0) || this.$root.i18n.required,
			number: value => (! isNaN(+value) && Number.isInteger(parseFloat(value))) || this.$root.i18n.required,
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
		authorExtract: /\bauthor: ?['"]?(.*?)['"]?;/, // option
		authorMetaExtract: /\bauthor ['"]?(.*?)['"]?[,;]/, // metadata
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
			footerProps: { 'items-per-page-options': [10,50,250,1000] },
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
		extractedAuthor: '',
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

		},
		newDetection() {
			let author = [this.$root.user.firstName, this.$root.user.lastName].filter(x => x).join(' ');
			return {
				title: this.i18n.detectionDefaultTitle,
				description: this.i18n.detectionDefaultDescription,
				author: author,
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
				this.detect = response.data;
				this.tagOverrides();
				this.loadAssociations();
			} catch (error) {
				if (error.response != undefined && error.response.status == 404) {
					this.$root.showError(this.i18n.notFound);
				} else {
					this.$root.showError(error);
				}
			}

			this.$root.stopLoading();
		},
		loadAssociations() {
			this.extractSummary();
			this.extractReferences();
			this.extractLogic();
			this.extractDetails();
			this.loadHistory();
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
				this.extractedReferences.push({ type: matches[i][1], text: matches[i][2], link: this.fixProtocol(matches[i][2]) });
			}
		},
		extractStrelkaReferences() {
			const refFinder = /reference\d*\s*=\s*['"]([^'"]*)['"]/ig;
			const matches = [...this.detect.content.matchAll(refFinder)];

			this.extractedReferences = [];
			for (let i = 0; i < matches.length; i++) {
				this.extractedReferences.push({ type: "url", text: matches[i][1], link: this.fixProtocol(matches[i][1]) });
			}
		},
		extractElastAlertReferences() {
			const yaml = jsyaml.load(this.detect.content, {schema: jsyaml.FAILSAFE_SCHEMA});
			if (!yaml['references']) {
				return;
			}

			this.extractedReferences = yaml['references'].map(r => {
				return { type: "url", text: r, link: this.fixProtocol(r) };
			});
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

			this.extractedLogic = [head, ...meta].join('\n\n');
		},
		extractStrelkaLogic() {
			// from strings to the end of the rule
			let stringsStart = this.detect.content.indexOf('strings:');
			let ruleStop = this.detect.content.lastIndexOf('}');

			// back up to the beginning of the strings line
			while (this.detect.content[stringsStart] !== '\n') {
				stringsStart--;
			}
			stringsStart++;

			// cut out the part we want
			const dump = this.detect.content.substring(stringsStart, ruleStop);

			// begin unindenting
			let lines = dump.split('\n');

			// check if the first line begins with whitespace
			const ws = dump[0];
			if (ws !== ' ' && ws !== '\t') {
				// does not begin with whitespace, no indentation to remove
				return dump
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
				return dump;
			}

			// remove the minimum amount of whitespace from each line
			this.extractedLogic = lines.map(l => l.length >= min ? l.substring(min) : l).join('\n');
		},
		extractElastAlertLogic() {
			const yaml = jsyaml.load(this.detect.content, { schema: jsyaml.FAILSAFE_SCHEMA });
			const logSource = yaml['logsource'];
			const detection = yaml['detection'];

			this.extractedLogic = jsyaml.dump({ logsource: logSource, detection: detection });
		},
		extractDetails() {
			this.extractedAuthor = this.extractedCreated = this.extractedUpdated = '';

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

				if (md.indexOf('author') > -1) {
					this.extractedAuthor = md.replace('author', '').trim();
				}
			}
		},
		extractStrelkaDetails() {
			const authorExtractor = /^\s*author\s*=\s*"(.*)"/im;
			const dateExtractor = /^\s*date\s*=\s*"(.*)"/im;

			const authorMatch = authorExtractor.exec(this.detect.content);

			if (authorMatch) {
				this.extractedAuthor = authorMatch[1];
			}

			const dateMatch = dateExtractor.exec(this.detect.content);

			if (dateMatch) {
				this.extractedCreated = dateMatch[1];
			}
		},
		extractElastAlertDetails() {
			const yaml = jsyaml.load(this.detect.content, { schema: jsyaml.FAILSAFE_SCHEMA });

			this.extractedAuthor = yaml['author'];
			this.extractedCreated = yaml['date'];
			this.extractedUpdated = yaml['modified'];
		},
		async loadHistory() {
			const route = this;
			const id = route.$route.params.id;
			const response = await this.$root.papi.get(`detection/${id}/history`);
			if (response && response.data) {
				this.history = response.data;
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
						return this.capitalizeOptions(this.presets[kind].labels);
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
		capitalizeOptions(opts) {
			return opts.map(opt => {
				const cap = opt.charAt(0).toUpperCase() + opt.slice(1).toLowerCase();
				return {
					text: cap,
					value: opt,
				}
			})
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
		cancelDetection() {
			if (this.isNew()) {
				this.$router.push({name: 'detections'});
			} else {
				this.detect = this.origDetect;
			}
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
		isEdit(target) {
			return this.curEditTarget === target;
		},
		async stopEdit(commit) {
			if (!commit) {
				this.detect[this.editField] = this.origValue;
			}

			this.curEditTarget = null;
			this.origValue = null;
			this.editField = null;

			if (commit && !this.isNew()) {
				this.saveDetection(false);
			}
		},
		async saveDetection(createNew) {
			if (this.curEditTarget !== null) this.stopEdit(true);

			if (this.isNew()) {
				this.$refs.detection.validate();
				if (!this.editForm.valid) return;
			}

			let err;
			switch (this.detect.engine) {
				case 'yara':
					err = this.validateYara();
					break;
				case 'sigma':
					err = this.validateSigma();
					break;
				case 'suricata':
					err = this.validateSuricata();
					break;
			}

			if (err) {
				this.$root.showError(err);
				return;
			}

			if (this.detect.overrides) {
				for (let i = 0; i < this.detect.overrides.length; i++) {
					this.detect.overrides[i] = this.cleanupOverride(this.detect.engine, this.detect.overrides[i]);
				}
			}

			try {
				let response;
				this.$root.startLoading();

				if (createNew) {
					response = await this.$root.papi.post('/detection', this.detect);
				} else {
					response = await this.$root.papi.put('/detection', this.detect);
				}

				// get any expanded overrides before updating this.detect
				let index = -1;
				if (this.expanded && this.expanded.length) {
					index = this.expanded[0].index;
				}

				this.detect = response.data;
				this.tagOverrides();
				this.origDetect = Object.assign({}, this.detect);

				// reinstate expanded override
				if (index != -1 && this.detect.overrides && this.detect.overrides.length > index) {
					this.expand(this.detect.overrides[index]);
				}

				this.$root.showTip(this.i18n.saveSuccess);

				if (createNew) {
					this.$router.push({ name: 'detection', params: { id: response.data.id } });
				}

			} catch (error) {
				this.$root.showError(error);
			} finally {
				this.$root.stopLoading();
			}
		},
		async duplicateDetection() {
			const response = await this.$root.papi.post('/detection/' + encodeURIComponent(this.$route.params.id) + '/duplicate');
			this.$router.push({name: 'detection', params: {id: response.data.id}});
		},
		async deleteDetection() {
			await this.$root.papi.delete('/detection/' + encodeURIComponent(this.$route.params.id));
			this.$router.push({ name: 'detections' });
		},
		validateYara() {
			return null;
		},
		validateSigma() {
			return null;
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
		extractAuthor() {
			let author = this.detect.author;
			switch (this.detect.engine) {
				case 'suricata':
					try {
						const a = this.extractSuricataAuthor();
						if (a) author = a;
					} catch {}
					break;
				case 'elastalert':
					try {
						const a = this.extractElastAlertAuthor();
						if (a) author = a;
					} catch {}
					break;
			}

			this.detect.author = author;
		},
		extractSuricataPublicID() {
			const results = this.sidExtract.exec(this.detect.content);
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
		extractSuricataAuthor() {
			// do suricata rules even have a place for an author?

			// first look for an option labeled author
			const author = this.authorExtract.exec(this.detect.content);
			if (author && author.length >= 2) return author[1];

			// if no option, check metadata for a field labeled author
			const authorMeta = this.authorMetaExtract.exec(this.detect.content);
			if (authorMeta && authorMeta.length >= 2) return authorMeta[1];
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
		extractElastAlertAuthor() {
			const yaml = jsyaml.load(this.detect.content, {schema: jsyaml.FAILSAFE_SCHEMA});
			return yaml['author'];
		},
		onDetectionChange() {
			if (this.detect.engine) {
				this.extractPublicID();
				this.extractSeverity();
				this.extractAuthor();
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
		expand(item) {
			if (this.isExpanded(item)) {
				this.expanded = [];
			} else {
				this.expanded = [item];
			}
		},
		isExpanded(item) {
			return (this.expanded.length > 0 && this.expanded[0] === item);
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
						{ value: 'custom filter', text: 'Custom Filter' }
					];
			}

			return [];
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
				out.type = o.type

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
		async stopOverrideEdit(commit) {
			if (commit && this.$refs[this.curOverrideEditTarget].hasError) return;

			if (!commit) {
				this.editOverride[this.overrideEditField] = this.origOverrideValue;
			} else {
				this.saveDetection(false);
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
			if (this.detect.engine === 'elastalert') {
				if (this.detect.overrides && this.detect.overrides.length > 0) {
					for (let i = 0; i < this.detect.overrides.length; i++) {
						if (this.detect.overrides[i].type === 'custom filter') {
							// elastalert detections that already have a custom filter
							// cannot have any other custom filter overrides
							return false;
						}
					}
				}
			} else if (this.detect.engine === 'strelka') {
				return false;
			}

			return true;
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
		isExpanded(row) {
			const expanded = this.historyTableOpts.expanded;
			for (var i = 0; i < expanded.length; i++) {
				if (expanded[i].id == row.id) {
					return true;
				}
			}
			return false;
		},
		async expandRow(row) {
			const expanded = this.historyTableOpts.expanded;
			for (var i = 0; i < expanded.length; i++) {
				if (expanded[i].id == row.id) {
					expanded.splice(i, 1);
					return;
				}
			}

			expanded.push(row);
		}
	}
}});