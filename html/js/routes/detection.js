// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
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

const MAX_OVERRIDE_NOTE_LENGTH = 150;

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
				noteLengthLimit: value => (value.length <= MAX_OVERRIDE_NOTE_LENGTH) || this.$root.i18n.required,
				longLengthLimit: value => (encodeURI(value).split(/%..|./).length - 1 < 10000000) || this.$root.i18n.required,
				fileSizeLimit: value => (value == null || value.length == 0 || value[0].size < this.maxUploadSizeBytes) || this.$root.i18n.fileTooLarge.replace("{maxUploadSizeBytes}", this.$root.formatCount(this.maxUploadSizeBytes)),
				fileNotEmpty: value => (value == null || value.length == 0 || value[0].size > 0) || this.$root.i18n.fileEmpty,
				fileRequired: value => (value != null && value.length != 0) || this.$root.i18n.required,
				cidrFormat: value => (!value ||
					/^!?\$[a-z_][a-z0-9_]*$/i.test(value) || // Suricata variable
					/^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\/(3[0-2]|[12]\d|\d)$/.test(value) || // IPv4 CIDR
					/^((([0-9a-f]{1,4}:){7}([0-9a-f]{1,4}|:))|(([0-9a-f]{1,4}:){6}(:[0-9a-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9a-f]{1,4}:){5}(((:[0-9a-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9a-f]{1,4}:){4}(((:[0-9a-f]{1,4}){1,3})|((:[0-9a-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9a-f]{1,4}:){3}(((:[0-9a-f]{1,4}){1,4})|((:[0-9a-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9a-f]{1,4}:){2}(((:[0-9a-f]{1,4}){1,5})|((:[0-9a-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9a-f]{1,4}:){1}(((:[0-9a-f]{1,4}){1,6})|((:[0-9a-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9a-f]{1,4}){1,7})|((:[0-9a-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*(\/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8]))$/i.test(value) // IPv6 CIDR
				) || this.i18n.invalidCidrOrVar,
			},
			panel: [0, 1, 2],
			activeTab: '',
			sidExtract: /\bsid: ?['"]?(.*?)['"]?;/, // option
			severityExtract: /\bsignature_severity ['"]?(.*?)['"]?[,;]/, // metadata
			sortBy: [{ key: 'createdAt', order: 'asc' }],
			expanded: [],
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
			zone: moment.tz.guess(),
			newOverride: null,
			newOverrideValid: false,
			thresholdTypes: [
				{ title: this.$root.i18n.threshold, value: 'threshold' },
				{ title: this.$root.i18n.limit, value: 'limit' },
				{ title: this.$root.i18n.both, value: 'both' }
			],
			historyTableOpts: {
				sortBy: [{ key: 'updateTime', order: 'asc' }],
				search: '',
				headers: [
					{ title: this.$root.i18n.actions, width: '10.0em' },
					{ title: this.$root.i18n.username, value: 'owner' },
					{ title: this.$root.i18n.time, value: 'updateTime', key: 'updateTime', sortRaw: this.$root.dateAwareCompare('updateTime') },
					{ title: this.$root.i18n.kind, value: 'kind' },
					{ title: this.$root.i18n.operation, value: 'operation' },
				],
				itemsPerPage: 10,
				footerProps: { 'items-per-page-options': [10, 50, 250, 1000] },
				count: 500,
				expanded: [],
				loading: false,
			},
			historyOverrideTableOpts: {
				"elastalert": {
					sortBy: [{ key: 'updatedAt', order: 'asc' }],
					headers: [
						{ title: this.$root.i18n.actions, width: '10.0em' },
						{ title: this.$root.i18n.kind, value: 'type' },
						{ title: this.$root.i18n.time, value: 'updatedAt', key: 'updatedAt', rawSort: this.$root.dateAwareCompare('updatedAt') },
						{ title: this.$root.i18n.enabled, value: 'isEnabled' },
					],
					itemsPerPage: 10,
					footerProps: { 'items-per-page-options': [10, 50, 250, 1000] },
					count: 500,
					expanded: [],
					loading: false,
				},
				"suricata": {
					sortBy: [{ key: 'updatedAt', order: 'asc' }],
					headers: [
						{ title: this.$root.i18n.actions, width: '10.0em' },
						{ title: this.$root.i18n.kind, value: 'type' },
						{ title: this.$root.i18n.time, value: 'updatedAt' },
						{ title: this.$root.i18n.enabled, value: 'isEnabled' },
					],
					itemsPerPage: 10,
					footerProps: { 'items-per-page-options': [10, 50, 250, 1000] },
					count: 500,
					expanded: [],
					loading: false,
				},
			},
			extractedSummary: '',
			extractedReferences: [],
			extractedLogic: '',
			extractedLogicClass: '',
			history: [],
			extractedCreated: '',
			extractedUpdated: '',
			comments: [],
			commentsTable: {
				showAll: false,
				sortBy: [{ key: 'createTime', order: 'asc' }],
				search: '',
				headers: [
					{ title: this.$root.i18n.username, value: 'owner' },
					{ title: this.$root.i18n.dateCreated, value: 'createTime' },
					{ title: this.$root.i18n.dateModified, value: 'updateTime' },
					{ title: this.$root.i18n.commentDescription, value: 'description' },
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
			ruleTemplates: {},
			languageToEngine: {
				'suricata': 'suricata',
				'sigma': 'elastalert',
				'yara': 'strelka',
			},
			changedKeys: {},
			changedOverrideKeys: {},
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
			showUnreviewedAiSummaries: false,
			MAX_OVERRIDE_NOTE_LENGTH: MAX_OVERRIDE_NOTE_LENGTH,
	}},
	created() {
		this.$root.initializeEditor();
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
	updated() {
		this.$nextTick(() => {
			Prism.highlightAll();
		});
	},
	methods: {
		async initDetection(params) {
			this.params = params;
			this.presets = params['presets'];
			this.renderAbbreviatedCount = params["renderAbbreviatedCount"];
			this.severityTranslations = params['severityTranslations'];
			this.ruleTemplates = params['templateDetections'];
			this.showUnreviewedAiSummaries = params['showUnreviewedAiSummaries'];

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
				case 'elastalert':
					const yaml = jsyaml.load(this.detect.content, { schema: jsyaml.FAILSAFE_SCHEMA });
					if (yaml.description) {
						this.extractedSummary = yaml.description;
						break;
					}
					// else fall through
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
			this.extractedLogicClass = '';

			switch (this.detect.engine) {
				case 'suricata':
					this.extractSuricataLogic();
					this.extractedLogicClass = 'language-suricata-logic';
					break;
				case 'strelka':
					this.extractStrelkaLogic();
					this.extractedLogicClass = 'language-yara';
					break;
				case 'elastalert':
					this.extractElastAlertLogic();
					this.extractedLogicClass = 'language-yaml';
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
		async loadHistory(showLoadingIndicator = false) {
			if (showLoadingIndicator) this.$root.startLoading();

			const id = this.$route.params.id;

			const response = await this.$root.papi.get(`detection/${id}/history`);
			if (response && response.data) {
				this.history = response.data;

				for (var i = 0; i < this.history.length; i++) {
					this.$root.populateUserDetails(this.history[i], "userId", "owner");
					this.history[i].overrides = this.history[i].overrides || [];
				}
			}
			if (showLoadingIndicator) this.$root.stopLoading();
		},
		findHistoryChange(id) {
			let retList = [];

			let index = this.history.findIndex((row) => row.id === id);

			if (this.history.length > 1 && index !== 0) {
				let oldDict = JSON.parse(JSON.stringify(this.history[index - 1]));
				let newDict = JSON.parse(JSON.stringify(this.history[index]));
				let releventKeys = ['title', 'description', 'isEnabled', 'severity', 'content'];

				if (oldDict['engine'] === 'elastalert') {
					contentJsonOld = jsyaml.load(oldDict['content'], { schema: jsyaml.FAILSAFE_SCHEMA });
					contentJsonNew = jsyaml.load(newDict['content'], { schema: jsyaml.FAILSAFE_SCHEMA });

					delete contentJsonOld['title'];
					delete contentJsonOld['description'];
					delete contentJsonOld['level'];
					delete contentJsonNew['title'];
					delete contentJsonNew['description'];
					delete contentJsonNew['level'];

					oldDict['content'] = JSON.stringify(contentJsonOld);
					newDict['content'] = JSON.stringify(contentJsonNew);

				} else if (oldDict['engine'] === 'suricata'){
					let sev1 = oldDict['severity'];
					let sev2 = newDict['severity'];
					let reversedSevTranslations = Object.fromEntries(
						Object.entries(this.severityTranslations).map(([k, v]) => [v, k])
					);

					if (reversedSevTranslations.hasOwnProperty(sev1)) sev1 = reversedSevTranslations[sev1];
					if (reversedSevTranslations.hasOwnProperty(sev2)) sev2 = reversedSevTranslations[sev2];

					regex1 = new RegExp('signature_severity' + sev1, 'ig');
					regex2 = new RegExp('signature_severity' + sev2, 'ig');

					oldDict['content'] = oldDict['content'].replaceAll(/\s/g,'').replaceAll('msg:"' + oldDict['title'].replaceAll(/\s/g,'') + '"', '').replaceAll(regex1, '');
					newDict['content'] = newDict['content'].replaceAll(/\s/g,'').replaceAll('msg:"' + newDict['title'].replaceAll(/\s/g,'') + '"', '').replaceAll(regex2, '');

				} else {
					oldDict['content'] = oldDict['content'].replaceAll(/\s/g,'').replaceAll('rule' + oldDict['title'].replaceAll(/\s/g,''), '').replaceAll('description="' + oldDict['description'].replaceAll(/\s/g,'') + '"', '');
					newDict['content'] = newDict['content'].replaceAll(/\s/g,'').replaceAll('rule' + newDict['title'].replaceAll(/\s/g,''), '').replaceAll('description="' + newDict['description'].replaceAll(/\s/g,'') + '"', '');
				}

				for (let key of releventKeys) {
					if (oldDict[key] !== newDict[key]) {
						retList.push(key);
					}
				}
			}

			this.changedKeys[id] = retList;

			this.findOverrideHistoryChange(id);
		},
		findOverrideHistoryChange(historyID) {
			let index = this.history.findIndex((row) => row.id === historyID);

			if (index <= 0) return;

			let prev = this.history[index - 1];
			let parent = this.history[index];
			let releventKeys = ['isEnabled', 'customFilter', 'regex', 'value', 'track', 'ip', 'count', 'seconds'];
			let overrideRetList = [];

			for (let i = 0; i < parent.overrides.length; i++) {
				let retList = [];
				let newOverride = parent.overrides[i];
				let oldOverride = prev.overrides.find(o => o.createdAt === newOverride.createdAt);

				if (oldOverride == null) {
					return;
				}

				for (let key of releventKeys) {
					if (oldOverride[key] !== newOverride[key]) {
						retList.push(key);
					}
				}

				overrideRetList.push(retList);
			}

			this.changedOverrideKeys[historyID] = overrideRetList;
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
		pickValue(item, field) {
			let value = '';
			if (item[field.value]) {
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
			switch (this.detect.language.toLowerCase()) {
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

				if (createNew) {
					this.$router.push({ name: 'detection', params: { id: response.data.id } });
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
				this.$root.stopLoading();
			}
		},
		async duplicateDetection() {
			try {
				const response = await this.$root.papi.post('/detection/' + encodeURIComponent(this.$route.params.id) + '/duplicate');
				this.extractDetection(response);

				this.$router.push({ name: 'detection', params: { id: response.data.id } });
			} catch (error) {
				this.$root.showError(error);
			}
		},
		deleteDetection() {
			this.confirmDeleteDialog = true;
		},
		cancelDeleteDetection() {
			this.confirmDeleteDialog = false;
		},
		async saveOverrideNote(item) {
			try {
				this.$root.startLoading();
				await this.$root.papi.put('/detection/' + this.detect.id + '/override/' + item.index + '/note', { note: item.note });
			} catch (error) {
				this.$root.showError(error);
			} finally {
				this.$root.stopLoading();
			}
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
		verifyRuleSyntax() {
			const rules = this.ruleValidators[this.detect.language.toLowerCase()];
			for (let i = 0; i < rules.length; i++) {
				if (rules[i].pattern.test(this.detect.content) === rules[i].match) {
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
				if (this.detect.publicId && this.detect.publicId !== id) {
					throw this.i18n.idMismatchErr;
				}

				const detLogic = this.extractElastAlertDetection();
				if (!detLogic) {
					throw this.i18n.invalidDetectionElastAlertMissingDetectionLogic;
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

				if (!this.isNew() && this.detect.publicId !== sid) {
					// sid doesn't match metadata
					return this.i18n.invalidDetectionSuricataSIDMismatch;
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

			let sev = (results && results[1] || '').toLowerCase();
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
		extractElastAlertDetection() {
			const yaml = jsyaml.load(this.detect.content, {schema: jsyaml.FAILSAFE_SCHEMA});
			return yaml['detection'];
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
		async onNewDetectionLanguageChange() {
			const lang = (this.detect.language || '').toLowerCase();
			const engine = this.languageToEngine[lang];

			if (engine) {
				let publicId = '';

				if (engine !== 'strelka') {
					try {
						const response = await this.$root.papi.get(`detection/${engine}/genpublicid`);
						publicId = response.data.publicId;
					} catch (error) {
						this.$root.showError(error);
					}
				}

				this.detect.content = this.ruleTemplates[engine].replaceAll('[publicId]', publicId).trim();
			}

			this.onDetectionChange();
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
				note: '',
			};
		},
		getOverrideTypes(engine) {
			engine = engine || this.detect.engine;

			switch (engine) {
				case 'suricata':
					return [
						{ title: this.i18n.modify, value: 'modify' },
						{ title: this.i18n.suppress, value: 'suppress' },
						{ title: this.i18n.threshold, value: 'threshold' }
					];
				case 'elastalert':
					return [
						{ title: this.i18n.customFilter, value: 'customFilter' }
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
		async addNewOverride() {
			if (!this.newOverride) return;

			if (!this.detect.overrides) {
				this.detect.overrides = [];
			}

			this.newOverride.isEnabled = true;

			this.detect.overrides.push(this.newOverride);

			const result = await this.saveDetection(false);
			if (!result) {
				this.detect.overrides.pop();
			}
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
		async loadComments(showLoadingIndicator = false) {
			if (showLoadingIndicator) this.$root.startLoading();
			try {
				const response = await this.$root.papi.get(`detection/${this.detect.id}/comment`);
				if (response && response.data) {
					this.comments = [];
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
			} finally {
				if (showLoadingIndicator) this.$root.stopLoading();
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
						this.loadComments();
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
		async convertDetection() {
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
		highlighter(code) {
			let grammar = null;
			let language = null;

			switch ((this.detect.language || '').toLowerCase()) {
				case 'sigma':
					grammar = Prism.languages.yaml;
					language = 'yaml';
					break;
				case 'suricata':
					grammar = Prism.languages.suricata;
					language = 'suricata';
					break;
				case 'yara':
					grammar = Prism.languages.yara;
					language = 'yara';
					break;
				default:
					return code;
			}

			return Prism.highlight(code, grammar, language);
		},
		checkChangedKey(id, key) {
			return this.changedKeys[id]?.includes(key);
		},
		checkOverrideChangedKey(id, index, key) {
			return this.changedOverrideKeys?.[id]?.[index]?.includes(key);
		},
		showAiSummary() {
			return !!(this?.detect?.aiSummary && (this.detect.aiSummaryReviewed || this.showUnreviewedAiSummaries));
		}
	}
}});
