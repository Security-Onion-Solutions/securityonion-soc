// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

routes.push({ path: '/detection/:id', name: 'detection', component: {
  template: '#page-detection',
  data() { return {
		i18n: this.$root.i18n,
		presets: {},
		params: {},
		detect: null,
		origDetect: null,
		curEditTarget: null, // string containing element ID, null if not editing
		origValue: null,
		editField: null,
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
		},
		panel: [0, 1, 2],
		activeTab: '',
  }},
  created() {
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
      } catch (error) {
        if (error.response != undefined && error.response.status == 404) {
          this.$root.showError(this.i18n.notFound);
        } else {
          this.$root.showError(error);
        }
			}

      this.$root.stopLoading();
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
		generatePublicID() {
			this.detect.publicId = crypto.randomUUID();
		},
		isEdit(target) {
			return this.curEditTarget === target;
		},
		async stopEdit(commit) {
			if (!commit) {
				this.detect[this.editField] = this.origValue;
			} else if (!this.isNew()) {
				const response = await this.$root.papi.put('/detection', this.detect);

        console.log('UPDATE', response);
			}

			this.curEditTarget = null;
			this.origValue = null;
			this.editField = null;
		},
		async saveDetection(createNew) {
			if (this.curEditTarget !== null) this.stopEdit(true);

			if (this.isNew()) {
				this.$refs['detection'].validate();
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

			try {
				let response;
				if (createNew) {
					response = await this.$root.papi.post('/detection', this.detect);
				} else {
					response = await this.$root.papi.put('/detection', this.detect);
				}

				this.origDetect = Object.assign({}, this.detect);

				this.$root.showTip(this.i18n.saveSuccess);

				this.$router.push({name: 'detection', params: {id: response.data.id}});
			} catch (error) {
				this.$root.showError(error);
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
			const sidExtract = /\bsid: ?['"]?(.*?)['"]?;/
			const results = sidExtract.exec(this.detect.content);

			if (!results || results.length < 2) {
				// sid not present in rule
				return this.i18n.sidMissingErr;
			} else if (results && results.length > 2) {
				// multiple sids present in rule
				return this.i18n.sidMultipleErr;
			}

			const sid = results[1];

			if (this.detect.publicId !== sid) {
				// sid doesn't match metadata
				return this.i18n.sidMismatchErr;
			}

			// normalize quotes
			this.detect.content = this.detect.content.replaceAll('”', '"');
			this.detect.content = this.detect.content.replaceAll('“', '"');

			return null;
		},
		print(x) {
			console.log(x);
		},
  }
}});
