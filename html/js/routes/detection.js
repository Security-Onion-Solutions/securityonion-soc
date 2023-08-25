// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

routes.push({ path: '/detection/:id', name: 'detection', component: {
  template: '#page-detection',
  data() { return {
		i18n: this.$root.i18n,
		params: {},
		detect: null,
		origDetect: null,
		curEditTarget: null, // string containing element ID, null if not editing
		origValue: null,
		editField: null,
		rules: {
      required: value => (value && value.length > 0) || this.$root.i18n.required,
      number: value => (! isNaN(+value) && Number.isInteger(parseFloat(value))) || this.$root.i18n.required,
      hours: value => (!value || /^\d{1,4}(\.\d{1,4})?$/.test(value)) || this.$root.i18n.invalidHours,
      shortLengthLimit: value => (value.length < 100) || this.$root.i18n.required,
      longLengthLimit: value => (encodeURI(value).split(/%..|./).length - 1 < 10000000) || this.$root.i18n.required,
      fileSizeLimit: value => (value == null || value.size < this.maxUploadSizeBytes) || this.$root.i18n.fileTooLarge.replace("{maxUploadSizeBytes}", this.$root.formatCount(this.maxUploadSizeBytes)),
      fileNotEmpty: value => (value == null || value.size > 0) || this.$root.i18n.fileEmpty,
      fileRequired: value => (value != null) || this.$root.i18n.required,
		},
		severityOptions: ['low', 'medium', 'high'],
		engineOptions: ['suricata', 'yara', 'elastalert'],
		panel: [0, 1, 2],
		activeTab: '',
		associatedPlaybook: {
			onionId: 'y5IYKIoB9-Z7uL2kmy_o',
			publicId: "4020131e-223a-421e-8ebe-8a211a5ac4d6",
			title: "Find the baddies",
			severity: "high",
			description: "A long description that spans multiple lines. A long description that spans multiple lines. A long description that spans multiple lines. A long description that spans multiple lines. A long description that spans multiple lines. A long description that spans multiple lines.",
			mechanism: "suricata",
			tags: ["one", "two", "three"],
			relatedPlaybooks: [],
			contributors: ["Corey Ogburn"],
			userEditable: true,
			createTime: "2023-08-22T12:49:47.302819008-06:00",
			userId: "83656890-2acd-4c0b-8ab9-7c73e71ddaf3",
		},
  }},
  created() {
  },
  watch: {
	},
	mounted() {
		this.$root.loadParameters('detection', this.initDetection);
	},
  methods: {
		async initDetection(params) {
			this.params = params;
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
				title: 'Detection title not yet provided - click here to update this title',
				description: 'Detection description not yet provided - click here to update this description',
				author: author,
				publicId: '',
				severity: 'low',
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
				this.detect.note = 'This is a note.';
      } catch (error) {
        if (error.response != undefined && error.response.status == 404) {
          this.$root.showError(this.i18n.notFound);
        } else {
          this.$root.showError(error);
        }
			}

      this.$root.stopLoading();
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
		saveDetection(createNew) {
			if (createNew) {
				this.$root.papi.post('/detection', this.detect);
			} else {
				this.$root.papi.put('/detection', this.detect);
			}
			this.origDetect = Object.assign({}, this.detect);
		},
		print(x) {
			console.log(x);
		},
  }
}});
