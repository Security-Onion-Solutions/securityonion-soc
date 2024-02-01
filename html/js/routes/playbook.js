// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

routes.push({ path: '/playbook/:id', name: 'playbook', component: {
  template: '#page-playbook',
  data() { return {
		i18n: this.$root.i18n,
		params: {},
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
		playbook: null,
		origPlaybook: null,
		curEditTarget: null, // string containing element ID, null if not editing
		origValue: null,
		editField: null,
		severityOptions: ['low', 'medium', 'high'],
		engineOptions: ['none', 'suricata', 'yara', 'elastalert'],
		panel: [0, 1, 2],
		activeTab: '',
		tags: [],
		addQuestion: '',
		addContext: '',
		addDataSources: [],
		addQuery: '',
		search: '',
		questionHeaders: [{ title: '@timestamp', key: 'item.payload["@timestamp"]' }, { title: '@version', value: '@version' }, { title: 'message', value: 'message' }],
  }},
  created() {
  },
  watch: {
	},
	mounted() {
		this.$root.loadParameters('playbooks', this.initPlaybook);
	},
  methods: {
		async initPlaybook(params) {
			this.params = params;
			if (this.$route.params.id === 'create') {
				this.detect = this.newPlaybook();
			} else {
				await this.loadData();
			}

			this.origPlaybook = Object.assign({}, this.playbook);

			this.loadUrlParameters();
		},
		loadUrlParameters() {

		},
		newPlaybook() {
			let author = [this.$root.user.firstName, this.$root.user.lastName].filter(x => x).join(' ');
			return {
				publicId: '',
				title: 'Detection title not yet provided - click here to update this title',
				description: 'Detection description not yet provided - click here to update this description',
				mechanism: '',
				tags: [],
				relatedPlaybooks: [],
				detectionLinks: [],
				contributors: [author],
				userEditable: true,
				questions: [],
				note: '',
			}
		},
		async loadData() {
			this.$root.startLoading();

			// try {
			// 		const response = await this.$root.papi.get('playbook/' + encodeURIComponent(this.$route.params.id));
			// 		this.detect = response.data;
      // } catch (error) {
      //   if (error.response != undefined && error.response.status == 404) {
      //     this.$root.showError(this.i18n.notFound);
      //   } else {
      //     this.$root.showError(error);
      //   }
			// }
			if (this.isNew()) {
				this.playbook = this.newPlaybook();
			} else {
				this.playbook = {
					onionId: this.$route.params.id,
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
					questions: [
						{
							question: "What network resources did they access?",
							context: "Bad actors do bad things to network resources",
							dataSources: ['windows_security', 'process_auditing'],
							query: '*',
							results: [
								{
									"source": "manager:.ds-logs-elastic_agent-default-2023.08.21-000001",
									"Time": "2023-08-24T15:10:05.747Z",
									"timestamp": "2023-08-24T15:10:05.747Z",
									"id": "y5IYKIoB9-Z7uL2kmy_o",
									"type": "",
									"score": 2,
									"payload": {
										"@timestamp": "2023-08-24T15:10:05.747Z",
										"@version": "1",
										"agent.ephemeral_id": "b36260f3-7e22-4ada-9736-7825bba61050",
										"agent.id": "6a7d0533-85fe-4aab-ad23-25659d59415f",
										"agent.name": "manager",
										"agent.type": "filebeat",
										"agent.version": "8.8.2",
										"container.id": "elastic-agent-cdc5ba",
										"data_stream.dataset": "elastic_agent",
										"data_stream.namespace": "default",
										"data_stream.type": "logs",
										"ecs.version": "8.0.0",
										"elastic_agent.id": "6a7d0533-85fe-4aab-ad23-25659d59415f",
										"elastic_agent.snapshot": false,
										"elastic_agent.version": "8.8.2",
										"event.agent_id_status": "auth_metadata_missing",
										"event.dataset": "elastic_agent",
										"event.ingested": "2023-08-24T15:10:16Z",
										"event.module": "elastic_agent",
										"host.architecture": "x86_64",
										"host.containerized": false,
										"host.hostname": "manager",
										"host.id": "9b909224852841ee9e8394c0ccb6f345",
										"host.ip": [
											"192.168.122.119",
											"172.17.1.1",
											"172.17.0.1"
										],
										"host.mac": [
											"02-42-F7-90-7C-0F",
											"02-42-FD-01-4C-18",
											"22-69-52-DA-7E-60",
											"26-32-CC-C2-D0-96",
											"32-5D-A3-D9-5E-BB",
											"36-30-04-3E-2A-74",
											"3A-47-4A-42-2D-42",
											"52-54-00-17-A5-16",
											"52-54-00-79-9B-AF",
											"56-22-21-D2-59-BB",
											"5A-84-1E-33-78-6F",
											"5A-B1-C1-9E-26-54",
											"5E-07-4D-47-FC-B6",
											"66-FE-30-61-E6-77",
											"82-20-8F-6D-BA-2B",
											"86-14-06-40-98-7D",
											"86-29-18-6F-10-88",
											"8E-AD-CA-9F-EA-F6",
											"96-4D-FB-AD-AB-8E",
											"AA-FB-73-2B-C4-24",
											"B2-68-3A-55-50-88",
											"BE-53-9A-99-67-0C",
											"CA-68-C4-C1-5B-4D",
											"E2-0C-CE-E7-DA-50",
											"EE-F2-CD-8D-0A-17",
											"FE-99-5F-39-DF-D1"
										],
										"host.name": "manager",
										"host.os.family": "redhat",
										"host.os.kernel": "5.15.0-103.114.4.el9uek.x86_64",
										"host.os.name": "Oracle Linux Server",
										"host.os.platform": "ol",
										"host.os.type": "linux",
										"host.os.version": "9.2",
										"input.type": "filestream",
										"log.file.path": "/opt/Elastic/Agent/data/elastic-agent-cdc5ba/logs/elastic-agent-20230824.ndjson",
										"log.level": "info",
										"log.offset": 311104,
										"log.origin.file.line": 821,
										"log.origin.file.name": "coordinator/coordinator.go",
										"log.source": "elastic-agent",
										"message": "Updating running component model",
										"metadata.beat": "filebeat",
										"metadata.input.beats.host.ip": "172.17.1.1",
										"metadata.input_id": "filestream-monitoring-agent",
										"metadata.raw_index": "logs-elastic_agent-default",
										"metadata.stream_id": "filestream-monitoring-agent",
										"metadata.type": "_doc",
										"metadata.version": "8.8.2",
										"tags": [
											"elastic-agent",
											"input-manager",
											"beats_input_codec_plain_applied"
										]
									}
								},
								{
									"source": "manager:.ds-logs-elastic_agent-default-2023.08.21-000001",
									"Time": "2023-08-24T15:09:25.702Z",
									"timestamp": "2023-08-24T15:09:25.702Z",
									"id": "GJIXKIoB9-Z7uL2k7C-E",
									"type": "",
									"score": 2,
									"payload": {
										"@timestamp": "2023-08-24T15:09:25.702Z",
										"@version": "1",
										"agent.ephemeral_id": "b36260f3-7e22-4ada-9736-7825bba61050",
										"agent.id": "6a7d0533-85fe-4aab-ad23-25659d59415f",
										"agent.name": "manager",
										"agent.type": "filebeat",
										"agent.version": "8.8.2",
										"container.id": "elastic-agent-cdc5ba",
										"data_stream.dataset": "elastic_agent",
										"data_stream.namespace": "default",
										"data_stream.type": "logs",
										"ecs.version": "8.0.0",
										"elastic_agent.id": "6a7d0533-85fe-4aab-ad23-25659d59415f",
										"elastic_agent.snapshot": false,
										"elastic_agent.version": "8.8.2",
										"event.agent_id_status": "auth_metadata_missing",
										"event.dataset": "elastic_agent",
										"event.ingested": "2023-08-24T15:09:31Z",
										"event.module": "elastic_agent",
										"host.architecture": "x86_64",
										"host.containerized": false,
										"host.hostname": "manager",
										"host.id": "9b909224852841ee9e8394c0ccb6f345",
										"host.ip": [
											"192.168.122.119",
											"172.17.1.1",
											"172.17.0.1"
										],
										"host.mac": [
											"02-42-F7-90-7C-0F",
											"02-42-FD-01-4C-18",
											"22-69-52-DA-7E-60",
											"26-32-CC-C2-D0-96",
											"32-5D-A3-D9-5E-BB",
											"36-30-04-3E-2A-74",
											"3A-47-4A-42-2D-42",
											"52-54-00-17-A5-16",
											"52-54-00-79-9B-AF",
											"56-22-21-D2-59-BB",
											"5A-84-1E-33-78-6F",
											"5A-B1-C1-9E-26-54",
											"5E-07-4D-47-FC-B6",
											"66-FE-30-61-E6-77",
											"82-20-8F-6D-BA-2B",
											"86-14-06-40-98-7D",
											"86-29-18-6F-10-88",
											"8E-AD-CA-9F-EA-F6",
											"96-4D-FB-AD-AB-8E",
											"AA-FB-73-2B-C4-24",
											"AE-49-EF-7B-5E-B9",
											"B2-68-3A-55-50-88",
											"BE-53-9A-99-67-0C",
											"CA-68-C4-C1-5B-4D",
											"E2-0C-CE-E7-DA-50",
											"EE-F2-CD-8D-0A-17",
											"FE-99-5F-39-DF-D1"
										],
										"host.name": "manager",
										"host.os.family": "redhat",
										"host.os.kernel": "5.15.0-103.114.4.el9uek.x86_64",
										"host.os.name": "Oracle Linux Server",
										"host.os.platform": "ol",
										"host.os.type": "linux",
										"host.os.version": "9.2",
										"input.type": "filestream",
										"log.file.path": "/opt/Elastic/Agent/data/elastic-agent-cdc5ba/logs/elastic-agent-20230824.ndjson",
										"log.level": "error",
										"log.offset": 304406,
										"log.origin.file.line": 221,
										"log.origin.file.name": "fleet/fleet_gateway.go",
										"log.source": "elastic-agent",
										"message": "Checkin request to fleet-server succeeded after 2 failures",
										"metadata.beat": "filebeat",
										"metadata.input.beats.host.ip": "172.17.1.1",
										"metadata.input_id": "filestream-monitoring-agent",
										"metadata.raw_index": "logs-elastic_agent-default",
										"metadata.stream_id": "filestream-monitoring-agent",
										"metadata.type": "_doc",
										"metadata.version": "8.8.2",
										"tags": [
											"elastic-agent",
											"input-manager",
											"beats_input_codec_plain_applied"
										]
									}
								},
								{
									"source": "manager:.ds-logs-elastic_agent-default-2023.08.21-000001",
									"Time": "2023-08-24T15:08:46.446Z",
									"timestamp": "2023-08-24T15:08:46.446Z",
									"id": "lZIXKIoB9-Z7uL2kTy6x",
									"type": "",
									"score": 2,
									"payload": {
										"@timestamp": "2023-08-24T15:08:46.446Z",
										"@version": "1",
										"agent.ephemeral_id": "b36260f3-7e22-4ada-9736-7825bba61050",
										"agent.id": "6a7d0533-85fe-4aab-ad23-25659d59415f",
										"agent.name": "manager",
										"agent.type": "filebeat",
										"agent.version": "8.8.2",
										"container.id": "elastic-agent-cdc5ba",
										"data_stream.dataset": "elastic_agent",
										"data_stream.namespace": "default",
										"data_stream.type": "logs",
										"ecs.version": "8.0.0",
										"elastic_agent.id": "6a7d0533-85fe-4aab-ad23-25659d59415f",
										"elastic_agent.snapshot": false,
										"elastic_agent.version": "8.8.2",
										"event.agent_id_status": "auth_metadata_missing",
										"event.dataset": "elastic_agent",
										"event.ingested": "2023-08-24T15:08:50Z",
										"event.module": "elastic_agent",
										"host.architecture": "x86_64",
										"host.containerized": false,
										"host.hostname": "manager",
										"host.id": "9b909224852841ee9e8394c0ccb6f345",
										"host.ip": [
											"192.168.122.119",
											"172.17.1.1",
											"172.17.0.1"
										],
										"host.mac": [
											"02-42-F7-90-7C-0F",
											"02-42-FD-01-4C-18",
											"22-69-52-DA-7E-60",
											"26-32-CC-C2-D0-96",
											"32-5D-A3-D9-5E-BB",
											"36-30-04-3E-2A-74",
											"3A-47-4A-42-2D-42",
											"52-54-00-17-A5-16",
											"52-54-00-79-9B-AF",
											"56-22-21-D2-59-BB",
											"5A-84-1E-33-78-6F",
											"5A-B1-C1-9E-26-54",
											"5E-07-4D-47-FC-B6",
											"66-FE-30-61-E6-77",
											"82-20-8F-6D-BA-2B",
											"86-14-06-40-98-7D",
											"86-29-18-6F-10-88",
											"8E-AD-CA-9F-EA-F6",
											"96-4D-FB-AD-AB-8E",
											"AA-FB-73-2B-C4-24",
											"AE-49-EF-7B-5E-B9",
											"B2-68-3A-55-50-88",
											"BE-53-9A-99-67-0C",
											"CA-68-C4-C1-5B-4D",
											"E2-0C-CE-E7-DA-50",
											"EE-F2-CD-8D-0A-17",
											"FE-99-5F-39-DF-D1"
										],
										"host.name": "manager",
										"host.os.family": "redhat",
										"host.os.kernel": "5.15.0-103.114.4.el9uek.x86_64",
										"host.os.name": "Oracle Linux Server",
										"host.os.platform": "ol",
										"host.os.type": "linux",
										"host.os.version": "9.2",
										"input.type": "filestream",
										"log.file.path": "/opt/Elastic/Agent/data/elastic-agent-cdc5ba/logs/elastic-agent-20230824.ndjson",
										"log.level": "info",
										"log.offset": 296546,
										"log.origin.file.line": 821,
										"log.origin.file.name": "coordinator/coordinator.go",
										"log.source": "elastic-agent",
										"message": "Updating running component model",
										"metadata.beat": "filebeat",
										"metadata.input.beats.host.ip": "172.17.1.1",
										"metadata.input_id": "filestream-monitoring-agent",
										"metadata.raw_index": "logs-elastic_agent-default",
										"metadata.stream_id": "filestream-monitoring-agent",
										"metadata.type": "_doc",
										"metadata.version": "8.8.2",
										"tags": [
											"elastic-agent",
											"input-manager",
											"beats_input_codec_plain_applied"
										]
									}
								},
							]
						}
					],
					note: "This is a note",
				};
			}

      this.$root.stopLoading();
		},
		isNew() {
			return this.$route.params.id === 'create';
		},
		cancelPlaybook() {
			if (this.isNew()) {
				this.$router.push({name: 'playbooks'});
			} else {
				this.playbook = this.origPlaybook;
			}
		},
		generatePublicID() {
			this.playbook.publicId = crypto.randomUUID();
		},
		async startEdit(target, field) {
			if (this.curEditTarget === target) return;
			if (this.curEditTarget !== null) await this.stopEdit(false);

			this.curEditTarget = target;
			this.origValue = this.playbook[field];
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
				this.playbook[this.editField] = this.origValue;
			} else if (!this.isNew()) {
				// const response = await this.$root.papi.put('/playbook', this.playbook);
        // console.log('UPDATE', response);
			}

			this.curEditTarget = null;
			this.origValue = null;
			this.editField = null;
		},
		savePlaybook(createNew) {
			// if (createNew) {
			// 	this.$root.papi.post('/playbook', this.playbook);
			// } else {
			// 	this.$root.papi.put('/playbook', this.playbook);
			// }

			this.origPlaybook = Object.assign({}, this.playbook);
		},
		print(x) {
			console.log(x);
		},
  }
}});
