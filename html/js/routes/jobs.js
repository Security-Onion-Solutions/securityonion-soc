// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

const JobStatusPending = 0;
const JobStatusCompleted = 1;
const JobStatusIncomplete = 2;
const JobStatusDeleted = 3;

loadPageTemplate('page-jobs', 'pages/jobs.html');

const jobsComponent = {
  template: '#page-jobs',
  data() { return {
    i18n: this.$root.i18n,
    jobs: [],
    headers: [
      { title: this.$root.i18n.id, value: 'id' },
      { title: this.$root.i18n.owner, value: 'owner' },
      { title: this.$root.i18n.dateQueued, value: 'createTime' },
      { title: this.$root.i18n.dateCompleted, value: 'completeTime' },
      { title: this.$root.i18n.sensorId, value: 'sensorId' },
      { title: this.$root.i18n.status, value: 'status' },
      { title: this.$root.i18n.actions },
    ],
    reportHeaders: [
      { title: this.$root.i18n.id, value: 'id' },
      { title: this.$root.i18n.owner, value: 'owner' },
      { title: this.$root.i18n.dateQueued, value: 'createTime' },
      { title: this.$root.i18n.description, value: 'description' },
      { title: this.$root.i18n.filesize, value: 'size' },
      { title: this.$root.i18n.status, value: 'status' },
      { title: this.$root.i18n.actions },
    ],
    rules: {
      required: value => !!value || this.$root.i18n.required,
    },
    sortBy: [{ key: 'id', order: 'asc' }],
    itemsPerPage: 10,
    dialog: false,
    form: {
      valid: false,
      sensorId: null,
      importId: null,
      protocol: null,
      srcIp: null,
      srcPort: null,
      dstIp: null,
      dstPort: null,
      type: null,
      timeframe: '',
    },
    itemsPerPageOptions: [10,50,250,1000],
    kind: '',
    standardReportTypes: [
      { title: this.$root.i18n.reportProductivity, value: 'productivity' },
    ]
  }},
  created() {
    this.loadData();
  },
  unmounted() {
    this.$root.unsubscribe('job', this.updateJob);
  },
  watch: {
    '$route': 'loadData',
    'sortBy': 'saveLocalSettings',
    'itemsPerPage': 'saveLocalSettings',
  },
  methods: {
    async loadData() {
      this.$root.startLoading();
      try {
        this.kind = this.$route.path.replace("/", "");
        const response = await this.$root.papi.get('jobs', { params: { kind: this.kind }});
        this.jobs = response.data;
        this.loadUserDetails();
        this.loadLocalSettings();
      } catch (error) {
        this.$root.showError(error);
      }
      this.$root.stopLoading();
      this.$root.subscribe("job", this.updateJob);
    },
    getReportDescription(type) {
      const types = this.getReportTypes();
      for (var idx = 0; idx < types.length; idx++) {
        const reportType = types[idx];
        if (reportType.value == type) {
          return reportType.title;
        }
      }
      return type;
    },
    getReportTypes() {
      let types = [];
      types = types.concat(this.standardReportTypes);

      for (const key in this.$root.getCustomReports()) {
        types.push({ title: this.$root.getCustomReports()[key], value: key });
      }
      
      return types;
    },
    loadUserDetails() {
      for (var i = 0; i < this.jobs.length; i++) {
        this.$root.populateUserDetails(this.jobs[i], 'userId', 'owner');
      }
    },
    saveLocalSettings() {
      localStorage['settings.jobs.sortBy'] = JSON.stringify(this.sortBy);
      localStorage['settings.jobs.itemsPerPage'] = this.itemsPerPage;
    },
    loadLocalSettings() {
      if (localStorage['settings.jobs.sortBy']) {
        try {
          this.sortBy = JSON.parse(localStorage['settings.jobs.sortBy']);
        } catch {}
        this.itemsPerPage = parseInt(localStorage['settings.jobs.itemsPerPage']);
      }
      this.form.sensorId = localStorage['settings.jobs.addJobForm.sensorId'];
      this.form.importId = localStorage['settings.jobs.addJobForm.importId'];
      this.form.protocol = localStorage['settings.jobs.addJobForm.protocol'];
      this.form.srcIp = localStorage['settings.jobs.addJobForm.srcIp'];
      this.form.srcPort = localStorage['settings.jobs.addJobForm.srcPort'];
      this.form.dstIp = localStorage['settings.jobs.addJobForm.dstIp'];
      this.form.dstPort = localStorage['settings.jobs.addJobForm.dstPort'];
      this.form.timeframe = localStorage['settings.jobs.addJobForm.' + this.kind + '.timeframe'];
    },
    updateJob(job) {
      for (var i = 0; i < this.jobs.length; i++) {
        if (this.jobs[i].id == job.id) {
          if (job.status == JobStatusDeleted) {
            this.jobs.splice(i, 1);
          } else {
            this.$root.populateUserDetails(job, "userId", "owner");
            this.jobs[i] = job;
          }
          break;
        }
      }
    },
    submitAddJob(event) {
      switch (this.kind) {
        case 'reports':
          this.addExportJob();
          break;
        default:
          this.addJob(this.form.sensorId, this.form.importId, this.form.protocol, this.form.srcIp, this.form.srcPort, this.form.dstIp, this.form.dstPort, this.form.timeframe);
      }
      this.dialog = false;
      this.saveAddJobForm();

      // Auto refresh the job list after a short delay
      setTimeout(this.loadData, 500);
    },
    saveAddJobForm() {
      if (this.form.sensorId) localStorage['settings.jobs.addJobForm.sensorId'] = this.form.sensorId;
      if (this.form.importId) localStorage['settings.jobs.addJobForm.importId'] = this.form.importId;
      if (this.form.protocol) localStorage['settings.jobs.addJobForm.protocol'] = this.form.protocol;
      if (this.form.srcIp) localStorage['settings.jobs.addJobForm.srcIp'] = this.form.srcIp;
      if (this.form.srcPort) localStorage['settings.jobs.addJobForm.srcPort'] = this.form.srcPort;
      if (this.form.dstIp) localStorage['settings.jobs.addJobForm.dstIp'] = this.form.dstIp;
      if (this.form.dstPort) localStorage['settings.jobs.addJobForm.dstPort'] = this.form.dstPort;
      if (this.form.timeframe) localStorage['settings.jobs.addJobForm.' + this.kind + '.timeframe'] = this.form.timeframe;
    },
    clearAddJobForm() {
      this.form.sensorId = null;
      this.form.importId = null;
      this.form.protocol = null;
      this.form.srcIp = null;
      this.form.srcPort = null;
      this.form.dstIp = null;
      this.form.dstPort = null;
      this.form.timeframe = '';
      $('#jobtimeframe').val('');
      if (this.isKind("pcap")) {
        localStorage.removeItem('settings.jobs.addJobForm.sensorId');
        localStorage.removeItem('settings.jobs.addJobForm.importId');
        localStorage.removeItem('settings.jobs.addJobForm.protocol');
        localStorage.removeItem('settings.jobs.addJobForm.srcIp');
        localStorage.removeItem('settings.jobs.addJobForm.srcPort');
        localStorage.removeItem('settings.jobs.addJobForm.dstIp');
        localStorage.removeItem('settings.jobs.addJobForm.dstPort');
      }
      localStorage.removeItem('settings.jobs.addJobForm.' + this.kind + '.timeframe');
    },
    addExportJob() {
      let beginDate;
      let endDate;
      if (this.form.timeframe) {
        const [beginTime, endTime] = this.form.timeframe.split(' - ', 2);
        beginDate = moment(beginTime, this.i18n.timePickerFormat).format(/* ISO 8601 */);
        endDate = moment(endTime, this.i18n.timePickerFormat).format(/* ISO 8601 */);
      }
      this.$root.export({
        type: this.form.type,
        description: this.getReportDescription(this.form.type),
      }, beginDate, endDate);
    },
    async addJob(sensorId, importId, protocol, srcIp, srcPort, dstIp, dstPort, timeframe) {
      try {
        if (!sensorId) {
          this.$root.showError(this.i18n.sensorIdRequired);
        } else {
          if (protocol) {
            protocol = protocol.toLowerCase();
          }

          let filter = {
            importId: importId,
            protocol: protocol,
            srcIp: srcIp,
            srcPort: parseInt(srcPort),
            dstIp: dstIp,
            dstPort: parseInt(dstPort),
          };

          let beginDate;
          let endDate;
          if (timeframe) {
            const [beginTime, endTime] = timeframe.split(' - ', 2);
            beginDate = moment(beginTime, this.i18n.timePickerFormat).format(/* ISO 8601 */);
            endDate = moment(endTime, this.i18n.timePickerFormat).format(/* ISO 8601 */);
          }

          if (beginDate && endDate) {
            filter.beginTime = beginDate;
            filter.endTime = endDate;
          }

          const response = await this.$root.papi.post('job/', {
            nodeId: sensorId,
            filter: filter,
          });
          this.$root.populateUserDetails(response.data, "userId", "owner");
          this.jobs.push(response.data);
        }
      } catch (error) {
         this.$root.showError(error);
      }
    },
    async deleteJob(job) {
      try {
        if (job) {
          await this.$root.papi.delete('job/' + job.id);
          // Filter out the deleted job from the local array
          this.jobs = this.jobs.filter((j) => j.id != job.id);
        }
      } catch (error) {
         this.$root.showError(error);
      }
    },
    formatJobStatus(job) {
      var status = this.i18n.pending;
      if (job.status == JobStatusCompleted) {
        status = this.i18n.completed;
      } else if (job.status == JobStatusIncomplete) {
        status = this.i18n.incomplete;
      } else if (job.status == JobStatusDeleted) {
        status = this.i18n.deleted;
      }
      return status;
    },
    colorJobStatus(job) {
      var color = "gray";
      if (job.status == JobStatusCompleted) {
        color = "success";
      } else if (job.status == JobStatusIncomplete) {
        color = "info";
      } else if (job.status == JobStatusDeleted) {
        color = "warning";
      }
      return color;
    },
    isKind(kind) {
      if ((this.kind == '' || this.kind == 'jobs') && kind == 'pcap') {
        return true;
      }
      return this.kind == kind;
    },
    openNewJobDialog() {
      this.dialog = true;
      this.$nextTick(() => {
        this.setupDateRangePicker();
      })
    },
    setupDateRangePicker() {
      $('#jobtimeframe').daterangepicker({
        ranges: this.$root.generateDatePickerPreselects(),
        timePicker: true,
        timePickerSeconds: true,
        alwaysShowCalendars: true,
        locale: {
          format: this.i18n.timePickerFormat
        },
        drops: 'up',
        autoUpdateInput: false,
      });
      if (this.form.timeframe == '') {
        this.form.timeframe = $('#jobtimeframe')[0].value;
      }
      const route = this;
      $('#jobtimeframe').on('apply.daterangepicker', function (ev, picker) {
        const value = picker.startDate.format(route.i18n.timePickerFormat) + ' - ' + picker.endDate.format(route.i18n.timePickerFormat)
        route.form.timeframe = value;
        $(this).val(value);
      });
    },
    isComplete(job) {
      return job.status == JobStatusCompleted;
    },
    downloadUrl(job) {
      return this.$root.apiUrl + "stream?jobId=" + job.id;
    },
    isViewable() {
      switch(this.kind) {
        case 'reports':
          return false;
      }
      return true;
    },
    isDownloadable(job) {
      switch(this.kind) {
        case 'reports':
          return true
      }
      return false;
    },
    isDownloadReady(job) {
      return this.isComplete(job) && job.size > 0;
    },
    canCreate() {
      switch(this.kind) {
        case 'reports':
          return this.$root.isLicensed(this.$root.FEAT_RPT);
      }
      return true;
    },
    isSensorJob() {
      switch(this.kind) {
        case 'reports':
          return false;
      }
      return true;
    },
    getHeaders() {
      switch(this.kind) {
        case 'reports':
          return this.reportHeaders;
      }
      return this.headers;        
    },
    getDescription(job) {
      var desc = "";
      switch(this.kind) {
        case 'reports':
          if (job.filter.parameters.description) {
            desc = job.filter.parameters.description;
          } else {
            desc = this.$root.localizeMessage(job.filter.parameters.type);
          }
          if (job.filter.parameters.id) {
            desc += " " + job.filter.parameters.id
          } else if (job.filter.beginTime != '0001-01-01T00:00:00Z' && job.filter.endTime != '0001-01-01T00:00:00Z') {
            var start = moment(job.filter.beginTime).format(this.i18n.dateFormat);
            var end = moment(job.filter.endTime).format(this.i18n.dateFormat);
            desc += ": " + start + " - " + end;
          }
          if (job.fileExtension != "bin") {
            desc += " [" + this.$root.localizeMessage(job.fileExtension) + "]";
          }
          break;
        default:
          desc = JSON.stringify(job.filter.parameters);
      }
      return desc;
    },
  }
};

const pcapComponent = Object.assign({}, jobsComponent);
routes.push({path: '/jobs', name: 'jobs', component: pcapComponent });

const reportsComponent = Object.assign({}, jobsComponent);
routes.push({ path: '/reports', name: 'reports', component: reportsComponent});
