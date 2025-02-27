// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

const JobStatusPending = 0;
const JobStatusCompleted = 1;
const JobStatusIncomplete = 2;
const JobStatusDeleted = 3;

routes.push({ path: '/jobs', name: 'jobs', component: {
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
      timeframe: '',
    },
    footerProps: { 'items-per-page-options': [10,50,250,1000] },
    kind: '',
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
        if (this.$route.query.k) {
          this.kind = this.$route.query.k;
        }
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
      this.form.beginTime = localStorage['settings.jobs.addJobForm.beginTime'];
      this.form.endTime = localStorage['settings.jobs.addJobForm.endTime'];
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
      this.addJob(this.form.sensorId, this.form.importId, this.form.protocol, this.form.srcIp, this.form.srcPort, this.form.dstIp, this.form.dstPort, this.form.timeframe);
      this.dialog = false;
      this.saveAddJobForm();
    },
    saveAddJobForm() {
      if (this.form.sensorId) localStorage['settings.jobs.addJobForm.sensorId'] = this.form.sensorId;
      if (this.form.importId) localStorage['settings.jobs.addJobForm.importId'] = this.form.importId;
      if (this.form.protocol) localStorage['settings.jobs.addJobForm.protocol'] = this.form.protocol;
      if (this.form.srcIp) localStorage['settings.jobs.addJobForm.srcIp'] = this.form.srcIp;
      if (this.form.srcPort) localStorage['settings.jobs.addJobForm.srcPort'] = this.form.srcPort;
      if (this.form.dstIp) localStorage['settings.jobs.addJobForm.dstIp'] = this.form.dstIp;
      if (this.form.dstPort) localStorage['settings.jobs.addJobForm.dstPort'] = this.form.dstPort;
      if (this.form.timeframe) localStorage['settings.jobs.addJobForm.timeframe'] = this.form.timeframe;
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
      localStorage.removeItem('settings.jobs.addJobForm.sensorId');
      localStorage.removeItem('settings.jobs.addJobForm.importId');
      localStorage.removeItem('settings.jobs.addJobForm.protocol');
      localStorage.removeItem('settings.jobs.addJobForm.srcIp');
      localStorage.removeItem('settings.jobs.addJobForm.srcPort');
      localStorage.removeItem('settings.jobs.addJobForm.dstIp');
      localStorage.removeItem('settings.jobs.addJobForm.dstPort');
      localStorage.removeItem('settings.jobs.addJobForm.timeframe');
    },
    async addJob(sensorId, importId, protocol, srcIp, srcPort, dstIp, dstPort, timeframe) {
      try {
        if (!sensorId) {
          this.$root.showError(this.i18n.sensorIdRequired);
        } else {
          if (protocol) {
            protocol = protocol.toLowerCase();
          }
          const [beginTime, endTime] = timeframe.split(' - ', 2);
          const beginDate = moment(beginTime);
          const endDate = moment(endTime);
          const response = await this.$root.papi.post('job/', {
            nodeId: sensorId,
            filter: {
              importId: importId,
              protocol: protocol,
              srcIp: srcIp,
              srcPort: parseInt(srcPort),
              dstIp: dstIp,
              dstPort: parseInt(dstPort),
              beginTime: beginDate,
              endTime: endDate
            }
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
      if (this.kind == '' && kind == 'pcap') {
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
        $(this).val(value);
      });
    },
    getEndDate() {
      if (this.form.timeframe != '') {
        var pieces = this.form.timeframe.split(' - ');
        if (pieces.length == 2) {
          return moment(pieces[1], this.i18n.timePickerFormat);
        }
      }
      return moment();
    },
    getStartDate() {
      if (this.form.timeframe != '') {
        var pieces = this.form.timeframe.split(' - ');
        if (pieces.length == 2) {
          return moment(pieces[0], this.i18n.timePickerFormat);
        }
      }

      return moment().subtract(24, 'hours');
    },
  }
}});
