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
      beginTime: null,
      endTime: null,
    },
    footerProps: { 'items-per-page-options': [10,50,250,1000] },
    kind: "",
    relativeTimeEnabled: true,
    relativeTimeValue: 24,
    dateRange: '',
    relativeTimeUnits: [
      { title: this.$root.i18n.seconds, value: RELATIVE_TIME_SECONDS },
      { title: this.$root.i18n.minutes, value: RELATIVE_TIME_MINUTES },
      { title: this.$root.i18n.hours, value: RELATIVE_TIME_HOURS },
      { title: this.$root.i18n.days, value: RELATIVE_TIME_DAYS },
      { title: this.$root.i18n.weeks, value: RELATIVE_TIME_WEEKS },
      { title: this.$root.i18n.months, value: RELATIVE_TIME_MONTHS }
    ],
    relativeTimeUnit: RELATIVE_TIME_HOURS,
    zone: '',
  }},
  created() {
    this.zone = moment.tz.guess();
    this.loadLocalSettings();
    this.notifyInputsChanged();
  },
  unmounted() {
    this.$root.unsubscribe("job", this.updateJob);
  },
  watch: {
    '$route': 'loadData',
    'sortBy': 'saveLocalSettings',
    'relativeTimeValue': 'saveLocalSettings',
    'relativeTimeUnit': 'saveLocalSettings',
    'itemsPerPage': 'saveLocalSettings',
  },
  methods: {
    async loadData() {
      this.$root.startLoading();
      try {
        if (this.$route.query.k) {
          this.kind = this.$route.query.k;
        }
        if (this.$route.query.z) {
          this.zone = this.$route.query.z;
        }
        const response = await this.$root.papi.get('jobs', {
          params: {
            kind: this.kind,
            dateRange: this.dateRange,
            dateRangeFormat: this.i18n.timePickerSample,
            timezone: this.zone,
          }
        });
        this.jobs = response.data;
        this.loadUserDetails();
      } catch (error) {
        this.$root.showError(error);
      }
      this.$root.stopLoading();
      this.$root.subscribe("job", this.updateJob);
    },
    loadUserDetails() {
      for (var i = 0; i < this.jobs.length; i++) {
        this.$root.populateUserDetails(this.jobs[i], "userId", "owner");
      }
    },
    saveTimezone() {
      localStorage['timezone'] = this.zone;
    },
    saveLocalSettings() {
      localStorage['settings.jobs.sortBy'] = JSON.stringify(this.sortBy);
      localStorage['settings.jobs.itemsPerPage'] = this.itemsPerPage;
      localStorage['settings.jobs.relativeTimeValue'] = this.relativeTimeValue;
      localStorage['settings.jobs.relativeTimeUnit'] = this.relativeTimeUnit;
    },
    loadLocalSettings() {
      if (localStorage['timezone']) this.zone = localStorage['timezone'];

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

      this.relativeTimeValue = parseInt(localStorage['settings.jobs.relativeTimeValue']) || 24;
      this.relativeTimeUnit = localStorage['settings.jobs.relativeTimeUnit'] || RELATIVE_TIME_HOURS;
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
      this.addJob(this.form.sensorId, this.form.importId, this.form.protocol, this.form.srcIp, this.form.srcPort, this.form.dstIp, this.form.dstPort, this.form.beginTime, this.form.endTime);
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
      if (this.form.beginTime) localStorage['settings.jobs.addJobForm.beginTime'] = this.form.beginTime;
      if (this.form.endTime) localStorage['settings.jobs.addJobForm.endTime'] = this.form.endTime;
    },
    clearAddJobForm() {
      this.form.sensorId = null;
      this.form.importId = null;
      this.form.protocol = null;
      this.form.srcIp = null;
      this.form.srcPort = null;
      this.form.dstIp = null;
      this.form.dstPort = null;
      this.form.beginTime = null;
      this.form.endTime = null;
      localStorage.removeItem('settings.jobs.addJobForm.sensorId');
      localStorage.removeItem('settings.jobs.addJobForm.importId');
      localStorage.removeItem('settings.jobs.addJobForm.protocol');
      localStorage.removeItem('settings.jobs.addJobForm.srcIp');
      localStorage.removeItem('settings.jobs.addJobForm.srcPort');
      localStorage.removeItem('settings.jobs.addJobForm.dstIp');
      localStorage.removeItem('settings.jobs.addJobForm.dstPort');
      localStorage.removeItem('settings.jobs.addJobForm.beginTime');
      localStorage.removeItem('settings.jobs.addJobForm.endTime');
    },
    async addJob(sensorId, importId, protocol, srcIp, srcPort, dstIp, dstPort, beginTime, endTime) {
      try {
        if (!sensorId) {
          this.$root.showError(this.i18n.sensorIdRequired);
        } else {
          if (protocol) {
            protocol = protocol.toLowerCase();
          }
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
    loading() {
      return this.$root.loading;
    },
    showAbsoluteTime() {
      this.relativeTimeEnabled = false;
      setTimeout(this.setupDateRangePicker, 10);
    },
    showRelativeTime() {
      this.relativeTimeEnabled = true;
      this.notifyInputsChanged();
    },
    setupDateRangePicker() {
      if (this.relativeTimeEnabled) return;

      // range = document.getElementById('jobsdaterange');
      $('#jobsdaterange').daterangepicker({
        ranges: this.$root.generateDatePickerPreselects(),
        timePicker: true,
        timePickerSeconds: true,
        endDate: this.getEndDate(),
        startDate: this.getStartDate(),
        locale: {
          format: this.i18n.timePickerFormat
        }
      });
      if (this.dateRange == '') {
        this.dateRange = $('#jobsdaterange')[0].value;
      }
      $('#jobsdaterange').on('hide.daterangepicker', (ev, picker) => {
        this.hideDateRangePicker();
      });
    },
    showDateRangePicker() {
      if (this.relativeTimeEnabled) return;
      $('#jobsdaterange').click();
    },
    hideDateRangePicker() {
      if (this.relativeTimeEnabled) return;
      this.dateRange = $('#jobsdaterange')[0].value;
      this.notifyInputsChanged();
    },
    getEndDate() {
      if (this.dateRange != '') {
        var pieces = this.dateRange.split(" - ");
        if (pieces.length == 2) {
          return moment(pieces[1], this.i18n.timePickerFormat);
        }
      }
      return moment();
    },
    getStartDate() {
      if (this.dateRange != '') {
        var pieces = this.dateRange.split(" - ");
        if (pieces.length == 2) {
          return moment(pieces[0], this.i18n.timePickerFormat);
        }
      }
      var unit = "hour";
      switch (this.relativeTimeUnit) {
        case RELATIVE_TIME_SECONDS: unit = "seconds"; break;
        case RELATIVE_TIME_MINUTES: unit = "minutes"; break;
        case RELATIVE_TIME_HOURS: unit = "hours"; break;
        case RELATIVE_TIME_DAYS: unit = "days"; break;
        case RELATIVE_TIME_WEEKS: unit = "weeks"; break;
        case RELATIVE_TIME_MONTHS: unit = "months"; break;
      }
      return moment().subtract(this.relativeTimeValue, unit);
    },
    getRelativeTimeUnits() {
      let text = 'hours';

      this.relativeTimeUnits.forEach((unit) => {
        if (unit.value == this.relativeTimeUnit) {
          text = unit.title;
          return false;
        }
      });

      return text;
    },
    setRelativeTimeUnits(m) {
      let value = 30;

      this.relativeTimeUnits.forEach((unit) => {
        if (unit.title.toLowerCase() == m.toLowerCase()) {
          value = unit.value;
          return false;
        }
      });

      this.relativeTimeUnit = value;
    },
    notifyInputsChanged() {
      if (this.relativeTimeEnabled) {
        this.dateRange = '';
        this.dateRange = this.getStartDate().format(this.i18n.timePickerFormat) + " - " + this.getEndDate().format(this.i18n.timePickerFormat);
      }

      this.loadData();
    },
  }
}});
