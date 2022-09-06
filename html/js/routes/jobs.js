// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
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
      { text: this.$root.i18n.id, value: 'id' },
      { text: this.$root.i18n.owner, value: 'owner' },
      { text: this.$root.i18n.dateQueued, value: 'createTime' },
      { text: this.$root.i18n.dateCompleted, value: 'completeTime' },
      { text: this.$root.i18n.sensorId, value: 'sensorId' },
      { text: this.$root.i18n.status, value: 'status' },
      { text: this.$root.i18n.actions },
    ],
    sortBy: 'id',
    sortDesc: false,
    itemsPerPage: 10,
    dialog: false,
    form: {
      valid: false,
      sensorId: null,
      importId: null,
      srcIp: null,
      srcPort: null,
      dstIp: null,
      dstPort: null,
      beginTime: null,
      endTime: null,
    },
    footerProps: { 'items-per-page-options': [10,50,250,1000] },
    kind: "",
  }},
  created() {
    Vue.filter('formatJobStatus', this.formatJobStatus);
    Vue.filter('colorJobStatus', this.colorJobStatus);
    this.loadData();
  },
  destroyed() {
    this.$root.unsubscribe("job", this.updateJob);
  },
  watch: {
    '$route': 'loadData',
    'sortBy': 'saveLocalSettings',
    'sortDesc': 'saveLocalSettings',
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
        this.$root.populateUserDetails(this.jobs[i], "userId", "owner");
      }
    },
    saveLocalSettings() {
      localStorage['settings.jobs.sortBy'] = this.sortBy;
      localStorage['settings.jobs.sortDesc'] = this.sortDesc;
      localStorage['settings.jobs.itemsPerPage'] = this.itemsPerPage;
    },
    loadLocalSettings() {
      if (localStorage['settings.jobs.sortBy']) {
        this.sortBy = localStorage['settings.jobs.sortBy'];
        this.sortDesc = localStorage['settings.jobs.sortDesc'] == "true";
        this.itemsPerPage = parseInt(localStorage['settings.jobs.itemsPerPage']);
      }
      this.form.sensorId = localStorage['settings.jobs.addJobForm.sensorId'];
      this.form.importId = localStorage['settings.jobs.addJobForm.importId'];
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
            this.$set(this.jobs, i, job);
          }
          break;
        }
      }
    },
    submitAddJob(event) {
      this.addJob(this.form.sensorId, this.form.importId, this.form.srcIp, this.form.srcPort, this.form.dstIp, this.form.dstPort, this.form.beginTime, this.form.endTime);
      this.dialog = false;
      this.saveAddJobForm();
    },
    saveAddJobForm() {
      if (this.form.sensorId) localStorage['settings.jobs.addJobForm.sensorId'] = this.form.sensorId;
      if (this.form.importId) localStorage['settings.jobs.addJobForm.importId'] = this.form.importId;
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
      this.form.srcIp = null;
      this.form.srcPort = null;
      this.form.dstIp = null;
      this.form.dstPort = null;
      this.form.beginTime = null;
      this.form.endTime = null;
      localStorage.removeItem('settings.jobs.addJobForm.sensorId');
      localStorage.removeItem('settings.jobs.addJobForm.importId');
      localStorage.removeItem('settings.jobs.addJobForm.srcIp');
      localStorage.removeItem('settings.jobs.addJobForm.srcPort');
      localStorage.removeItem('settings.jobs.addJobForm.dstIp');
      localStorage.removeItem('settings.jobs.addJobForm.dstPort');
      localStorage.removeItem('settings.jobs.addJobForm.beginTime');
      localStorage.removeItem('settings.jobs.addJobForm.endTime');
    },
    async addJob(sensorId, importId, srcIp, srcPort, dstIp, dstPort, beginTime, endTime) {
      try {
        if (!sensorId) {
          this.$root.showError(this.i18n.sensorIdRequired);
        } else {
          const beginDate = moment(beginTime);
          const endDate = moment(endTime);
          const response = await this.$root.papi.post('job/', {
            nodeId: sensorId,
            filter: {
              importId: importId,
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
    }
  }
}});
