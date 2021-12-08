// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

routes.push({ path: '/case/:id', name: 'case', component: {
  template: '#page-case',
  data() { return {
    i18n: this.$root.i18n,
    caseObj: {},
    associationsLoading: false,
    search: '',
    associations: {
      comments: [],
      artifacts: [],
      events: [],
      tasks: [],
      history: []
    },
    headers: {
      comments: [],
      artifacts: [],
      events: [],
      tasks: [],
      history: []
    },
    sortBy: 'number',
    sortDesc: false,
    itemsPerPage: 10,
    footerProps: { 'items-per-page-options': [10,50,250,1000] },
    count: 500,
    form: {
      valid: false,
      id: null,
      title: null,
      description: null,
      status: null,
      severity: null,
      priority: null,
      assigneeId: null,
      tags: null,
      tlp: null,
      pap: null,
      category: null
    },
    associatedForms: {
      comments: {
        id: "",
        caseId: "",
        description: "",
        valid: false
      },
      tasks: {
        id: "",
        caseId: "",
        description: "",
        status: "",
        valid: false
      },
      artifacts: {
        id: "",
        caseId: "",
        description: "",
        valid: false
      }
    },
    mruCaseLimit: 5,
    mruCases: [],
    presets: {},
    rules: {
      required: value => (!!value) || this.$root.i18n.required,
    },
  }},
  created() {
  },
  mounted() {
    this.loadData();
    this.$root.loadParameters('case', this.initCase);
  },
  destroyed() {
    this.$root.unsubscribe("case", this.updateCase);
  },
  watch: {
    '$route': 'loadData',
  },
  methods: {
    initCase(params) {
      this.params = params;
      this.mruCaseLimit = params["mostRecentlyUsedLimit"];
      this.presets = params["presets"];
      this.loadLocalSettings();
    },
    async loadAssociations() {
      this.associationsLoading = true;

      this.associations["comments"] = [];
      this.associatedForms["comments"].caseId = this.caseObj.id;
      this.loadAssociation('comments');

      this.associations["tasks"] = [];
      this.associatedForms["tasks"].caseId = this.caseObj.id;
      this.loadAssociation('tasks');

      this.associations["artifacts"] = [];
      this.associatedForms["artifacts"].caseId = this.caseObj.id;
      this.loadAssociation('artifacts');

      this.associations["events"] = [];
      this.loadAssociation('events');

      this.associations["history"] = [];
      this.loadAssociation('history');

      this.associationsLoading = false;
    },
    async loadAssociation(dataType) {
      try {
        const response = await this.$root.papi.get('case/' + dataType, { params: {
          id: this.$route.params.id,
          offset: this.associations[dataType].length,
          count: this.count,
        }});
        if (response && response.data) {
          for (var idx = 0; idx < response.data.length; idx++) {
            const obj = response.data[idx];
            await this.$root.populateUserDetails(obj, "userId", "owner");
            this.associations[dataType].push(obj);
          }
        }
      } catch (error) {
        this.$root.showError(error);
      }
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
    addMRUCaseObj(caseObj) {
      if (caseObj) {
        for (var idx = 0; idx < this.mruCases.length; idx++) {
          const cur = this.mruCases[idx];
          if (cur.id == caseObj.id) {
            this.mruCases.splice(idx, 1);
            break;
          }
        }
        this.mruCases.unshift(caseObj);
        while (this.mruCases.length > this.mruCaseLimit) {
          this.mruCases.pop();
        }
        this.saveLocalSettings();
      }
    },
    async loadData() {
      this.$root.startLoading();

      try {
        const response = await this.$root.papi.get('case/', { params: {
            id: this.$route.params.id
        }});
        this.updateCaseDetails(response.data);
        this.loadAssociations();
      } catch (error) {
        if (error.response != undefined && error.response.status == 404) {
          this.$root.showError(this.i18n.notFound);
        } else {
          this.$root.showError(error);
        }
      }
      this.$root.stopLoading();
      this.$root.subscribe("case", this.updateCase);
    },
    updateCaseDetails(caseObj) {
      this.form.id = caseObj.id;
      this.form.title = caseObj.title;
      this.form.description = caseObj.description;
      this.form.severity = caseObj.severity;
      this.form.priority = caseObj.priority;
      this.form.status = caseObj.status;
      this.form.tags = caseObj.tags ? caseObj.tags.join(", ") : "";
      this.form.tlp = caseObj.tlp;
      this.form.pap = caseObj.pap;
      this.form.category = caseObj.category;
      this.form.assigneeId = caseObj.assigneeId;
      this.$root.populateUserDetails(caseObj, "userId", "owner");
      this.$root.populateUserDetails(caseObj, "assigneeId", "assignee");
      this.addMRUCaseObj(caseObj);
      this.caseObj = caseObj;
    },    
    async modifyCase() {
      this.$root.startLoading();
      try {
        // Convert priority and severity to ints
        this.form.severity = parseInt(this.form.severity, 10);
        this.form.priority = parseInt(this.form.priority, 10);
        const formattedTags = this.form.tags;
        if (this.form.tags) {
          this.form.tags = this.form.tags.split(",").map(tag => {
            return tag.trim();
          });
        } else {
          this.form.tags = [];
        }
        const json = JSON.stringify(this.form);
        this.form.tags = formattedTags;
        const response = await this.$root.papi.put('case/', json);
        if (response.data) {
          this.updateCaseDetails(response.data);
        }
      } catch (error) {
        if (error.response != undefined && error.response.status == 404) {
          this.$root.showError(this.i18n.notFound);
        } else {
          this.$root.showError(error);
        }
      }
      this.$root.stopLoading();
    },
    async addAssociation(association) {
      this.$root.startLoading();
      try {
        const response = await this.$root.papi.post('case/' + association, JSON.stringify(this.associatedForms[association]));
        if (response.data) {
          this.$root.populateUserDetails(response.data, "userId", "owner");
          this.associations[association].push(response.data);
        }
      } catch (error) {
        this.$root.showError(error);
      }
      this.$root.stopLoading();
    },
    async modifyAssociation(association) {
      var idx = -1;
      for (var i = 0; i < this.associations[association].length; i++) {
        if (this.associations[association][i].id == this.associatedForms[association].id) {
          idx = i;
          break;
        }
      }
      if (idx > -1) {
        this.$root.startLoading();
        try {
          const response = await this.$root.papi.put('case/' + association, JSON.stringify(this.associatedForms[association]));
          if (response.data) {
            this.$root.populateUserDetails(response.data, "userId", "owner");
            Vue.set(this.associations[association], idx, response.data);
          }
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
    async deleteAssociation(association, obj) {
      const idx = this.associations[association].indexOf(obj);
      if (idx > -1) {
        this.$root.startLoading();
        try {
          const response = await this.$root.papi.delete('case/' + association, { params: {
            id: obj.id
          }});
          this.associations[association].splice(idx, 1);
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
    editComment(comment) {
      this.associatedForms['comments'].id = comment.id;
      this.associatedForms['comments'].description = comment.description;
    },
    cancelComment() {
      this.associatedForms['comments'].id = "";
      this.associatedForms['comments'].description = "";
    },
    updateCase(caseObj) {
      // No-op until we can detect if the user has made any changes to the form. We don't
      // want to wipe out a long description they might be working on typing.

      // if (!caseObj || caseObj.id != this.caseObj.id) return;
      // this.updateCaseDetails(caseObj)
      // this.loadAssociations();
    },
    saveLocalSettings() {
      localStorage['settings.case.mruCases'] = JSON.stringify(this.mruCases);
    },
    loadLocalSettings() {
      if (localStorage['settings.case.mruCases']) this.mruCases = JSON.parse(localStorage['settings.case.mruCases']);
    },
  }
}});

