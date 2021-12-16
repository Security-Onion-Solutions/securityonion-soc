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
    userList: [],
    collapsed: [
      'case-details'
    ],
    collapsible: {},
    mainForm: {
      valid: false,
      title: null,
      assigneeId: null,
      status: null,
      id: null,
      description: null,
      severity: null,
      priority: null,
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
    editField: {},
    mruCaseLimit: 5,
    mruCases: [],
    presets: {},
    rules: {
      required: value => (value != [] && value != "") || this.$root.i18n.required,
      number: value => (! isNaN(+value) && Number.isInteger(parseFloat(value))) || this.$root.i18n.required,
      shortLengthLimit: value => (value.length < 100) || this.$root.i18n.required,
      longLengthLimit: value => (encodeURI(value).split(/%..|./).length - 1 < 10000000) || this.$root.i18n.required,
    },
  }},
  computed: {
  },
  created() {
  },
  async mounted() {
    await this.loadData();
    this.$root.loadParameters('case', this.initCase);
    this.updateCollapsible('case-description'); // Update collapsible state for description manually
  },
  destroyed() {
    this.$root.unsubscribe("case", this.updateCase);
  },
  watch: {
    '$route': 'loadData',
  },
  methods: {
    selectList(field) {
      const presets = this.getPresets(field)
      return this.isPresetCustomEnabled(field) && this.mainForm[field] !== null 
        ? presets.concat(this.mainForm[field]) 
        : presets
    },
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
      this.loadAssociation('artifacts', "/evidence");

      this.associations["events"] = [];
      this.loadAssociation('events');

      this.associations["history"] = [];
      this.loadAssociation('history');

      this.associationsLoading = false;
    },
    async loadAssociation(dataType, extraPath = "") {
      try {
        const response = await this.$root.papi.get('case/' + dataType + extraPath, { params: {
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
        this.userList = await this.$root.getUsers();
        await this.updateCaseDetails(response.data);
        await this.loadAssociations();
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
    async updateCaseDetails(caseObj) {
      this.mainForm.id = caseObj.id;
      this.mainForm.title = caseObj.title;
      this.mainForm.description = caseObj.description;
      this.mainForm.severity = caseObj.severity;
      this.mainForm.priority = caseObj.priority;
      this.mainForm.status = caseObj.status;
      this.mainForm.tags = caseObj.tags;
      this.mainForm.tlp = caseObj.tlp;
      this.mainForm.pap = caseObj.pap;
      this.mainForm.category = caseObj.category;
      this.mainForm.assigneeId = caseObj.assigneeId;
      await this.$root.populateUserDetails(caseObj, "userId", "owner");
      await this.$root.populateUserDetails(caseObj, "assigneeId", "assignee");
      this.addMRUCaseObj(caseObj);
      this.caseObj = caseObj;
    },
    async modifyCase(keyStr = null) {
      this.$root.startLoading();
      try {
        let jsonObj = {...this.mainForm };
        if (keyStr !== null) {
          jsonObj[keyStr] = this.editField.val;
        }
        // Convert priority to int
        jsonObj.priority = parseInt(jsonObj.priority, 10);
        // if (jsonObj.tags) {
        //   jsonObj.tags = jsonObj.tags.split(",").map(tag => tag.trim());
        // } else { jsonObj.tags = []; }
        const json = JSON.stringify(jsonObj);
        const response = await this.$root.papi.put('case/', json);
        if (response.data) {
          this.stopEdit();
          await this.updateCaseDetails(response.data);
        }
      } catch (error) {
        if (error.response != undefined && error.response.status == 404) {
          this.$root.showError(this.i18n.notFound);
        } else {
          this.$root.showError(error);
        }
      }
      // Also update description collapsible bool when the description has been changed
      if (keyStr === 'description') {
        this.updateCollapsible('case-description');
      }
      this.$root.stopLoading();
    },
    async addAssociation(association) {
      this.$root.startLoading();
      try {
        const response = await this.$root.papi.post('case/' + association, JSON.stringify(this.associatedForms[association]));
        if (response.data) {
          await this.$root.populateUserDetails(response.data, "userId", "owner");
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
            await this.$root.populateUserDetails(response.data, "userId", "owner");
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
          await this.$root.papi.delete('case/' + association, { params: {
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
    isEdit(id) {
      return this.editField.id === id;
    },
    startEdit(val, id) {
      this.editField = {
        val,
        id
      };
    },
    stopEdit() {
      this.editField = {}
    },
    async saveEdit(keyStr) {
      if (this.mainForm[keyStr] === this.editField.val) {
        this.stopEdit();
      } else {
        await this.modifyCase(keyStr);
      }
    },
    saveLocalSettings() {
      localStorage['settings.case.mruCases'] = JSON.stringify(this.mruCases);
    },
    loadLocalSettings() {
      if (localStorage['settings.case.mruCases']) this.mruCases = JSON.parse(localStorage['settings.case.mruCases']);
    },
    updateCollapsible(id) {
      if (! Object.keys(this.collapsible).includes(id)) {
        this.collapsible[id] = false
      }
      this.$nextTick(() => {
        let element = document.getElementById(id);
        let retVal = element.offsetHeight < element.scrollHeight || element.offsetWidth < element.scrollWidth;
        if (retVal && !this.collapsible[id]) {
          this.collapsible[id] = true
        } else if (!retVal && this.collapsible[id]) {
          this.collapsible[id] = false
        }
      })
    },
    isCollapsible(item) {
      if ((Object.keys(this.collapsible).indexOf(item) === -1)) {
        this.updateCollapsible(item)
      }
      return (this.collapsible[item] === true)
    },
    toggleCollapse(item) {
      if (!this.isCollapsed(item)) {
        this.collapsed.push(item);
      } else {
        this.collapsed.splice(this.collapsed.indexOf(item), 1);
      }
    },
    isCollapsed(item) {
      return (this.collapsed.indexOf(item) !== -1);
    }
  }
}});

