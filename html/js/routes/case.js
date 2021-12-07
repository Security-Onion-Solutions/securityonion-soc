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
    mainForms: {
      info: {
        valid: false,
        title: null,
        assigneeId: null,
        status: null
      },
      details: {
        valid: false,
        id: null,
        description: null,
        severity: null,
        priority: null,
        tags: null,
        tlp: null,
        pap: null,
        category: null
      }
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
    editFields: [],
    mruCaseLimit: 5,
    mruCases: [],
    rules: {
      required: value => (!!value) || this.$root.i18n.required,
    },
  }},
  computed: {
    severityList() {
      return [
        { text: 'High', value: 0 },
        { text: 'Medium', value: 1 },
        { text: 'Low', value: 2 },
        { text: 'Extra Low', value: 3}
      ]
    },
    severityString() {
      return typeof(this.mainForms.details.severity) == Number
        ? this.severityList.find(el => el.value == this.mainForms.details.severity).text
        : this.mainForms.details.severity
    }, 
    statusList() {
      const statuses = [
        'new',
        'in progress',
        'closed'
      ]
      return statuses.map((value) => {
        return {
          text: value.split(' ').map(word => word.charAt(0).toLocaleUpperCase() + word.substring(1)).join(' '),
          value: value
        }
      })
    }
  },
  created() {
  },
  mounted() {
    this.loadData();
    this.$root.loadParameters('cases', this.initCase);
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
      this.mainForms.details.id = caseObj.id;
      this.mainForms.info.title = caseObj.title;
      this.mainForms.details.description = caseObj.description;
      this.mainForms.details.severity = caseObj.severity;
      this.mainForms.details.priority = caseObj.priority;
      this.mainForms.info.status = caseObj.status;
      this.mainForms.details.tags = caseObj.tags ? caseObj.tags.join(", ") : "";
      this.mainForms.details.tlp = caseObj.tlp;
      this.mainForms.details.pap = caseObj.pap;
      this.mainForms.details.category = caseObj.category;
      this.mainForms.info.assigneeId = caseObj.assigneeId;
      this.$root.populateUserDetails(caseObj, "userId", "owner");
      this.$root.populateUserDetails(caseObj, "assigneeId", "assignee");
      this.addMRUCaseObj(caseObj);
      this.caseObj = caseObj;
    },
    async modifyCase() {
      this.$root.startLoading();
      try {
        // Convert priority and severity to ints
        this.mainForms.details.severity = parseInt(this.mainForms.details.severity, 10);
        this.mainForms.details.severity = this.severityString;
        this.mainForms.details.priority = parseInt(this.mainForms.details.priority, 10);
        const formattedTags = this.mainForms.details.tags;
        if (this.mainForms.details.tags) {
          this.mainForms.details.tags = this.mainForms.details.tags.split(",").map(tag => {
            return tag.trim();
          });
        } else { this.mainForms.details.tags = []; }
        const caseInfo = {
          ...this.mainForms.info,
          ...this.mainForms.details
        };
        const json = JSON.stringify(caseInfo);
        this.mainForms.details.tags = formattedTags;
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
    isEdit(id) {
      return this.editFields.find(item => item == id) != null
    },
    async toggleEdit(id) {
      if (this.editFields.find(item => item == id) == null) {
        this.editFields.push(id)
      } else {
        this.editFields = this.editFields.filter(item => item != id)
        await this.modifyCase()
      }
    },
    saveLocalSettings() {
      localStorage['settings.case.mruCases'] = JSON.stringify(this.mruCases);
    },
    loadLocalSettings() {
      if (localStorage['settings.case.mruCases']) this.mruCases = JSON.parse(localStorage['settings.case.mruCases']);
    },
  }
}});
