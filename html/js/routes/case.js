// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

const MAX_TIMEOUT_ATTEMPTS=20;

routes.push({ path: '/case/:id', name: 'case', component: {
  template: '#page-case',
  data() { return {
    i18n: this.$root.i18n,
    caseObj: {},
    associationsLoading: false,
    associations: {
      comments: [],
      artifacts: [],
      events: [],
      tasks: [],
      history: []
    },
    associatedTable: {
      comments: {
        sortBy: 'createTime',
        sortDesc: false,
        search: '',
        headers: [
          { text: this.$root.i18n.username, value: 'owner' },
          { text: this.$root.i18n.dateCreated, value: 'createTime' },
          { text: this.$root.i18n.dateModified, value: 'updateTime' },
          { text: this.$root.i18n.commentDescription, value: 'description' },
        ],
        itemsPerPage: 10,
        footerProps: { 'items-per-page-options': [10,50,250,1000] },
        count: 500,
        expanded: [],
        loading: false,
      },
      artifacts: {
        sortBy: 'createTime',
        sortDesc: false,
        search: '',
        headers: [
          { text: this.$root.i18n.dateCreated, value: 'createTime' },
          { text: this.$root.i18n.dateModified, value: 'updateTime' },
          { text: this.$root.i18n.artifactType, value: 'artifactType' },
          { text: this.$root.i18n.value, value: 'value' },
        ],
        itemsPerPage: 10,
        footerProps: { 'items-per-page-options': [10,50,250,1000] },
        count: 500,
        expanded: [],
        loading: false,
      },
      events: {
        sortBy: 'fields.timestamp',
        sortDesc: false,
        search: '',
        headers: [
          { text: this.$root.i18n.actions },
          { text: this.$root.i18n.timestamp, value: 'fields.timestamp' },
          { text: this.$root.i18n.category, value: 'fields["event.category"]' },
          { text: this.$root.i18n.dataset, value: 'fields["event.dataset"]' },
          { text: this.$root.i18n.message, value: 'fields.message' },
        ],
        itemsPerPage: 10,
        footerProps: { 'items-per-page-options': [10,50,250,1000] },
        count: 500,
        expanded: [],
        loading: false,
      },
      tasks: {
        sortBy: 'order',
        sortDesc: false,
        search: '',
        headers: [
          { text: this.$root.i18n.order, value: 'order' },
          { text: this.$root.i18n.summary, value: 'summary' },
        ],
        itemsPerPage: 10,
        footerProps: { 'items-per-page-options': [10,50,250,1000] },
        count: 500,
        expanded: [],
        loading: false,
      },
      history: {
        sortBy: 'updateTime',
        sortDesc: false,
        search: '',
        headers: [
          { text: this.$root.i18n.username, value: 'owner' },
          { text: this.$root.i18n.time, value: 'updateTime' },
          { text: this.$root.i18n.kind, value: 'kind' },
          { text: this.$root.i18n.operation, value: 'operation' },
        ],
        itemsPerPage: 10,
        footerProps: { 'items-per-page-options': [10,50,250,1000] },
        count: 500,
        expanded: [],
        loading: false,
      },
    },
    userList: [],
    expanded: [0, 1],
    associatedForms: {
      comments: {},
      artifacts: {},
    },
    editForm: {},
    mruCaseLimit: 5,
    mruCases: [],
    presets: {},
    rules: {
      required: value => (value && value.length > 0) || this.$root.i18n.required,
      number: value => (! isNaN(+value) && Number.isInteger(parseFloat(value))) || this.$root.i18n.required,
      shortLengthLimit: value => (value.length < 100) || this.$root.i18n.required,
      longLengthLimit: value => (encodeURI(value).split(/%..|./).length - 1 < 10000000) || this.$root.i18n.required,
      fileSizeLimit: value => (value == null || value.size < this.maxUploadSizeBytes) || this.$root.i18n.fileTooLarge.replace("{maxUploadSizeBytes}", this.$root.formatCount(this.maxUploadSizeBytes)),
      fileNotEmpty: value => (value == null || value.size > 0) || this.$root.i18n.fileEmpty,
    },
    attachment: null,
    maxUploadSizeBytes: 26214400,
  }},
  computed: {
  },
  created() {   
  },
  async mounted() {
    this.$root.loadParameters('case', this.initCase);
    await this.loadData();
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
      if (params["maxUploadSizeBytes"]) {
        this.maxUploadSizeBytes = params.maxUploadSizeBytes;
      }
      this.loadLocalSettings();
      this.resetForm('artifacts');
      this.resetForm('comments');
    },
    getAttachmentHelp() {
      return this.i18n.attachmentHelp.replace("{maxUploadSizeBytes}", this.$root.formatCount(this.maxUploadSizeBytes));
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
    async loadAssociations() {
      this.associationsLoading = true;

      this.associations["comments"] = [];
      this.loadAssociation('comments');

      this.associations["tasks"] = [];
      this.loadAssociation('tasks');

      this.associations["artifacts"] = [];
      this.loadAssociation('artifacts', "/evidence");

      this.associations["events"] = [];
      this.loadAssociation('events');

      this.associations["history"] = [];
      this.loadAssociation('history');

      this.associationsLoading = false;
    },
    async loadAssociation(dataType, extraPath = "") {
      try {
        const route = this;
        const response = await this.$root.papi.get('case/' + dataType + extraPath, { params: {
          id: route.$route.params.id,
          offset: route.associations[dataType].length,
          count: route.associatedTable[dataType].count,
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
    expandRow(association, row) {
      const expanded = this.associatedTable[association].expanded;
      for (var i = 0; i < expanded.length; i++) {
        if (expanded[i].id == row.id) {
          expanded.splice(i, 1);
          return;
        }
      }
      expanded.push(row);
    },    
    withDefault(value, deflt) {
      if (value == null || value == undefined || value == "") {
        value = deflt;
      }
      return value;
    },
    selectList(field, value) {
      const presets = this.getPresets(field);
      return this.isPresetCustomEnabled(field) && value
        ? presets.concat(value)
        : presets
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
      await this.$root.populateUserDetails(caseObj, "userId", "owner", this.i18n.unknown);
      await this.$root.populateUserDetails(caseObj, "assigneeId", "assignee", this.i18n.unassigned);
      this.addMRUCaseObj(caseObj);
      this.caseObj = caseObj;
    },

    prepareModifyForm(obj) {
      const form = {...obj};
      let val = this.editForm.val;
      if (typeof this.editForm.orig == 'number' &&
          typeof val == 'string') {
        val = parseInt(val, 10);
      }
      
      if (form[this.editForm.field] == val) return false;

      form[this.editForm.field] = val;
      delete form.kind;
      delete form.operation;
      return form;
    },

    async modifyCase() {
      let success = false;
      this.$root.startLoading();
      try {
        const form = this.prepareModifyForm(this.caseObj);
        if (form) {
          const response = await this.$root.papi.put('case/', JSON.stringify(form));
          if (response.data) {
            this.stopEdit();
            await this.updateCaseDetails(response.data);
            success = true;
          }
        } else {
          success = true; // no change detected, allow edit mode to exit
        }
      } catch (error) {
        if (error.response != undefined && error.response.status == 404) {
          this.$root.showError(this.i18n.notFound);
        } else {
          this.$root.showError(error);
        }
      }
      this.$root.stopLoading();
      return success;
    },
    async addAssociation(association, additionalProps) {
      if (this.$refs && this.$refs[association] && !this.$refs[association].validate()) {
        return;
      }
      this.$root.startLoading();
      try {
        const form = this.associatedForms[association];
        if (additionalProps) {
          Object.assign(form, additionalProps);
        }
        form.caseId = this.caseObj.id;
        form.id = '';

        let config = undefined;
        let data = JSON.stringify(form);
        if (this.attachment) {
          let jsonData = data;
          data = new FormData();
          data.append("json", jsonData);
          data.append("attachment", this.attachment);
          headers = { 'Content-Type': 'multipart/form-data; boundary=' + data._boundary }
          config = { 'headers': headers };
        }
        const response = await this.$root.papi.post('case/' + association, data, config);
        if (response.data) {
          await this.$root.populateUserDetails(response.data, "userId", "owner");
          this.associations[association].push(response.data);
          this.resetForm(association);
        }
      } catch (error) {
        this.$root.showError(error);
      }
      // always clear file, even if failure. Otherwise there's a risk that the file could be sent on 
      // all subsequent artifacts.
      this.attachment = null;
      this.$root.stopLoading();
    },
    async modifyAssociation(association, obj) {
      let success = false;
      let idx = this.associations[association].findIndex((x) =>  x.id === obj.id)
      if (idx > -1) {
        this.$root.startLoading();
        try {
          const form = this.prepareModifyForm(obj);
          if (form) {
            const response = await this.$root.papi.put('case/' + association, JSON.stringify(form));
            if (response.data) {
              await this.$root.populateUserDetails(response.data, "userId", "owner");
              Vue.set(this.associations[association], idx, response.data);
              success = true;
            }
          } else {
            success = true; // no change detected, allow edit mode to exit
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
      return success;
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

    isEdit(roId) {
      return this.editForm.roId == roId;
    },
    startEdit(focusId, val, roId, field, callback, callbackArgs, isMultiline) {
      if (this.editForm.focusId == focusId) {
        // We're already editing this field.
        return;
      }
      if (this.stopEdit(true)) {
        this.editForm.focusId = focusId;
        this.editForm.orig = val;
        this.editForm.val = val;
        this.editForm.roId = roId;
        this.editForm.field = field;
        this.editForm.callback = callback;
        this.editForm.callbackArgs = callbackArgs;
        this.editForm.isMultiline = isMultiline;
        window.addEventListener("keyup", this.onEditKeyUp);
        const route = this;
        this.$nextTick(() => {
          let element = document.getElementById(this.editForm.focusId);
          if (element) {
            element.focus();
          }
        });
      }
    },
    async stopEdit(save = false) {
      let okToClear = true;
      if (save && this.editForm && this.editForm.callback) {
        if (this.editForm.valid) {
          if (this.editForm.callbackArgs) {
            okToClear = await this.editForm.callback(...this.editForm.callbackArgs);
          } else {
            okToClear = await this.editForm.callback();
          }
        } else {
          okToClear = false;
        }
      }
      if (okToClear) {
        this.editForm = { valid: true };
        window.removeEventListener("keyup", this.onEditKeyUp);
      }
      return okToClear;
    },
    onEditKeyUp(event) {
      switch (event.which) {
        case 27: this.stopEdit(); break;
        case 13: if (!this.editForm.isMultiline) this.stopEdit(true); break;
      }
    },
    resetForm(ref) {
      const form = { valid: false };
      switch (ref) {
        case "artifacts": 
          form.tlp = this.getDefaultPreset('tlp');
          form.artifactType = this.getDefaultPreset('artifactType');
          break;
      }
      Vue.set(this.associatedForms, ref, form)
    },
    isEdited(association) {
      const createTime = Date.parse(association.createTime);
      const updateTime = Date.parse(association.updateTime);
      return Math.abs(updateTime - createTime) >= 1000;
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

