// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

const MAX_TIMEOUT_ATTEMPTS=20;
const ipRegex = /^[0-9a-fA-F:]*([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F:]*$|^(\d{1,3}\.){3}\d{1,3}$/;
const fqdnRegex = /(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$)/;
const domainRegex = /^(xn\-\-)?([a-z0-9\-]{1,61}|[a-z0-9\-]{1,30})\.[a-z]{2,}$/;
const urlRegex = /^[a-z]+:\/\//;
const filenameRegex = /(\/)?[\w,\s-]+\.[A-Za-z]{3}$/;
const uriPathRegex = /^\/[\w,\s-]/;
const hashRegex = /^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$|^[0-9a-fA-F]{128}$/;
const internalPrefix = "___";

routes.push({ path: '/case/:id', name: 'case', component: {
  template: '#page-case',
  data() { return {
    i18n: this.$root.i18n,
    caseObj: {},
    associations: {
      comments: [],
      attachments: [],
      evidence: [],
      events: [],
      tasks: [],
      history: []
    },
    associatedTable: {
      comments: {
        showAll: false,
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
      attachments: {
        sortBy: 'createTime',
        sortDesc: false,
        search: '',
        headers: [
          { text: this.$root.i18n.actions, width: '10.0em' },
          { text: this.$root.i18n.dateCreated, value: 'createTime' },
          { text: this.$root.i18n.dateModified, value: 'updateTime' },
          { text: this.$root.i18n.filename, value: 'value' },
        ],
        itemsPerPage: 10,
        footerProps: { 'items-per-page-options': [10,50,250,1000] },
        count: 500,
        expanded: [],
        loading: false,
      },
      evidence: {
        sortBy: 'createTime',
        sortDesc: false,
        search: '',
        headers: [
          { text: this.$root.i18n.actions, width: '10.0em' },
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
        sortBy: 'fields.soc_timestamp',
        sortDesc: false,
        search: '',
        headers: [
          { text: this.$root.i18n.actions, width: '10.0em' },
          { text: this.$root.i18n.timestamp, value: 'fields.soc_timestamp' },
          { text: this.$root.i18n.id, value: 'fields.soc_id' },
          { text: this.$root.i18n.category, value: 'fields.' + internalPrefix + 'event_category' },
          { text: this.$root.i18n.module, value: 'fields.' + internalPrefix + 'event_module' },
          { text: this.$root.i18n.dataset, value: 'fields.' + internalPrefix + 'event_dataset' },
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
          { text: this.$root.i18n.actions, width: '10.0em' },
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
      attachments: {},
      evidence: {},
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
      fileRequired: value => (value != null) || this.$root.i18n.required,
    },
    attachment: null,
    maxUploadSizeBytes: 26214400,
    addingAssociation: null,
    activeTab: null,
    renderAbbreviatedCount: 30,
    analyzerNodeId: null,
    analyzeJobs: {},
  }},
  computed: {
  },
  created() {   
  },
  async mounted() {
    this.$root.loadParameters('case', this.initCase);
    if (this.$route.params.id == 'create') {
      await this.createCase();
    } else {
      await this.loadData();
    }
    this.$root.subscribe("job", this.updateJob);
  },
  beforeDestroy() {
    this.$root.setSubtitle("");
  },  
  destroyed() {
    this.$root.unsubscribe("case", this.updateCase);
    this.$root.unsubscribe("job", this.updateJob);
  },
  watch: {
    '$route': 'loadData',
  },
  methods: {
    initCase(params) {
      this.params = params;
      this.mruCaseLimit = params["mostRecentlyUsedLimit"];
      this.renderAbbreviatedCount = params["renderAbbreviatedCount"];
      this.presets = params["presets"];
      if (params["maxUploadSizeBytes"]) {
        this.maxUploadSizeBytes = params.maxUploadSizeBytes;
      }
      this.analyzerNodeId = params["analyzerNodeId"];
      this.loadLocalSettings();
      this.resetForm('attachments');
      this.resetForm('evidence');
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
    mapAssociatedPath(association, concatPath = false) {
      var path = association;
      switch (association) {
        case 'attachments':
          path = "artifacts";
          if (concatPath) {
            path += "/" + association
          }
          break;
        case 'evidence':
          path = "artifacts";
          if (concatPath) {
            path += "/" + association
          }
          break;
      }
      return path;
    },
    mapAssociatedKind(obj) {
      var name = "";
      if (obj) {
        switch (obj.kind) {
          case 'artifact':
            name = obj.groupType;
            break;
          default:
            name = obj.kind;
        }
      }
      return name;
    },
    loadAssociations() {
      this.reloadAssociation("comments");
      this.reloadAssociation("tasks");
      this.reloadAssociation("attachments");
      this.reloadAssociation("evidence");
      this.reloadAssociation("events");
      this.reloadAssociation("history");
    },
    async reloadAssociation(association, showLoadingIndicator = false) {
      if (showLoadingIndicator) this.$root.startLoading();
      this.associations[association] = [];
      await this.loadAssociation(association);
      if (showLoadingIndicator) this.$root.stopLoading();
    },
    async loadAssociation(association) {
      try {
        const route = this;
        const response = await this.$root.papi.get('case/' + this.mapAssociatedPath(association, true), { params: {
          id: route.$route.params.id,
          offset: route.associations[association].length,
          count: route.associatedTable[association].count,
        }});
        if (response && response.data) {
          for (var idx = 0; idx < response.data.length; idx++) {
            const obj = response.data[idx];

            // Don't await the user details -- takes too long for the task scheduler to
            // complete all these futures when looping across hundreds of records. Let
            // the UI update as they finish, for a better user experience.
            this.$root.populateUserDetails(obj, "userId", "owner");
            if (obj.assigneeId) {
              this.$root.populateUserDetails(obj, "assigneeId", "assignee");
            }
            obj.kind = this.$root.localizeMessage(this.mapAssociatedKind(obj));
            obj.operation = this.$root.localizeMessage(obj.operation);
            this.associations[association].push(obj);
            this.duplicateEventFields(obj);
          }
        }
      } catch (error) {
        this.$root.showError(error);
      }
    },
    duplicateEventFields(obj) {
      // Vuetify Data Tables has a flaw in that it cannot resolve object properties
      // for the purpose of filtering, when the property name contains a dot (.)
      // character. So our obj.fields["event.module"] won't work with filtering.
      // To resolve this, we have to duplicate the field name into one with an 
      // underscore instead of a dot. Fortunately these three event fields are
      // small so it's not going cost much overhead.
      if (obj && obj.fields) {
        ["event.module", "event.category", "event.dataset"].forEach( field => {
          if (obj.fields[field]) {
            obj.fields[internalPrefix + field.replace(".", "_")] = obj.fields[field];
          }
        });
      }
    },
    getUnrenderedCount(association) {
      var hiddenCount = 0;
      if (!this.associatedTable[association].showAll && this.renderAbbreviatedCount) {
        const count = this.associations[association] ? this.associations[association].length : 0;
        if (count > this.renderAbbreviatedCount) {
          hiddenCount = count - this.renderAbbreviatedCount;
        }
      }
      return hiddenCount;
    },
    renderAllAssociations(association) {
      this.associatedTable[association].showAll = true;
    },
    shouldRenderShowAll(association, index) {
      var render = false;
      if (!this.associatedTable[association].showAll && this.renderAbbreviatedCount) {
        const count = this.associations[association] ? this.associations[association].length : 0;
        const lowerCutoff = Math.floor(this.renderAbbreviatedCount / 2);
        if (count - this.renderAbbreviatedCount > lowerCutoff) {
          if (index == lowerCutoff-1) {
            render = true;
          }
        }
      }
      return render;
    },
    shouldRenderAssociationRecord(association, obj, index) {
      var render = true;
      if (!this.associatedTable[association].showAll && this.renderAbbreviatedCount) {      
        const count = this.associations[association] ? this.associations[association].length : 0;
        const lowerCutoff = Math.floor(this.renderAbbreviatedCount / 2);
        if (count - this.renderAbbreviatedCount > lowerCutoff) {
          const upperCutoff = count - lowerCutoff;
          if (index >= lowerCutoff && index < upperCutoff) {
            render = false;
          }
        }
      }
      return render;
    },
    isExpanded(association, row) {
      const expanded = this.associatedTable[association].expanded;
      for (var i = 0; i < expanded.length; i++) {
        if (expanded[i].id == row.id) {
          return true;
        }
      }
      return false;
    },
    async expandRow(association, row) {
      const expanded = this.associatedTable[association].expanded;
      for (var i = 0; i < expanded.length; i++) {
        if (expanded[i].id == row.id) {
          expanded.splice(i, 1);
          return;
        }
      }
      expanded.push(row);

      if (association == "evidence") {
        this.loadAnalyzeJobs(row.id);
      }
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
    async createCase() {
      this.$root.startLoading();
      try {
        const response = await this.$root.papi.post('case/', {
          title: this.i18n.caseDefaultTitle,
          description: this.i18n.caseDefaultDescription,
        });
        if (response && response.data && response.data.id) {
          this.$router.replace({ name: 'case', params: { id: response.data.id } });
        } else {
          this.$root.showError(i18n.createFailed);
        }
      }
      catch (error) {
        this.$root.showError(error);
      }
      this.$root.stopLoading();
    },
    async loadData() {
      this.$root.startLoading();

      try {
        const response = await this.$root.papi.get('case/', { params: {
            id: this.$route.params.id
        }});
        this.userList = await this.$root.getActiveUsers();
        await this.updateCaseDetails(response.data);
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
    async updateCaseDetails(caseObj) {
      await this.$root.populateUserDetails(caseObj, "userId", "owner", this.i18n.unknown);
      await this.$root.populateUserDetails(caseObj, "assigneeId", "assignee", this.i18n.unassigned);
      this.addMRUCaseObj(caseObj);
      this.$root.setSubtitle(this.i18n.case + " - " + caseObj.title); 
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
        if (form.value) {
          form.value = form.value.trim();
        }

        let response = undefined;
        let config = undefined;
        if (this.attachment && form.artifactType == 'file') {
          const data = new FormData();
          data.append("json", JSON.stringify(form));
          data.append("attachment", this.attachment);
          headers = { 'Content-Type': 'multipart/form-data; boundary=' + data._boundary }
          config = { 'headers': headers };
          response = await this.$root.papi.post('case/' + this.mapAssociatedPath(association), data, config);
        } else if (association == 'evidence' && this.isEvidenceBulkCapable() && form.bulk) {
          let added = 0;
          const combined = form.value;
          const values = combined.split("\n")
          for (var i = 0; i < values.length; i++) {
            const val = values[i];
            if (val.trim().length > 0) {
              form.value = val.trim();
              let data = JSON.stringify(form);
              response = await this.$root.papi.post('case/' + this.mapAssociatedPath(association), data, config);
              if (response && response.data) {
                await this.$root.populateUserDetails(response.data, "userId", "owner");
                this.associations[association].push(response.data);
                added++;
              }
              response = null;
            }
          }
          if (added > 0) {
            this.resetForm(association);
            this.$root.showTip(this.i18n.saveSuccess);
          }
        } else {
          let data = JSON.stringify(form);
          response = await this.$root.papi.post('case/' + this.mapAssociatedPath(association), data, config);
        }
        
        if (response && response.data) {
          await this.$root.populateUserDetails(response.data, "userId", "owner");
          this.associations[association].push(response.data);
          this.resetForm(association);
          this.$root.showTip(this.i18n.saveSuccess);
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
            const response = await this.$root.papi.put('case/' + this.mapAssociatedPath(association), JSON.stringify(form));
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
          await this.$root.papi.delete('case/' + this.mapAssociatedPath(association), { params: {
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
    async startEdit(focusId, val, roId, field, callback, callbackArgs, isMultiline) {
      if (this.editForm.focusId == focusId) {
        // We're already editing this field.
        return;
      }
      if (await this.stopEdit(true)) {
        this.editForm = { valid: true };
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
      switch (event.key) {
        case 'Escape': this.stopEdit(); break;
        case 'Enter': if (!this.editForm.isMultiline) this.stopEdit(true); break;
      }
    },
    getTlp() {
      var tlp = this.caseObj.tlp;
      if (!tlp) {
        tlp = this.getDefaultPreset('tlp');
      }
      return tlp;
    },
    isEvidenceBulkCapable() {
      return this.associatedForms['evidence'].artifactType != "file";
    },
    resetFormDefaults(form, ref) {
      switch (ref) {
        case "attachments": 
          form.tlp = this.getTlp();
          break;
        case "evidence": 
          form.tlp = this.getTlp();
          form.bulk = false;
          form.artifactType = this.getDefaultPreset('artifactType');
          break;
        case "comments":
          if (this.$refs && this.$refs[ref]) {
            this.$refs[ref].reset();
          }
          break;
      }      
    },
    resetForm(ref) {
      const form = { valid: false };
      this.attachment = null;
      this.resetFormDefaults(form, ref);
      this.addingAssociation = null;
      Vue.set(this.associatedForms, ref, form)
    },
    isEdited(association) {
      const createTime = Date.parse(association.createTime);
      const updateTime = Date.parse(association.updateTime);
      return Math.abs(updateTime - createTime) >= 1000;
    },
    enableAdding(association) {
      this.addingAssociation = association;
      this.resetFormDefaults(this.associatedForms[association], association);
    },
    isAdding(association) {
      return this.addingAssociation == association;
    },
    mapArtifactTypeFromValue(value) {
      var artifactType = null;
      if (ipRegex.test(value)) {
        artifactType = "ip";
      } else if (domainRegex.test(value)) {
        artifactType = "domain";
      } else if (fqdnRegex.test(value)) {
        artifactType = "fqdn";
      } else if (urlRegex.test(value)) {
        artifactType = "url"
      } else if (filenameRegex.test(value)) {
        artifactType = "filename"
      } else if (uriPathRegex.test(value)) {
        artifactType = "uri_path"
      } else if (hashRegex.test(value)) {
        artifactType = "hash"
      }
      return artifactType;
    },
    populateAddObservableForm(key, value) {
      const association = 'evidence';
      this.enableAdding(association);
      this.associatedForms[association].value = value.toString();
      this.associatedForms[association].description = key;
      const artifactType = this.mapArtifactTypeFromValue(value.toString());
      const typePresets = this.getPresets('artifactType');
      if (artifactType && typePresets && typePresets.indexOf(artifactType) != -1) {
        this.associatedForms[association].artifactType = artifactType;
      }
      this.switchToTab(association);
    },
    switchToTab(association) {
      this.activeTab = association;
    },
     
    updateCase(caseObj) {
      // No-op until we can detect if the user has made any changes to the form. We don't
      // want to wipe out a long description they might be working on typing.

      // if (!caseObj || caseObj.id != this.caseObj.id) return;
      // this.updateCaseDetails(caseObj)
      // this.loadAssociations();
    },

    colorizeChip(color) {
      if (typeof color === 'string') {
        color = color.split('+')[0];
      }
      if (color == "white" && !this.$root.$vuetify.theme.dark) {
        color = "grey";
      } else if (color == "amber" && !this.$root.$vuetify.theme.dark) {
        color = "orange";
      }

      return color;
    },

    escapeQueryValue(value) {
      if (value) {
        return this.$root.escape(value.toString());
      }
      return '';
    },
    buildHuntQuery(event) {
      var value = this.escapeQueryValue(event.fields["soc_id"]);
      return '_id: "' + value + '"';
    },
    buildHuntQueryForValue(value) {
      var value = this.escapeQueryValue(value);
      return '"' + value + '" | groupby event.module event.dataset';
    },
    getEventId(event) {
      var id = event.fields['soc_id'];
      if (!id) {
        id = this.i18n.caseEventIdAggregation;
      }
      return id;
    },
    prepareForInput(id) {
      const el = document.getElementById(id)
      el.scrollIntoView()
      el.focus();
    },

    async analyze(evidence) {
      try {
        const response = await this.$root.papi.post('job/', {
          kind: 'analyze',
          nodeId: this.analyzerNodeId,
          filter: {
            parameters: {
              artifact: evidence
            }
          }
        });
        this.$root.showTip(this.i18n.analyzeJobEnqueued);
      } catch (error) {
        this.$root.showError(error);
      }
    },
    async loadAnalyzeJobs(artifactId) {
      var existingResults = this.analyzeJobs[artifactId];
      if (!existingResults) {
        existingResults = [];
        Vue.set(this.analyzeJobs, artifactId, existingResults);

        try {
          const response = await this.$root.papi.get('jobs/', { params: {
              kind: 'analyze',
              parameters: {
                artifact: {
                  id: artifactId
                }
              }
          }});
          const jobs = response.data;

          for (var idx = 0; idx < jobs.length; idx++) {
            const job = jobs[idx];
            this.updateJob(job);
          }
        } catch (error) {
          if (error.response != undefined && error.response.status == 404) {
            // If none found, it's ok
          } else {
            this.$root.showError(error);
          }
        }

      }
    },
    analyzeInProgress(evidence) {
      const jobs = this.analyzeJobs[evidence.id];
      if (jobs) {
        const pending = jobs.find((job) => job.status == JobStatusPending);
        return pending != null;
      }
      return false;
    },
    getAnalyzeJobs(evidence) {
      const jobs = this.analyzeJobs[evidence.id];
      if (jobs && jobs.length > 0) {
        return jobs;
      }
      return null;
    },
    getAnalyzersInJob(job) {
      if (job && job.results) {
        return job.results.length;
      }
      return 0;
    },
    async deleteAnalyzeJob(job) {
      try {
        if (job) {
          await this.$root.papi.delete('job/' + job.id);

        }
      } catch (error) {
         this.$root.showError(error);
      }
    },
    updateJob(job) {
      if (job.filter.parameters && job.filter.parameters.artifact) {
        const artifactId = job.filter.parameters.artifact.id;
        const artifacts = this.associations['evidence'];
        for (var i = 0; i < artifacts.length; i++) {
          const artifact = artifacts[i];
          if (artifact.id == artifactId) {
            this.$root.populateUserDetails(job, "userId", "owner");
            var existingResults = this.analyzeJobs[artifactId];
            if (!existingResults) {
              existingResults = [];
            }
            var found = false;
            for (var jobIndex = 0; jobIndex< existingResults.length; jobIndex++) {
              const existingJob = existingResults[jobIndex];
              if (existingJob.id == job.id) {
                if (job.status == JobStatusDeleted) {
                  Vue.delete(existingResults, jobIndex);
                } else {
                  Vue.set(existingResults, jobIndex, job);
                }
                found = true;
                break;
              }
            }

            if (!found) {
              existingResults.push(job);
              existingResults.sort((a, b) => { 
                if (a.id < b.id) {
                  return -1;
                } else if (a.id > b.id) {
                  return 1;
                }
                return 0;
              });
              Vue.set(this.analyzeJobs, artifactId, existingResults);
            }

            break;
          }
        }
      }
    },
    getAnalyzerSummary(analyzer) {
      var i18nKey = "analyzer_" + analyzer.id + "_" + analyzer.summary;
      var msg = this.$root.localizeMessage(i18nKey);
      if (msg == i18nKey) {
        i18nKey = "analyzer_" + analyzer.summary;
        msg = this.$root.localizeMessage(i18nKey);
        if (msg == i18nKey) {
          msg = analyzer.summary;
        }
      }
      return msg;
    },
    getAnalyzerDecoration(analyzer) {
      var decoration = {
        color: "", // Use default color scheme
        icon: "fa-circle-question",
        severity: 50, // unknown, place severity in middle of the range
        help: "analyzer_result_unknown",
      }
      if (analyzer.data) {
        switch (analyzer.data.status) {
          case "info":
            decoration.color = "info"; 
            decoration.icon = "fa-circle-info";
            decoration.severity = 10;
            decoration.help = "analyzer_result_info";
            break;
          case "ok":
            decoration.color = "success"; 
            decoration.icon = "fa-circle-check";
            decoration.severity = 0;
            decoration.help = "analyzer_result_ok";
            break;
          case "caution":
            decoration.color = "warning"; 
            decoration.icon = "fa-circle-exclamation";
            decoration.severity = 80;
            decoration.help = "analyzer_result_caution";
            break;
          case "threat":
            decoration.color = "error"; 
            decoration.icon = "fa-triangle-exclamation";
            decoration.severity = 100;
            decoration.help = "analyzer_result_threat";
            break;
        }
      }
      return decoration;
    },
    getAnalyzeJobDecoration(job) {
      var current = { severity: -1 };
      if (job && job.results) {
        for (var idx = 0; idx < job.results.length; idx++) {
          var result = job.results[idx];
          var decoration = this.getAnalyzerDecoration(result);
          if (decoration.severity > current.severity) {
            current = decoration;
          }
        }
      } else if (job.status == JobStatusCompleted) {
        current.icon = "fa-ban";
        current.help = "analyzer_result_none";
      }
      return current;
    },

    saveLocalSettings() {
      localStorage['settings.case.mruCases'] = JSON.stringify(this.mruCases);
    },
    loadLocalSettings() {
      if (localStorage['settings.case.mruCases']) this.mruCases = JSON.parse(localStorage['settings.case.mruCases']);
    },
  }
}});

