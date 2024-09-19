// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

routes.push({
  path: '/config', name: 'config', component: {
    template: '#page-config',
    data() {
      return {
        i18n: this.$root.i18n,
        settings: [],
        search: "",
        searchFilter: null,
        autoExpand: false,
        autoSelect: "",
        form: {
          valid: true,
          key: "",
          value: "",
        },
        duplicate_id_rules: [
          value => !!value || this.$root.i18n.required,
          value => (!!value && /^[a-zA-Z0-9_]{3,50}$/.test(value)) || this.$root.i18n.settingDuplicateNameInvalid,
        ],

        selectedNode: null,
        cancelDialog: false,
        open: [],
        active: [],
        activeBackup: [],
        hierarchy: Vue.ref([]),
        nodes: [],
        availableNodes: [],
        advanced: false,
        settingsCustomized: 0,
        settingsAvailable: 0,
        showDefault: false,
        nextStopId: null,
        showDuplicate: false,
        duplicateId: null,
        duplicateIdValid: false,
        resetSetting: null,
        resetNodeId: null,
        confirmResetDialog: false,
        treeVisible: true,
      }
    },
    mounted() {
      this.processRouteParameters();
      this.loadData();
    },
    watch: {
      "active": "selectSetting",
      "advanced": "loadData",
      '$route': "onRouteUpdate",
  },
  computed: {
    selected() {
      return this.findActiveSetting();
    },
  },
  methods: {
    onRouteUpdate() {
      this.processRouteParameters();
      this.refreshTree();
    },
    processRouteParameters() {
      if (this.$route.query.a == "1") {
        this.advanced = true;
      }
      if (this.$route.query.f) {
        this.search = this.$route.query.f;
      }
      if (this.$route.query.e == "1") {
        this.autoExpand = true;
        if (this.advanced) {
          this.$nextTick(() => {
            this.autoExpand = true;
          });
        }
      }
      if (this.$route.query.s) {
        this.autoSelect = this.$route.query.s;
        this.autoExpand = true;
        this.search = this.$route.query.s;
      }
      this.applySearchFilter();
    },
    findActiveSetting() {
      if (this.active.length > 0) {
        const id = this.active[0];
        const found = this.settings.find(s => s.id == id);
        if (found) {
          return found;
        }
      }
      return null;
    },
    applySearchFilter() {
      this.searchFilter = this.search;
    },
    clearFilter() {
      this.search = "";
      this.searchFilter = "";
    },
    filter(value, search, internalItem) {
      if (!search) return true;
      search = search.toLowerCase();
      const item = internalItem.raw;
      return !!((value && value.toLowerCase().indexOf(search) > -1) ||
                (item?.name && item?.name.toLowerCase().indexOf(search) > -1) ||
                (item?.id && item?.id.toLowerCase().indexOf(search) > -1) ||
                (item?.value && item?.value.toLowerCase().indexOf(search) > -1) ||
                (item?.nodeValues && [...item?.nodeValues.keys()].find(k => k.indexOf(search) > -1)) ||
                (item?.title && item?.title.toLowerCase().indexOf(search) > -1) ||
                (item?.description && item?.description.toLowerCase().indexOf(search) > -1));
    },
    addToNode(node, parent, path, setting) {
      if (node.children == undefined) {
        throw new Error("Setting name '" + node.name + "' conflicts with another similarly named setting");
      }

      const name = path.shift();
      if (path.length == 0) {
        if (!setting.name) {
          setting.name = name;
        }
        node.children.push(setting);
      } else {
        child = node.children.find(n => n.name == name);
        const id = parent ? parent + "." + name : name;
        if (!child) {
          child = {id: id, name: name, children:[]};
          node.children.push(child);
        }
        this.addToNode(child, id, path, setting);
      }
    },

    async refreshTree() {
      this.hierarchy = this.organizeTree(this.settings);
      if (this.autoExpand) {
        this.expand();
        this.autoExpand = false;
      }
      if (this.autoSelect) {
        this.active = [this.autoSelect];
      }
    },
    organizeTree(settings) {
      const root = {children: []};
      this.settingsAvailable = 0;
      const route = this;
      settings.forEach((setting) => {
        try {
          path = setting.id.split(".");
          this.addToNode(root, "", path, setting);
          this.settingsAvailable++;
        } catch(e) {
          route.$root.showError(route.i18n.settingMalformed + " (" + setting.id + "): " + e);
        }
      });
      this.countCustomized();
      return root.children;
    },
    async countCustomized() {
      this.settingsCustomized = 0;
      const route = this;
      this.settings.forEach((setting) => {
        if (route.isSettingModified(setting) || (setting.defaultAvailable && route.isSettingModifiedPerNode(setting)) ||
          (route.isAdvanced(setting) && (setting.value || setting.nodeValues.size > 0))) {
          route.settingsCustomized++;
        }
      });
    },
    create(setting) {
      const created = {
        id: setting.id,
        global: setting.global,
        node: setting.node,
        title: setting.title,
        description: setting.description,
        multiline: setting.multiline,
        value: null,
        nodeValues: new Map(),
        default: null,
        defaultAvailable: false,
        readonly: setting.readonly,
        readonlyUi: setting.readonlyUi,
        sensitive: setting.sensitive,
        regex: setting.regex,
        regexFailureMessage: setting.regexFailureMessage,
        file: setting.file,
        helpLink: setting.helpLink,
        advanced: setting.advanced,
        syntax: setting.syntax,
        duplicates: setting.duplicates,
      };
      this.merge(created, setting);
      return created;
    },
    merge(existing, setting) {
      if (setting.nodeId) {
        existing.nodeValues.set(setting.nodeId, setting.value);
        existing.global = false;
      } else {
        existing.value = setting.value;
        existing.default = setting.default;
        existing.defaultAvailable = setting.defaultAvailable;
        existing.global = setting.global;
        existing.node = false;
      }

      if (!existing.description) existing.description = setting.description;
      if (!existing.title) existing.title = setting.title;
    },
    expand(node = null, filterFn=() => true) {
      if (!node) {
        this.open = [];
        this.hierarchy.forEach(i => this.expand(i, filterFn));
      } else if (node.children) {
        shouldExpand = false;
        node.children.forEach(s => shouldExpand |= this.expand(s, filterFn));
        if (shouldExpand) {
          node.open = true;
          this.open.push(node.id);
        }
        return shouldExpand;
      } else {
        return filterFn(node);
      }
    },
    isSettingModified(setting) {
      return setting.defaultAvailable && setting.default != setting.value;
    },
    isSettingModifiedPerNode(setting) {
      if (setting.nodeValues && setting.nodeValues.size > 0) {
        for (const value of setting.nodeValues.values()) {
          if (value) {
            return true;
          }
        }
      }
      return false;
    },
    collapse() {
      this.open = [];
      const col = (item) => {
        item.open = false;
        if (item.children) {
          item.children.forEach(i => col(i));
        }
      }

      this.hierarchy.forEach(i => col(i));
    },
    async loadData() {
      this.$root.startLoading();
      try {
        var response = await this.$root.papi.get('gridmembers/');
        this.nodes = response.data;

        response = await this.$root.papi.get('config/', {params: { advanced: this.advanced }});
        this.settings = [];
        response.data.forEach((setting) => {
          const existing = this.settings.find(s => s.id == setting.id);
          if (!existing) {
            this.settings.push(this.create(setting));
          } else {
            this.merge(existing, setting);
          }
        });
        this.refreshTree();
      } catch (error) {
        this.$root.showError(error);
      }
      this.$root.stopLoading();
    },
    translate(prefix, key, deflt) {
      modkey = key.replaceAll(".", "_");
      var str = this.i18n[prefix + modkey];
      if (!str) {
        str = deflt;
      }
      return str;
    },
    getSettingName(setting) {
      var name = setting.name;
      var title = this.translate("setting_", setting.id, setting.title);
      if (title) {
        return title;
      }
      return name;
    },
    isAdvanced(setting) {
      return setting.id.endsWith("advanced") && setting.multiline;
    },
    getSettingDescription(setting) {
      if (this.isAdvanced(setting)) {
        return this.i18n.settingAdvanced;
      }

      var desc = this.translate("settingHelp_", setting.id, setting.description);
      if (!desc) {
        desc = this.translate("setting_", setting.id, setting.title);
      }
      if (!desc) {
        desc = setting.id;
      }
      return desc;
    },
    getSettingBreadcrumbs(setting) {
      var breadcrumbs = setting.id.replaceAll(".", " > ");
      if (setting.title) {
        breadcrumbs = breadcrumbs.replace(/\s>\s[^>]+$/, " > " + setting.title);
      }
      var modifiers = []
      if (setting.advanced) {
        modifiers.push(this.i18n.configAdvancedTag);
      }
      if (modifiers.length > 0) {
        breadcrumbs = breadcrumbs + " [" + modifiers.join(", ") + "]";
      }
      return breadcrumbs;
    },
    isMultiline(setting) {
      return setting.multiline === true || (setting.advanced === true && !setting.description);
    },
    isPendingSave(setting, nodeId) {
      if (this.form.key != null) {
        if (nodeId != null && this.form.key == nodeId) {
          return this.form.value != setting.nodeValues.get(nodeId);
        } else if (nodeId == null && this.form.key == setting.id) {
          return this.form.value != setting.value;
        }
      }
      return false;
    },
    reset(setting) {
      if (setting) {
        this.form.value = setting.default;
        this.form.key = setting.id;
      }
    },
    retainChanges() {
      this.cancelDialog = false;
      this.nextStopId = null;
    },
    selectSetting() {
      if (!this.cancel()) {
        // User chose not to discard unsaved settings, go back
        this.$nextTick(() => {
          // Only set after next tick to avoid UI glitch. This has an unfortunate
          // flicker effect as the modal appears, but it avoids a more serious problem
          //  of having the wrong setting selected after dismissing the modal popup.
          this.active = this.activeBackup;
        });
        return false;
      }
      this.recomputeAvailableNodes(this.findActiveSetting());
      this.activeBackup = [...this.active];
      this.showDuplicate = false;
      this.showDefault = false;
      window.scrollTo(0,0);
    },
    cancel(force) {
      var setting = this.findActiveSetting();
      if (this.activeBackup && this.active[0] != this.activeBackup[0]) {
        // User has clicked on another setting. Grab the setting
        // from the backup so we can check if the edited value has been modified
        const currentSettingId = this.activeBackup[0];
        setting = this.settings.find(s => s.id == currentSettingId);
      }
      if (!force && setting && this.form.key && this.isPendingSave(setting, setting.id == this.form.key ? null : this.form.key)) {
        document.activeElement.blur();
        this.cancelDialog = true;

        // Save the active setting ID so we can forward the user over to that setting
        // once they approve the discard changes prompt.
        if (this.activeBackup && this.active[0] != this.activeBackup[0]) {
          this.nextStopId = this.active[0];
        }

        return false;
      }
      this.form.key = null;
      this.cancelDialog = false;

      // If the user has discarded the changes, and if there's a next-stop
      // forward the user there now.
      if (force) {
        if (this.nextStopId) {
          this.$nextTick(() => {
            this.active = [this.nextStopId];
            this.nextStopId = null;
          });
        }
      }

      return true;
    },
    remove(setting, nodeId) {
      this.resetSetting = setting;
      this.resetNodeId = nodeId;
      this.confirmResetDialog = true;
    },
    cancelRemove() {
      this.resetSetting = null;
      this.resetNodeId = null;
      this.confirmResetDialog = false;
    },
    async confirmRemove() {
      this.confirmResetDialog = false;
      if (this.resetSetting) {
        this.$root.startLoading();
        try {
          await this.$root.papi.delete('config/', { params: { id: this.resetSetting.id, minion: this.resetNodeId }});

          if (this.resetNodeId) {
            // Rebuild UI as needed
            const newMap = new Map();
            for (const [key, value] of this.resetSetting.nodeValues.entries()) {
              if (key != this.resetNodeId) {
                newMap.set(key, value);
              }
            }
            this.resetSetting.nodeValues.clear();
            this.resetSetting.nodeValues = newMap;
            this.recomputeAvailableNodes(this.findActiveSetting());
          } else {
            this.reset(this.resetSetting);
            this.resetSetting.value = this.resetSetting.default;
          }

          this.countCustomized();

          // Show update to user
          this.$root.showTip(this.i18n.settingDeleted);
        } catch (error) {
          this.$root.showError(this.i18n.settingDeleteError);
        }
        this.$root.stopLoading();
      }
      this.cancelRemove();
      this.cancel(true);
    },
    async save(setting, nodeId) {
      if (!nodeId) {
        if (this.form.key != setting.id) return;
      } else {
        if (this.form.key != nodeId) return;
      }

      if (setting) {
        this.form.value = this.form.value.trim();
        if (setting.regex) {
          var test_values = [this.form.value];
          if (setting.multiline) {
            test_values = this.form.value.split("\n");
          }
          for (var idx = 0; idx < test_values.length; idx++) {
            const re = new RegExp(setting.regex);
            if (!re.test(test_values[idx])) {
              this.$root.showError(setting.regexFailureMessage ? setting.regexFailureMessage : this.i18n.settingValidationFailed);
              return;
            }
          }
        }
        this.$root.startLoading();
        try {
          const server_setting = {
            id: setting.id,
            nodeId: nodeId,
            value: this.form.value,
            file: setting.file,
            syntax: setting.syntax,
          };
          await this.$root.papi.put('config/', server_setting);

          // Update UI
          if (!nodeId) {
            setting.value = this.form.value
          } else {
            setting.nodeValues.set(nodeId, this.form.value);
          }
          this.cancel(true);

          this.countCustomized();

          // Update the user with status
          this.$root.showTip(this.i18n.settingSaved);
        } catch (error) {
          var msg = this.i18n.settingSaveError;
          if (error.response && error.response.data && error.response.data.startsWith("ERROR_")) {
            msg = error.response.data;
          }
          this.$root.showError(msg);
        }
        this.$root.stopLoading();
      }
    },
    async sync() {
      this.$root.startLoading();
      try {
        const response = await this.$root.papi.put('config/sync');
        this.$root.showTip(this.i18n.settingsSynchronized);
      } catch (error) {
         this.$root.showError(error);
      }
      this.$root.stopLoading();
    },
    edit(setting, nodeId) {
      if (nodeId) {
        if ((this.form.key == nodeId) || !this.cancel()) return;
        this.form.key = nodeId;
        this.form.value = setting.nodeValues.get(nodeId);
        this.$root.drawAttention('#setting-node-save-' + nodeId);
      } else {
        if ((this.form.key == setting.id) || !this.cancel()) return;
        this.form.key = setting.id;
        this.form.value = setting.value;
        this.$root.drawAttention('#setting-global-save');
      }
    },
    addNode(setting, nodeId) {
      if (this.cancel() && setting && nodeId) {
        setting.nodeValues.set(nodeId, setting.default);
        this.recomputeAvailableNodes(setting);
      }
      this.$nextTick(() => {
        this.selectedNode = null;
      });
    },
    recomputeAvailableNodes(setting) {
      if (!setting) return;
      const eligible = this.nodes.filter(n => {
        return n.status == GridMemberAccepted && !setting.nodeValues.has(n.id);
      });
      this.availableNodes = eligible.map(n => { return { title: n.name + " (" + n.role + ")", value: n.id } });
    },
    toggleDuplicate(setting) {
      this.duplicateId = this.suggestDuplicateName(setting);
      this.showDuplicate = !this.showDuplicate;
    },
    suggestDuplicateName(setting) {
      return setting.name + "_dup";
    },
    duplicate(setting) {
      const new_name = this.duplicateId;
      var new_id = setting.id.substring(0, setting.id.lastIndexOf(setting.name));
      new_id += new_name;
      this.$root.startLoading();
      const found = this.settings.find(s => s.id == new_id);
      this.$root.stopLoading();
      if (found) {
        this.$root.showWarning(this.i18n.settingDuplicateInvalid);
        return
      }
      var new_setting = structuredClone(setting);
      new_setting.id = new_id;
      new_setting.name = new_name;
      this.settings.push(new_setting);
      this.settings.sort((a,b) => { if (a.id > b.id) return 1; else if (a.id < b.id) return -1; else return 0 });
      this.refreshTree();
      this.active = [new_id]
    },
    isReadOnly(item) {
      return item.readonly || item.readonlyUi;
    },
  }
}});
