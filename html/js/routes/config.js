// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

routes.push({ path: '/config', name: 'config', component: {
  template: '#page-config',
  data() { return {
    i18n: this.$root.i18n,
    settings: [],
    search: "",
    form: {
      valid: true,
      key: "",
      value: "",
    },

    selectedNode: null,
    cancelDialog: false,
    open: [],
    active: [],
    activeBackup: [],
    hierarchy: [],
    nodes: [],
    availableNodes: [],
    advanced: false,
    settingsCustomized: 0,
    settingsAvailable: 0,
    showDefault: false,
  }},
  mounted() {
    this.loadData()
  },
  watch: {
    "active": "selectSetting",
    "advanced": "refreshTree",
  },
  computed: {
    selected() {
      return this.findActiveSetting();
    },
  },
  methods: {
    findActiveSetting() {
      if (this.active.length > 0) {
        const id = this.active[0];
        return this.settings.find(s => s.id == id);
      }
      return null;
    },
    clearFilter() {
      this.search = "";
    },
    filter(item, search, textKey) {
      if (!search) return true;
      search = search.toLowerCase();
      return (item.name && item.name.toLowerCase().indexOf(search) > -1) ||
             (item.id && item.id.toLowerCase().indexOf(search) > -1) ||
             (item.value && item.value.toLowerCase().indexOf(search) > -1) ||
             (item.nodeValues && [...item.nodeValues.keys()].find(k => k.indexOf(search) > -1)) ||
             (item.title && item.title.toLowerCase().indexOf(search) > -1) ||
             (item.description && item.description.toLowerCase().indexOf(search) > -1);
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
    },
    organizeTree(settings) {
      const root = {children: []};
      this.settingsAvailable = 0;
      const route = this;
      settings.forEach((setting) => {
        try {
          path = setting.id.split(".");
          if ((setting.description && !setting.advanced) || this.advanced) {
            this.addToNode(root, "", path, setting);
            this.settingsAvailable++;
          }
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
        sensitive: setting.sensitive,
        regex: setting.regex,
        regexFailureMessage: setting.regexFailureMessage,
        file: setting.file,
        helpLink: setting.helpLink,
        advanced: setting.advanced,
        syntax: setting.syntax,
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
        this.hierarchy.forEach(s => this.expand(s, filterFn));
      } else if (node.children) {
        shouldExpand = false;
        node.children.forEach(s => shouldExpand |= this.expand(s, filterFn));
        if (shouldExpand) {
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
    },
    async loadData() {
      this.$root.startLoading();
      try {
        var response = await this.$root.papi.get('gridmembers/');
        this.nodes = response.data;

        response = await this.$root.papi.get('config/');
        this.settings = [];
        response.data.forEach((setting) => {
          const existing = this.settings.find(s => s.id == setting.id);
          if (!existing) {
            this.settings.push(this.create(setting));
          } else {
            this.merge(existing, setting);
          }
        });
        this.hierarchy = this.organizeTree(this.settings);
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
    isMultiline(setting) {
      return setting.multiline === true;
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
      window.scrollTo(0,0);
    },
    cancel(force) {
      const setting = this.findActiveSetting();
      if (!force && setting && this.form.key && this.isPendingSave(setting, setting.id == this.form.key ? null : this.form.key)) {
        document.activeElement.blur();
        this.cancelDialog = true;
        return false;
      }
      this.form.key = null;
      this.cancelDialog = false;
      return true;
    },
    async remove(setting, nodeId) {
      if (setting) {
        this.$root.startLoading();
        try {
          await this.$root.papi.delete('config/', { params: { id: setting.id, minion: nodeId }});

          if (nodeId) {
            // Rebuild UI as needed
            const newMap = new Map();
            for (const [key, value] of setting.nodeValues.entries()) {
              if (key != nodeId) {
                newMap.set(key, value);
              }
            }
            setting.nodeValues.clear();
            setting.nodeValues = newMap;
            this.recomputeAvailableNodes(this.findActiveSetting());
          } else {
            this.reset(setting);
            setting.value = setting.default;
          }

          this.countCustomized();

          // Show update to user
          this.$root.showTip(this.i18n.settingDeleted);
        } catch (error) {
          this.$root.showError(this.i18n.settingDeleteError);
        }
        this.$root.stopLoading();
      }
      this.cancel(true);
    },
    async save(setting, nodeId) {
      if (!nodeId) {
        if (this.form.key != setting.id) return;
      } else {
        if (this.form.key != nodeId) return;
      }

      if (setting) {
        if (setting.regex) {
          const re = new RegExp(setting.regex);
          if (!re.test(this.form.value)) {
            this.$root.showError(setting.regexFailureMessage ? setting.regexFailureMessage : this.i18n.settingValidationFailed);
            return;
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
      this.availableNodes = eligible.map(n => { return { text: n.name + " (" + n.role + ")", value: n.id } });
    },
  }
}});
