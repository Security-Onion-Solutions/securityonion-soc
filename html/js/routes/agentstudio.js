// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

// The Agent Studio manages the assistant's agents and skills. Rows come from the
// assistant client parameters, which the backend has already merged from the
// built-in definitions and stored config. Edits are saved one row at a time; the
// server merges each into the stored set and pushes the result to every browser.

loadPageTemplate('page-agentstudio', 'pages/agentstudio.html');

const LIMIT_DEPTH_SETTING_ID = 'soc.config.server.modules.assistant.maxDelegationDepth';
const LIMIT_TOKENS_SETTING_ID = 'soc.config.server.modules.assistant.maxSubSessionTokens';

const MEMORY_SETTING_IDS = {
  useMemory: 'soc.config.server.modules.assistant.useMemory',
  useMemoryScanner: 'soc.config.server.modules.assistant.useMemoryScanner',
  scanIntervalSeconds: 'soc.config.server.modules.assistant.memoryScanIntervalSeconds',
  memoryProximityThreshold: 'soc.config.server.modules.assistant.memoryProximityThreshold',
  messageProximityThreshold: 'soc.config.server.modules.assistant.messageProximityThreshold',
  maxUserMemoriesToInclude: 'soc.config.server.modules.assistant.maxUserMemoriesToInclude',
  maxGlobalMemoriesToInclude: 'soc.config.server.modules.assistant.maxGlobalMemoriesToInclude',
  maxUserMemoriesToReconcile: 'soc.config.server.modules.assistant.maxUserMemoriesToReconcile',
  maxGlobalMemoriesToReconcile: 'soc.config.server.modules.assistant.maxGlobalMemoriesToReconcile',
  memoryModel: 'soc.config.server.modules.assistant.memoryModel',
  embedModel: 'soc.config.server.modules.assistant.embedModel',
  reconcileModel: 'soc.config.server.modules.assistant.reconcileModel',
  memoryPersona: 'soc.config.server.modules.assistant.memoryPersona',
  reconcilePersona: 'soc.config.server.modules.assistant.reconcilePersona',
  dontScanBefore: 'soc.config.server.modules.assistant.dontScanBefore',
};

routes.push({ path: '/agentstudio', name: 'agentstudio', component: {
  template: '#page-agentstudio',
  data() { return {
    i18n: this.$root.i18n,
    tab: 'agents',

    paramsLoaded: false,
    assistantEnabled: false,
    agentic: false,

    createAgentDialog: false,
    createSkillDialog: false,
    createMemoryDialog: false,
    scanHistoricalDialog: false,
    newAgent: {},
    newSkill: {},
    newMemory: {},

    memoryEnabled: false,
    memories: [],
    memoryTotal: 0,
    memoryScope: 'all',
    memorySearch: '',
    memoryPage: 1,
    memoryItemsPerPage: 10,
    memoryDrafts: {},
    expandedMemories: [],
    // Memories awaiting re-embedding; pushed by the server as the pass progresses.
    staleMemoryCount: 0,
    showPersonaDialog: false,

    // Global delegation guardrails, edited in the Options dialog. saved* is the
    // last-known server value, so Save stays disabled until something changes.
    showOptionsDialog: false,
    maxDelegationDepth: 0,
    maxSubSessionTokens: 0,
    savedMaxDelegationDepth: 0,
    savedMaxSubSessionTokens: 0,
    memoryOptions: {},
    savedMemoryOptions: {},

    sortByAgents: [{ key: 'name', order: 'asc' }],
    sortBySkills: [{ key: 'name', order: 'asc' }],
    expandedAgents: [],
    expandedSkills: [],
    // Per-row active sub-tab, keyed by row id (mirrors the alerts page's activeTabs).
    agentTabs: {},
    skillTabs: {},
    // Working copies of expanded rows. The table shows committed values; edits go
    // to the draft and are applied only after a successful save.
    agentDrafts: {},
    skillDrafts: {},
    itemsPerPage: 10,
    itemsPerPageOptions: [10, 50, 250, 1000],

    agentHeaders: [
      { title: '', value: 'expand', sortable: false, width: '48px' },
      { title: this.$root.i18n.agentStudioName, value: 'name' },
      { title: this.$root.i18n.agentStudioRole, value: 'role' },
      { title: this.$root.i18n.agentStudioModel, value: 'model' },
      { title: this.$root.i18n.agentStudioSkills, value: 'skills', sortable: false },
      { title: this.$root.i18n.agentStudioDelegatesTo, value: 'canDelegateTo', sortable: false },
      { title: this.$root.i18n.agentStudioEnabled, value: 'enabled', sortable: false, width: '110px' },
    ],
    skillHeaders: [
      { title: '', value: 'expand', sortable: false, width: '48px' },
      { title: this.$root.i18n.agentStudioSkill, value: 'name' },
      { title: this.$root.i18n.tools, value: 'tools', sortable: false },
      { title: this.$root.i18n.agentStudioUsedBy, value: 'usedBy', sortable: false },
      { title: this.$root.i18n.agentStudioEnabled, value: 'enabled', sortable: false, width: '110px' },
    ],

    memoryHeaders: [
      { title: '', value: 'expand', sortable: false, width: '48px' },
      { title: this.$root.i18n.agentStudioMemoryText, value: 'memoryText', sortable: false },
      { title: this.$root.i18n.agentStudioMemoryScope, value: 'scope', sortable: false, width: '140px' },
      { title: this.$root.i18n.owner, value: 'targetUserId', sortable: false },
      { title: this.$root.i18n.agentStudioMemoryRecalled, value: 'usageCount', sortable: false, width: '110px' },
      { title: this.$root.i18n.dateModified, value: 'updateTime', sortable: false, width: '180px' },
    ],

    roleItems: [
      { title: this.$root.i18n.agentStudioOrchestrator, value: true },
      { title: this.$root.i18n.agentStudioSpecialist, value: false },
    ],
    scopeItems: [
      { title: this.$root.i18n.agentStudioMemoryScopeUser, value: 'user' },
      { title: this.$root.i18n.agentStudioMemoryScopeGlobal, value: 'global' },
    ],
    scopeFilterItems: [
      { title: this.$root.i18n.all, value: 'all' },
      { title: this.$root.i18n.agentStudioMemoryScopeUser, value: 'self' },
      { title: this.$root.i18n.agentStudioMemoryScopeGlobal, value: 'global' },
    ],

    models: [],
    adapters: [],
    skills: [],
    agents: [],
    // Tool names an admin-created skill may grant, from assistant.availableTools.
    tools: [],
  }},
  computed: {
    agentNames() {
      return this.agents.map(a => a.name);
    },
    skillNames() {
      return this.skills.map(s => s.name);
    },
  },
  watch: {
    '$route': 'reload',
    'sortByAgents': 'saveLocalSettings',
    'sortBySkills': 'saveLocalSettings',
    'itemsPerPage': 'saveLocalSettings',
    'memoryItemsPerPage': 'saveLocalSettings',
  },
  mounted() {
    this.reload();
    this.$root.subscribe('assistant:agentic', this.onAgenticUpdate);
  },
  beforeUnmount() {
    this.$root.unsubscribe('assistant:agentic', this.onAgenticUpdate);
  },
  methods: {
    reload() {
      this.$root.startLoading();
      this.$root.loadParameters('assistant', this.initAssistant);
    },
    initAssistant(params) {
      params = params || {};
      this.assistantEnabled = params.enabled && this.$root.isLicensed('oai');
      this.agentic = params.agentic || false;
      this.paramsLoaded = true;
      if (this.assistantEnabled && (this.agentic || params.memoryEnabled)) {
        this.applyParams(params);
        this.loadLocalSettings();
        if (!this.agentic) this.tab = 'memories';
      }
      this.$root.stopLoading();
    },
    applyParams(params) {
      this.models = (params.availableModels || []).map(m => ({
        id: m.id,
        adapter: m.adapter,
        selector: AssistantUtils.buildModelIdentifier(m),
        displayName: m.displayName || AssistantUtils.buildModelIdentifier(m),
        enabled: !!m.enabled,
        contextWindow: m.contextLimitLarge || m.contextLimitSmall || 0,
      }));
      this.tools = params.availableTools || [];
      this.adapters = params.availableAdapters || [];
      this.memoryEnabled = !!params.memoryEnabled;
      this.setSkills(this.skillsFromParams(params));
      this.setAgents(this.agentsFromParams(params));
      this.applyLimits(params);
    },
    // Only adopt server values while the dialog is closed, so a push mid-edit does
    // not overwrite what the admin is typing.
    applyLimits(params) {
      this.savedMaxDelegationDepth = params.maxDelegationDepth || 0;
      this.savedMaxSubSessionTokens = params.maxSubSessionTokens || 0;
      this.savedMemoryOptions = Object.assign({}, params.memoryParams || {});
      this.staleMemoryCount = (params.memoryParams || {}).staleMemoryCount || 0;
      if (!this.showOptionsDialog) {
        this.maxDelegationDepth = this.savedMaxDelegationDepth;
        this.maxSubSessionTokens = this.savedMaxSubSessionTokens;
        this.memoryOptions = Object.assign({}, this.savedMemoryOptions);
      }
    },
    // The server pushes agentic changes over the websocket, so a save just waits for
    // that push to land in $root.parameters before rebuilding the rows from it.
    onAgenticUpdate() {
      this.applyParams((this.$root.parameters || {}).assistant || {});
    },
    saveSetting(name, value, defaultValue = null) {
      var item = 'settings.agentstudio.' + name;
      if (defaultValue == null || value != defaultValue) {
        localStorage[item] = value;
      } else {
        localStorage.removeItem(item);
      }
    },
    saveLocalSettings() {
      this.saveSetting('sortByAgents', this.sortByAgents[0].key, 'name');
      this.saveSetting('sortDescAgents', this.sortByAgents[0].order, 'asc');
      this.saveSetting('sortBySkills', this.sortBySkills[0].key, 'name');
      this.saveSetting('sortDescSkills', this.sortBySkills[0].order, 'asc');
      this.saveSetting('itemsPerPage', this.itemsPerPage, 10);
      this.saveSetting('memoryItemsPerPage', this.memoryItemsPerPage, 10);
    },
    loadLocalSettings() {
      if (localStorage['settings.agentstudio.sortByAgents']) this.sortByAgents[0].key = localStorage['settings.agentstudio.sortByAgents'];
      if (localStorage['settings.agentstudio.sortDescAgents']) this.sortByAgents[0].order = localStorage['settings.agentstudio.sortDescAgents'];

      if (localStorage['settings.agentstudio.sortBySkills']) this.sortBySkills[0].key = localStorage['settings.agentstudio.sortBySkills'];
      if (localStorage['settings.agentstudio.sortDescSkills']) this.sortBySkills[0].order = localStorage['settings.agentstudio.sortDescSkills'];

      if (localStorage['settings.agentstudio.itemsPerPage']) this.itemsPerPage = parseInt(localStorage['settings.agentstudio.itemsPerPage']);
      if (localStorage['settings.agentstudio.memoryItemsPerPage']) this.memoryItemsPerPage = parseInt(localStorage['settings.agentstudio.memoryItemsPerPage']);
    },
    agentsFromParams(params) {
      const mapping = params.agentMapping || {};
      return (params.availableAgents || []).map(a => {
        const selector = mapping[a.name] || '';
        const m = AssistantUtils.resolveMappedModel(this.models, selector);
        return {
          id: a.name,
          name: a.name,
          isSystem: !!a.isSystem,
          enabled: !!a.enabled,
          isOrchestrator: !!a.isOrchestrator,
          // Display name of the resolved model; an unresolvable selector is shown as-is.
          model: m ? m.displayName : selector,
          modelSelector: selector,
          provider: m ? m.adapter : '',
          description: a.agentDescription || '',
          allowedSkills: a.allowedSkills || [],
          canDelegateTo: a.canDelegateTo || [],
          persona: a.personaAddendum || '',
        };
      });
    },
    skillsFromParams(params) {
      return (params.availableSkills || []).map(s => ({
        id: s.name,
        name: s.name,
        isSystem: !!s.isSystem,
        enabled: !!s.enabled,
        tools: s.tools || [],
        persona: s.personaAddendum || '',
      }));
    },
    setAgents(agents) {
      // The table shows the resolved model name, so re-derive it here: an edit only
      // changes modelSelector, and the row would otherwise keep the old display name.
      this.agents = agents.map(a => this.resolveAgentModel(a));
      this.agents.forEach(a => { if (!this.agentTabs[a.id]) this.agentTabs[a.id] = 'identity'; });
    },
    resolveAgentModel(agent) {
      const m = AssistantUtils.resolveMappedModel(this.models, agent.modelSelector);
      return Object.assign({}, agent, {
        // A row's id is its stored name; after a rename the next write must address
        // the row by its new name or the server reads it as another rename.
        id: agent.name,
        model: m ? m.displayName : (agent.modelSelector || ''),
        provider: m ? m.adapter : '',
      });
    },
    setSkills(skills) {
      this.skills = skills.map(s => Object.assign({}, s, { id: s.name }));
      this.skills.forEach(s => { if (!this.skillTabs[s.id]) this.skillTabs[s.id] = 'tools'; });
    },
    roleLabel(agent) {
      return agent.isOrchestrator ? this.i18n.agentStudioOrchestrator : this.i18n.agentStudioSpecialist;
    },
    skillUsedBy(skillName) {
      return this.agents.filter(a => a.allowedSkills.includes(skillName)).map(a => a.name);
    },
    delegateChoices(agent) {
      return this.agents.map(a => a.name).filter(n => n !== agent.name);
    },
    modelItems() {
      return this.models.map(m => ({ title: m.displayName, subtitle: m.adapter, value: m.selector }));
    },
    groupModelItems(items) {
      const byAdapter = {};
      for (const item of items) {
        const adapter = item.subtitle || this.i18n.statusUnknown;
        if (!byAdapter[adapter]) byAdapter[adapter] = [];
        byAdapter[adapter].push(item);
      }

      const grouped = [];
      for (const adapter of Object.keys(byAdapter).sort()) {
        grouped.push({ header: adapter });
        grouped.push(...byAdapter[adapter]);
      }
      return grouped;
    },
    embedModelItems() {
      const capable = (this.adapters || []).filter(a => a.supportsEmbeddings).map(a => a.name);
      return this.modelItems().filter(item => capable.includes(item.subtitle));
    },
    memoryRoleResolves(field) {
      const selector = this.memoryOptions[field];
      if (!selector) return false;
      const m = AssistantUtils.resolveMappedModel(this.models, selector);
      return !!(m && m.enabled);
    },
    memoryRoleHint(field, help) {
      return this.memoryRoleResolves(field) ? help : this.i18n.agentStudioMemoryRoleDisabled;
    },
    providerFor(selector) {
      const m = AssistantUtils.resolveMappedModel(this.models, selector);
      return m ? m.adapter : '';
    },

    // A system agent's name, role, description and skills come from the built-in
    // definition, so only the fields an admin may change are written back.
    agentPayload(a) {
      if (a.isSystem) {
        return {
          name: a.name,
          enabled: !!a.enabled,
          model: a.modelSelector || '',
          canDelegateTo: a.canDelegateTo || [],
          persona: a.persona || '',
        };
      }
      return {
        name: a.name,
        enabled: !!a.enabled,
        isOrchestrator: !!a.isOrchestrator,
        model: a.modelSelector || '',
        allowedSkills: a.allowedSkills || [],
        canDelegateTo: a.canDelegateTo || [],
        description: a.description || '',
        persona: a.persona || '',
      };
    },
    skillPayload(s) {
      if (s.isSystem) {
        return { name: s.name, enabled: !!s.enabled, persona: s.persona || '' };
      }
      return { name: s.name, enabled: !!s.enabled, tools: s.tools || [], persona: s.persona || '' };
    },
    showOptions() {
      this.maxDelegationDepth = this.savedMaxDelegationDepth;
      this.maxSubSessionTokens = this.savedMaxSubSessionTokens;
      this.memoryOptions = Object.assign({}, this.savedMemoryOptions);
      this.showOptionsDialog = true;
    },
    dirtyMemoryOptions() {
      return Object.keys(MEMORY_SETTING_IDS)
        .filter(key => this.memoryOptions[key] !== this.savedMemoryOptions[key])
        .map(key => [MEMORY_SETTING_IDS[key], this.memoryOptions[key]]);
    },
    optionsDirty() {
      return this.maxDelegationDepth !== this.savedMaxDelegationDepth ||
        this.maxSubSessionTokens !== this.savedMaxSubSessionTokens ||
        this.dirtyMemoryOptions().length > 0;
    },
    // These are plain scalar settings with no merge concerns, so they go straight
    // to config; saving any of them triggers a reload and a push.
    async persistOptions() {
      this.$root.startLoading();
      try {
        if (this.maxDelegationDepth !== this.savedMaxDelegationDepth) {
          await this.saveLimit(LIMIT_DEPTH_SETTING_ID, this.maxDelegationDepth);
        }
        if (this.maxSubSessionTokens !== this.savedMaxSubSessionTokens) {
          await this.saveLimit(LIMIT_TOKENS_SETTING_ID, this.maxSubSessionTokens);
        }
        for (const [settingId, value] of this.dirtyMemoryOptions()) {
          await this.saveLimit(settingId, value);
        }
        this.savedMaxDelegationDepth = this.maxDelegationDepth;
        this.savedMaxSubSessionTokens = this.maxSubSessionTokens;
        this.savedMemoryOptions = Object.assign({}, this.memoryOptions);
        this.showOptionsDialog = false;
      } catch (error) {
        this.$root.showError(error);
      } finally {
        this.$root.stopLoading();
      }
    },
    saveLimit(settingId, value) {
      return this.$root.papi.put('config/', {
        id: settingId,
        nodeId: '',
        value: String(value),
        syntax: '',
        note: '',
        duplicatedFromId: '',
      });
    },
    // One row per request: the server merges it into the stored set, so a stale
    // page can never revert another admin's edit to a different agent or skill.
    async saveRow(kind, name, payload) {
      this.$root.startLoading();
      let ok = false;
      try {
        await this.$root.papi.put(`assistant/${kind}/${encodeURIComponent(name)}`, payload);
        ok = true;
      } catch (error) {
        this.$root.showError(error);
      } finally {
        this.$root.stopLoading();
      }
      return ok;
    },
    async deleteRow(kind, name) {
      this.$root.startLoading();
      let ok = false;
      try {
        await this.$root.papi.delete(`assistant/${kind}/${encodeURIComponent(name)}`);
        ok = true;
      } catch (error) {
        this.$root.showError(error);
      } finally {
        this.$root.stopLoading();
      }
      return ok;
    },
    // Rows are committed locally on a successful write so the table reflects the
    // change immediately; the server's push then reconciles them with what it merged.
    async persistAgent(agent, list) {
      // The URL names the row as stored; the body may rename it.
      const ok = await this.saveRow('agents', agent.id || agent.name, this.agentPayload(agent));
      if (ok) this.setAgents(list || this.agents.map(a => (a.id === agent.id ? agent : a)));
      return ok;
    },
    async persistSkill(skill, list) {
      const ok = await this.saveRow('skills', skill.id || skill.name, this.skillPayload(skill));
      if (ok) this.setSkills(list || this.skills.map(s => (s.id === skill.id ? skill : s)));
      return ok;
    },

    // Disabling the last enabled orchestrator would leave the grid with no entry
    // point for agentic chat; the backend refuses it too.
    canDisableAgent(agent) {
      if (!agent.isOrchestrator || !agent.enabled) return true;
      return this.agents.some(a => a.isOrchestrator && a.enabled && a.id !== agent.id);
    },
    async toggleAgentEnabled(agent) {
      if (agent.enabled && !this.canDisableAgent(agent)) {
        this.$root.showError(this.i18n.agentStudioLastOrchestrator);
        return;
      }
      await this.persistAgent(Object.assign({}, agent, { enabled: !agent.enabled }));
    },
    async toggleSkillEnabled(skill) {
      await this.persistSkill(Object.assign({}, skill, { enabled: !skill.enabled }));
    },

    draftForAgent(agent) {
      return this.agentDrafts[agent.id] || agent;
    },
    draftForSkill(skill) {
      return this.skillDrafts[skill.id] || skill;
    },
    // Expanding snapshots the row into a draft; collapsing without saving drops it.
    onToggleAgent(agent, toggleExpand, internalItem) {
      if (this.expandedAgents.includes(agent.id)) {
        delete this.agentDrafts[agent.id];
      } else {
        this.agentDrafts[agent.id] = JSON.parse(JSON.stringify(agent));
      }
      toggleExpand(internalItem);
    },
    onToggleSkill(skill, toggleExpand, internalItem) {
      if (this.expandedSkills.includes(skill.id)) {
        delete this.skillDrafts[skill.id];
      } else {
        this.skillDrafts[skill.id] = JSON.parse(JSON.stringify(skill));
      }
      toggleExpand(internalItem);
    },
    agentDirty(item) {
      const draft = this.agentDrafts[item.id];
      if (!draft) return false;
      return JSON.stringify(this.agentPayload(draft)) !== JSON.stringify(this.agentPayload(item));
    },
    skillDirty(item) {
      const draft = this.skillDrafts[item.id];
      if (!draft) return false;
      return JSON.stringify(this.skillPayload(draft)) !== JSON.stringify(this.skillPayload(item));
    },
    async saveAgent(agent) {
      const draft = this.agentDrafts[agent.id];
      if (!draft) return;
      if (this.renameCollides(draft, agent, this.agents)) {
        this.$root.showError(this.i18n.agentStudioDuplicateName);
        return;
      }
      const next = this.agents.map(a => (a.id === agent.id ? draft : a));
      if (await this.persistAgent(draft, next)) {
        this.expandedAgents = this.expandedAgents.filter(id => id !== agent.id);
        delete this.agentDrafts[agent.id];
      }
    },
    async saveSkill(skill) {
      const draft = this.skillDrafts[skill.id];
      if (!draft) return;
      if (this.renameCollides(draft, skill, this.skills)) {
        this.$root.showError(this.i18n.agentStudioDuplicateName);
        return;
      }
      const next = this.skills.map(s => (s.id === skill.id ? draft : s));
      if (await this.persistSkill(draft, next)) {
        this.expandedSkills = this.expandedSkills.filter(id => id !== skill.id);
        delete this.skillDrafts[skill.id];
      }
    },
    async removeAgent(agent) {
      if (agent.isSystem) return;
      const next = this.agents.filter(a => a.id !== agent.id);
      if (await this.deleteRow('agents', agent.name)) {
        this.setAgents(next);
        this.expandedAgents = this.expandedAgents.filter(id => id !== agent.id);
        delete this.agentDrafts[agent.id];
      }
    },
    async removeSkill(skill) {
      if (skill.isSystem) return;
      const next = this.skills.filter(s => s.id !== skill.id);
      if (await this.deleteRow('skills', skill.name)) {
        this.setSkills(next);
        this.expandedSkills = this.expandedSkills.filter(id => id !== skill.id);
        delete this.skillDrafts[skill.id];
      }
    },

    // copyName returns an unused "X (copy)" / "X (copy) 2" name.
    copyName(name, taken) {
      const base = name + ' ' + this.i18n.agentStudioCopySuffix;
      let candidate = base;
      let n = 1;
      while (taken.includes(candidate)) {
        n++;
        candidate = base + ' ' + n;
      }
      return candidate;
    },
    async duplicateAgent(agent) {
      const name = this.copyName(agent.name, this.agents.map(a => a.name));
      const copy = {
        id: name,
        name: name,
        isSystem: false,
        enabled: agent.enabled,
        isOrchestrator: agent.isOrchestrator,
        model: agent.model,
        modelSelector: agent.modelSelector,
        provider: agent.provider,
        description: agent.description,
        allowedSkills: (agent.allowedSkills || []).slice(),
        canDelegateTo: (agent.canDelegateTo || []).slice(),
        persona: agent.persona || '',
      };
      await this.persistAgent(copy, this.agents.concat([copy]));
    },
    async duplicateSkill(skill) {
      const name = this.copyName(skill.name, this.skills.map(s => s.name));
      const copy = {
        id: name,
        name: name,
        isSystem: false,
        enabled: skill.enabled,
        tools: (skill.tools || []).slice(),
        persona: skill.persona || '',
      };
      await this.persistSkill(copy, this.skills.concat([copy]));
    },

    showAddAgent() {
      this.newAgent = {
        name: '',
        isSystem: false,
        enabled: true,
        isOrchestrator: false,
        modelSelector: (this.models[0] && this.models[0].selector) || '',
        description: '',
        allowedSkills: [],
        canDelegateTo: [],
        // Existing agents that should be able to delegate to this one. Not part of
        // the agent itself; saving rewrites those agents' canDelegateTo.
        delegators: [],
        persona: '',
      };
      this.createAgentDialog = true;
    },
    showAddSkill() {
      this.newSkill = { name: '', isSystem: false, enabled: true, tools: [], persona: '' };
      this.createSkillDialog = true;
    },
    nameTaken(name, existing) {
      return existing.some(n => n.toLowerCase() === String(name || '').trim().toLowerCase());
    },
    // A rename onto another row's name would overwrite it, so the server refuses it.
    renameCollides(draft, item, rows) {
      if (draft.name === item.name) return false;
      return this.nameTaken(draft.name, rows.filter(r => r.id !== item.id).map(r => r.name));
    },
    async saveNewAgent() {
      const name = String(this.newAgent.name || '').trim();
      if (!name || this.nameTaken(name, this.agents.map(a => a.name))) {
        this.$root.showError(this.i18n.agentStudioDuplicateName);
        return;
      }
      const delegators = this.newAgent.delegators || [];
      const agent = Object.assign({}, this.newAgent, { id: name, name: name });
      delete agent.delegators;

      if (!await this.persistAgent(agent, this.agents.concat([agent]))) return;

      // Delegation lives on the delegating agent, so this edits them, not the new one.
      const failed = [];
      for (const delegator of delegators) {
        const row = this.agents.find(a => a.name === delegator);
        if (!row || row.canDelegateTo.includes(name)) continue;
        const updated = Object.assign({}, row, { canDelegateTo: row.canDelegateTo.concat([name]) });
        if (!await this.persistAgent(updated)) failed.push(delegator);
      }

      this.createAgentDialog = false;
      this.tab = 'agents';
      if (failed.length) {
        this.$root.showError(this.i18n.agentStudioDelegatorsFailed + ' ' + failed.join(', '));
      }
    },
    async saveNewSkill() {
      const name = String(this.newSkill.name || '').trim();
      if (!name || this.nameTaken(name, this.skills.map(s => s.name))) {
        this.$root.showError(this.i18n.agentStudioDuplicateName);
        return;
      }
      const skill = Object.assign({}, this.newSkill, { id: name, name: name });
      if (await this.persistSkill(skill, this.skills.concat([skill]))) {
        this.createSkillDialog = false;
        this.tab = 'skills';
      }
    },

    // v-data-table-server reports paging through options; a search is submitted
    // explicitly because every one of them costs an embedding call.
    onMemoryOptions(options) {
      this.memoryPage = options.page;
      this.memoryItemsPerPage = options.itemsPerPage;
      this.loadMemories();
    },
    onMemoryFilterChanged() {
      this.memoryPage = 1;
      this.loadMemories();
    },
    async loadMemories() {
      if (!this.memoryEnabled) return;
      this.$root.startLoading();
      try {
        const response = await this.$root.papi.get('assistant/memories', {
          params: {
            scope: this.memoryScope,
            q: this.memorySearch || '',
            limit: this.memoryItemsPerPage,
            offset: (this.memoryPage - 1) * this.memoryItemsPerPage,
          },
        });
        const results = response.data || {};
        this.memories = results.memories || [];
        this.memoryTotal = results.total || 0;
        this.memoryDrafts = {};
        this.expandedMemories = [];
      } catch (error) {
        this.$root.showError(error);
      } finally {
        this.$root.stopLoading();
      }
    },
    memoryPayload(mem) {
      return {
        memoryText: mem.memoryText || '',
        scope: mem.scope === 'global' ? 'global' : 'user',
        targetUserId: mem.scope === 'global' ? '' : (mem.targetUserId || ''),
      };
    },
    draftForMemory(mem) {
      return this.memoryDrafts[mem.id] || mem;
    },
    onToggleMemory(mem, toggleExpand, internalItem) {
      if (this.expandedMemories.includes(mem.id)) {
        delete this.memoryDrafts[mem.id];
      } else {
        this.memoryDrafts[mem.id] = JSON.parse(JSON.stringify(mem));
      }
      toggleExpand(internalItem);
    },
    memoryDirty(mem) {
      const draft = this.memoryDrafts[mem.id];
      if (!draft) return false;
      return JSON.stringify(this.memoryPayload(draft)) !== JSON.stringify(this.memoryPayload(mem));
    },
    memoryOwner(mem) {
      return mem.scope === 'global' ? this.i18n.all : (mem.targetUserId || '');
    },
    memoryPersonaDirty() {
      return ['memoryPersona', 'reconcilePersona']
        .some(key => (this.memoryOptions[key] || '') !== (this.savedMemoryOptions[key] || ''));
    },
    memoryLastRecalled(mem) {
      return mem.lastUsedAt ? this.$root.formatDateTime(mem.lastUsedAt) : this.i18n.agentStudioMemoryNeverRecalled;
    },
    async saveMemory(mem) {
      const draft = this.memoryDrafts[mem.id];
      if (!draft) return;
      if (!String(draft.memoryText || '').trim()) {
        this.$root.showError(this.i18n.agentStudioMemoryTextRequired);
        return;
      }
      this.$root.startLoading();
      try {
        await this.$root.papi.put('assistant/memories/' + encodeURIComponent(mem.id), this.memoryPayload(draft));
        await this.loadMemories();
      } catch (error) {
        this.$root.showError(error);
      } finally {
        this.$root.stopLoading();
      }
    },
    async removeMemory(mem) {
      this.$root.startLoading();
      try {
        await this.$root.papi.delete('assistant/memories/' + encodeURIComponent(mem.id));
        await this.loadMemories();
      } catch (error) {
        this.$root.showError(error);
      } finally {
        this.$root.stopLoading();
      }
    },
    showAddMemory() {
      this.newMemory = { memoryText: '', scope: 'user', targetUserId: '' };
      this.createMemoryDialog = true;
    },
    async saveNewMemory() {
      if (!String(this.newMemory.memoryText || '').trim()) {
        this.$root.showError(this.i18n.agentStudioMemoryTextRequired);
        return;
      }
      this.$root.startLoading();
      try {
        await this.$root.papi.post('assistant/memories', this.memoryPayload(this.newMemory));
        this.createMemoryDialog = false;
        this.tab = 'memories';
        this.memoryPage = 1;
        await this.loadMemories();
      } catch (error) {
        this.$root.showError(error);
      } finally {
        this.$root.stopLoading();
      }
    },
    onChangeUseMemoryScanner(newValue) {
      if (newValue) {
        this.scanHistoricalDialog = true;
      }
    },
    cancelScanHistorical() {
      this.scanHistoricalDialog = false;
      this.memoryOptions.useMemoryScanner = false;
    },
    saveScanHistorical(scanHistorical) {
      this.scanHistoricalDialog = false;
      if (scanHistorical) {
        this.memoryOptions.dontScanBefore = '';
      } else {
        this.memoryOptions.dontScanBefore = new Date().toISOString();
      }
    }
  }
}});
