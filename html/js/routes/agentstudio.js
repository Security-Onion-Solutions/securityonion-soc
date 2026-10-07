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
const AUTOMATION_TICK_SETTING_ID = 'soc.config.server.modules.assistant.automationSettings.tickIntervalSeconds';
const ALERT_TRIAGE_EPOCH_SETTING_ID = 'soc.config.server.modules.assistant.automationSettings.alertTriageEpoch';

// Matches the setting's validation in Config.
const ALERT_TRIAGE_EPOCH_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

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
  memoryExtractBatchSize: 'soc.config.server.modules.assistant.memoryExtractBatchSize',
  maxMemoryRetries: 'soc.config.server.modules.assistant.maxMemoryRetries',
  memoryModel: 'soc.config.server.modules.assistant.memoryModel',
  embedModel: 'soc.config.server.modules.assistant.embedModel',
  reconcileModel: 'soc.config.server.modules.assistant.reconcileModel',
  memoryPersona: 'soc.config.server.modules.assistant.memoryPersona',
  reconcilePersona: 'soc.config.server.modules.assistant.reconcilePersona',
  dontScanBefore: 'soc.config.server.modules.assistant.dontScanBefore',
};

// Custom automations are unsupported for now; the API still accepts them.
const AUTOMATIONS_READ_ONLY = true;

// Matches the server's limit.
const AUTOMATION_NAME_MAX_LENGTH = 100;

const AUTOMATION_RUNS_PAGE = 20;

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
    createAutomationDialog: false,
    scanHistoricalDialog: false,
    newAgent: {},
    newSkill: {},
    newMemory: {},
    newAutomation: {},

    automationsReadOnly: AUTOMATIONS_READ_ONLY,
    automations: [],
    expandedAutomations: [],

    confirmDeleteDialog: false,
    // { kind: 'agent' | 'automation', item }
    deleteTarget: null,
    creatorNames: {},
    // id -> { runs, backlog, hasMore, loading }
    automationRuns: {},
    automationTabs: {},
    automationDrafts: {},
    sortByAutomations: [{ key: 'displayName', order: 'asc' }],

    memoryEnabled: false,
    memories: [],
    memoryTotal: 0,
    memoryScope: 'all',
    memorySearch: '',
    memoryPage: 1,
    memoryItemsPerPage: 10,
    runItemsPerPage: 10,
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
    automationTickSeconds: 0,
    alertTriageEpoch: '',
    savedAutomationTickSeconds: 0,
    savedAlertTriageEpoch: '',
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

    automationHeaders: [
      { title: '', value: 'expand', sortable: false, width: '48px' },
      { title: this.$root.i18n.agentStudioName, value: 'displayName' },
      { title: this.$root.i18n.kind, value: 'automationKind', width: '160px' },
      { title: this.$root.i18n.agentStudioAutomationInterval, value: 'intervalSeconds', width: '130px' },
      { title: this.$root.i18n.agentStudioAutomationAgent, value: 'agent' },
      { title: this.$root.i18n.status, value: 'status', sortable: false, width: '200px' },
      { title: this.$root.i18n.agentStudioEnabled, value: 'enabled', sortable: false, width: '110px' },
    ],
    runHeaders: [
      // Lowercase key: the browser lowercases the template's #item.<key> slot name.
      { title: this.$root.i18n.startTime, value: 'startTime', key: 'starttime', sortable: false },
      { title: this.$root.i18n.stateDone, value: 'done', key: 'done', sortable: false },
      { title: this.$root.i18n.stateFailed, value: 'failed', key: 'failed', sortable: false },
      { title: this.$root.i18n.agentStudioAutomationOutcome, value: 'state', key: 'state', sortable: false },
      { title: this.$root.i18n.actions, value: 'actions', key: 'actions', sortable: false, width: '90px' },
    ],
    automationKinds: [],

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
    // Lazy: automations need config/read.
    tab(value) {
      if (value === 'automations') this.loadAutomations();
    },
    'sortByAgents': 'saveLocalSettings',
    'sortBySkills': 'saveLocalSettings',
    'sortByAutomations': 'saveLocalSettings',
    'itemsPerPage': 'saveLocalSettings',
    'memoryItemsPerPage': 'saveLocalSettings',
    'runItemsPerPage': 'saveLocalSettings',
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
        this.applyRouteQuery();
      }
      this.$root.stopLoading();
    },
    // ?tab=automations&automation=<id> deep-links an automation's editor (used by Agent Monitor).
    applyRouteQuery() {
      const query = (this.$route || {}).query || {};
      if (query.tab && this.agentic) this.tab = query.tab;
    },
    openRouteAutomation() {
      const query = (this.$route || {}).query || {};
      if (!query.automation) return;
      const row = this.automations.find(a => a.id === query.automation);
      if (!row) return;
      this.tab = 'automations';
      if (!this.expandedAutomations.includes(row.id)) {
        // Same draft snapshot as the chevron, so edits don't touch the committed row.
        this.automationDrafts[row.id] = JSON.parse(JSON.stringify(row));
        this.expandedAutomations = this.expandedAutomations.concat([row.id]);
      }
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
      this.automationKinds = params.availableAutomationKinds || [];
    },
    // Only adopt server values while the dialog is closed, so a push mid-edit does
    // not overwrite what the admin is typing.
    applyLimits(params) {
      this.savedMaxDelegationDepth = params.maxDelegationDepth || 0;
      this.savedMaxSubSessionTokens = params.maxSubSessionTokens || 0;
      this.savedAutomationTickSeconds = params.automationTickIntervalSeconds || 0;
      this.savedAlertTriageEpoch = params.alertTriageEpoch || '';
      this.savedMemoryOptions = Object.assign({}, params.memoryParams || {});
      this.staleMemoryCount = (params.memoryParams || {}).staleMemoryCount || 0;
      if (!this.showOptionsDialog) {
        this.resetOptions();
      }
    },
    resetOptions() {
      this.maxDelegationDepth = this.savedMaxDelegationDepth;
      this.maxSubSessionTokens = this.savedMaxSubSessionTokens;
      this.automationTickSeconds = this.savedAutomationTickSeconds;
      this.alertTriageEpoch = this.savedAlertTriageEpoch;
      this.memoryOptions = Object.assign({}, this.savedMemoryOptions);
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
      this.saveSetting('sortByAutomations', this.sortByAutomations[0].key, 'displayName');
      this.saveSetting('sortDescAutomations', this.sortByAutomations[0].order, 'asc');
      this.saveSetting('itemsPerPage', this.itemsPerPage, 10);
      this.saveSetting('memoryItemsPerPage', this.memoryItemsPerPage, 10);
      this.saveSetting('runItemsPerPage', this.runItemsPerPage, 10);
    },
    loadLocalSettings() {
      if (localStorage['settings.agentstudio.sortByAgents']) this.sortByAgents[0].key = localStorage['settings.agentstudio.sortByAgents'];
      if (localStorage['settings.agentstudio.sortDescAgents']) this.sortByAgents[0].order = localStorage['settings.agentstudio.sortDescAgents'];

      if (localStorage['settings.agentstudio.sortBySkills']) this.sortBySkills[0].key = localStorage['settings.agentstudio.sortBySkills'];
      if (localStorage['settings.agentstudio.sortDescSkills']) this.sortBySkills[0].order = localStorage['settings.agentstudio.sortDescSkills'];

      if (localStorage['settings.agentstudio.sortByAutomations']) this.sortByAutomations[0].key = localStorage['settings.agentstudio.sortByAutomations'];
      if (localStorage['settings.agentstudio.sortDescAutomations']) this.sortByAutomations[0].order = localStorage['settings.agentstudio.sortDescAutomations'];

      if (localStorage['settings.agentstudio.itemsPerPage']) this.itemsPerPage = parseInt(localStorage['settings.agentstudio.itemsPerPage']);
      if (localStorage['settings.agentstudio.memoryItemsPerPage']) this.memoryItemsPerPage = parseInt(localStorage['settings.agentstudio.memoryItemsPerPage']);
      if (localStorage['settings.agentstudio.runItemsPerPage']) this.runItemsPerPage = parseInt(localStorage['settings.agentstudio.runItemsPerPage']);
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
          maxConcurrentInstances: a.maxConcurrentInstances || 0,
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
    chatWithAgentLink(agent) {
      return { name: 'assistant', query: { agent: agent.name } };
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
          maxConcurrentInstances: a.maxConcurrentInstances || 0,
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
        maxConcurrentInstances: a.maxConcurrentInstances || 0,
      };
    },
    skillPayload(s) {
      if (s.isSystem) {
        return { name: s.name, enabled: !!s.enabled, persona: s.persona || '' };
      }
      return { name: s.name, enabled: !!s.enabled, tools: s.tools || [], persona: s.persona || '' };
    },
    showOptions() {
      this.resetOptions();
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
        this.automationTickSeconds !== this.savedAutomationTickSeconds ||
        this.alertTriageEpoch !== this.savedAlertTriageEpoch ||
        this.dirtyMemoryOptions().length > 0;
    },
    automationTickValid() {
      return Number.isInteger(this.automationTickSeconds) && this.automationTickSeconds > 0;
    },
    alertTriageEpochValid() {
      return ALERT_TRIAGE_EPOCH_PATTERN.test(this.alertTriageEpoch || '');
    },
    optionsValid() {
      return !this.agentic || (this.automationTickValid() && this.alertTriageEpochValid());
    },
    automationIntervalHelp() {
      return this.i18n.agentStudioAutomationIntervalHelp.replace('{seconds}', this.savedAutomationTickSeconds || 60);
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
        if (this.automationTickSeconds !== this.savedAutomationTickSeconds) {
          await this.saveLimit(AUTOMATION_TICK_SETTING_ID, this.automationTickSeconds);
        }
        if (this.alertTriageEpoch !== this.savedAlertTriageEpoch) {
          await this.saveLimit(ALERT_TRIAGE_EPOCH_SETTING_ID, this.alertTriageEpoch);
        }
        for (const [settingId, value] of this.dirtyMemoryOptions()) {
          await this.saveLimit(settingId, value);
        }
        this.savedMaxDelegationDepth = this.maxDelegationDepth;
        this.savedMaxSubSessionTokens = this.maxSubSessionTokens;
        this.savedAutomationTickSeconds = this.automationTickSeconds;
        this.savedAlertTriageEpoch = this.alertTriageEpoch;
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
      if (await this.deleteRow('agents', agent.name)) {
        this.expandedAgents = this.expandedAgents.filter(id => id !== agent.id);
        delete this.agentDrafts[agent.id];
        // Mirrors the server's delegate-list cleanup.
        const kept = this.agents.filter(a => a.id !== agent.id);
        this.setAgents(this.withoutReference(kept, 'canDelegateTo', agent.name));
      }
    },
    async removeSkill(skill) {
      if (skill.isSystem) return;
      if (await this.deleteRow('skills', skill.name)) {
        this.setSkills(this.skills.filter(s => s.id !== skill.id));
        this.expandedSkills = this.expandedSkills.filter(id => id !== skill.id);
        delete this.skillDrafts[skill.id];
        this.setAgents(this.withoutReference(this.agents, 'allowedSkills', skill.name));
      }
    },
    // Drafts too, so an open editor can't save the deleted reference back.
    withoutReference(agents, field, name) {
      Object.values(this.agentDrafts).forEach(d => { d[field] = d[field].filter(n => n !== name); });
      return agents.map(a => Object.assign({}, a, { [field]: a[field].filter(n => n !== name) }));
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
        maxConcurrentInstances: agent.maxConcurrentInstances || 0,
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
        maxConcurrentInstances: 0,
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
    setAutomations(automations) {
      this.automations = automations.slice();
      this.automations.forEach(a => { if (!this.automationTabs[a.id]) this.automationTabs[a.id] = 'general'; });
    },
    async loadAutomations() {
      if (!this.agentic) return;
      this.$root.startLoading();
      try {
        const response = await this.$root.papi.get('assistant/automations');
        this.setAutomations(response.data || []);
        this.openRouteAutomation();
      } catch (error) {
        this.$root.showError(error);
      } finally {
        this.$root.stopLoading();
      }
      this.automations.forEach(a => this.loadAutomationRuns(a));
    },
    async loadAutomationRuns(automation, more = false) {
      const current = this.automationRuns[automation.id];
      if (current && current.loading) return;
      const loaded = current ? current.runs : [];
      this.automationRuns[automation.id] = Object.assign({ runs: [] }, current, { loading: true });
      try {
        const response = await this.$root.papi.get('assistant/automations/' + encodeURIComponent(automation.id) + '/runs', {
          params: { limit: AUTOMATION_RUNS_PAGE, offset: more ? loaded.length : 0 },
        });
        const history = response.data || {};
        this.automationRuns[automation.id] = {
          runs: (more ? loaded : []).concat(history.runs || []),
          backlog: history.backlog || {},
          hasMore: !!history.hasMore,
        };
      } catch (error) {
        if (current) this.automationRuns[automation.id] = current;
        else delete this.automationRuns[automation.id];
        this.$root.showError(error);
      }
    },
    automationHistory(automation) {
      return this.automationRuns[automation.id] || { runs: [] };
    },
    latestAutomationRun(automation) {
      return this.automationHistory(automation).runs[0] || null;
    },
    runItemCount(run, state) {
      return (run.itemCounts || {})[state] || 0;
    },
    // Run History only lists finished runs.
    runMonitorLink(run) {
      if (['succeeded', 'failed'].includes(run.state)) return { name: 'agentmonitor', query: { run: run.id } };
      return { name: 'agentmonitor' };
    },
    automationStatus(automation) {
      const history = this.automationRuns[automation.id];
      if (!history || (history.loading && !history.runs.length)) return '';
      const run = this.latestAutomationRun(automation);
      return run && ['queued', 'running', 'failed'].includes(run.state) ? run.state : 'idle';
    },
    automationBacklog(automation) {
      const backlog = this.automationHistory(automation).backlog || {};
      return ['pending', 'running', 'applying'].filter(state => backlog[state]).map(state => ({ state, count: backlog[state] }));
    },
    automationAgentItems() {
      return this.agents.filter(a => a.enabled).map(a => a.name);
    },
    // Keeps a stale agent listed so the field doesn't read blank.
    automationAgentChoices(automation) {
      const items = this.automationAgentItems();
      if (automation.agent && !items.includes(automation.agent)) items.push(automation.agent);
      return items;
    },
    automationCreatorLabel(automation) {
      const id = automation.userId;
      if (!id) return '';
      if (this.creatorNames[id] === undefined) {
        this.creatorNames[id] = id;
        Promise.resolve(this.$root.getUserById(id))
          .then(user => { if (user) this.creatorNames[id] = this.$root.getUserDisplayName(user); })
          .catch(() => {});
      }
      return this.creatorNames[id];
    },
    automationKind(name) {
      return this.automationKinds.find(k => k.name === name) || null;
    },
    automationKindItems() {
      return this.automationKinds.map(k => ({ title: k.displayName, value: k.name }));
    },
    automationKindLabel(name) {
      const kind = this.automationKind(name);
      return kind ? kind.displayName : name;
    },
    automationKindFields(name) {
      const schema = ((this.automationKind(name) || {}).paramSchema || {}).json || {};
      const required = schema.required || [];
      const fields = Object.keys(schema.properties || {}).map(key => ({
        key: key,
        label: this.automationParamLabel(key),
        type: schema.properties[key].type,
        hint: schema.properties[key].description || '',
        default: schema.properties[key].default,
        required: required.includes(key),
      }));
      return fields.filter(f => f.required).concat(fields.filter(f => !f.required));
    },
    automationParamLabel(key) {
      const words = key.replace(/([a-z0-9])([A-Z])/g, '$1 $2');
      return words.charAt(0).toUpperCase() + words.slice(1);
    },
    automationParamDefaults(name) {
      const params = {};
      for (const field of this.automationKindFields(name)) {
        if (field.default !== undefined) params[field.key] = field.default;
        else params[field.key] = field.type === 'array' ? [] : '';
      }
      return params;
    },
    // Shaped for the server's strict decoder; blanks are dropped so the kind's defaults apply.
    automationParams(a) {
      const params = a.params || {};
      if (!this.automationKind(a.automationKind)) return Object.assign({}, params);
      const result = {};
      for (const field of this.automationKindFields(a.automationKind)) {
        let value = params[field.key];
        if (field.type === 'integer' || field.type === 'number') {
          if (value === '' || value === null || value === undefined) continue;
          value = Number(value);
        } else if (field.type === 'array') {
          value = (value || []).map(v => String(v).trim()).filter(v => v);
          if (!value.length) continue;
        } else if (typeof value === 'string') {
          value = value.trim();
          if (!value) continue;
        } else if (value === undefined) {
          continue;
        }
        result[field.key] = value;
      }
      return result;
    },
    // Mirrors the server's validation.
    automationValid(a) {
      const name = String(a.displayName || '').trim();
      if (!name || [...name].length > AUTOMATION_NAME_MAX_LENGTH) return false;
      if (!(Number(a.intervalSeconds) > 0) || !this.automationKind(a.automationKind)) return false;
      const agent = String(a.agent || '').trim();
      // A built-in's blank agent means its shipped one.
      if (!agent && !a.isSystem) return false;
      if (a.enabled && agent && !this.automationAgentItems().includes(agent)) return false;
      const params = this.automationParams(a);
      return this.automationKindFields(a.automationKind).every(f => !f.required || params[f.key] !== undefined);
    },
    formatInterval(seconds) {
      seconds = Number(seconds) || 0;
      if (seconds >= 3600 && seconds % 3600 === 0) return (seconds / 3600) + ' ' + this.i18n.hours;
      if (seconds >= 60 && seconds % 60 === 0) return (seconds / 60) + ' ' + this.i18n.minutes;
      return seconds + ' ' + this.i18n.seconds;
    },
    // Estimate only; the scheduler tick and in-progress runs shift it.
    automationNextRun(automation) {
      const run = this.latestAutomationRun(automation);
      if (!automation.enabled || !run || !run.startTime) return '';
      return this.$root.formatDateTime(new Date(new Date(run.startTime).getTime() + automation.intervalSeconds * 1000).toISOString());
    },
    automationLastRun(automation) {
      const run = this.latestAutomationRun(automation);
      return run && run.startTime ? this.$root.formatDateTime(run.startTime) : this.i18n.never;
    },
    automationStatusLabel(status) {
      return ({
        idle: this.i18n.stateIdle,
        pending: this.i18n.statePending,
        queued: this.i18n.stateQueued,
        running: this.i18n.stateRunning,
        applying: this.i18n.stateApplying,
        succeeded: this.i18n.completed,
        failed: this.i18n.stateFailed,
      })[status] || status;
    },
    automationStatusColor(status) {
      return ({ queued: 'warning', running: 'primary', failed: 'error' })[status] || '';
    },
    // isSystem must match the stored automation or the server refuses the save.
    automationPayload(a) {
      return {
        displayName: String(a.displayName || '').trim(),
        automationKind: a.automationKind,
        agent: a.agent || '',
        enabled: !!a.enabled,
        intervalSeconds: Number(a.intervalSeconds) || 0,
        params: this.automationParams(a),
        isSystem: !!a.isSystem,
      };
    },
    // Reloads after writing: a params change cancels queued work, and edits aren't pushed.
    async updateAutomation(updated) {
      this.$root.startLoading();
      try {
        await this.$root.papi.put('assistant/automations/' + encodeURIComponent(updated.id), this.automationPayload(updated));
        await this.loadAutomations();
        return true;
      } catch (error) {
        this.$root.showError(error);
        return false;
      } finally {
        this.$root.stopLoading();
      }
    },
    async createAutomation(automation) {
      this.$root.startLoading();
      try {
        await this.$root.papi.post('assistant/automations', this.automationPayload(automation));
        await this.loadAutomations();
        return true;
      } catch (error) {
        this.$root.showError(error);
        return false;
      } finally {
        this.$root.stopLoading();
      }
    },
    draftForAutomation(automation) {
      return this.automationDrafts[automation.id] || automation;
    },
    onToggleAutomation(automation, toggleExpand, internalItem) {
      if (this.expandedAutomations.includes(automation.id)) {
        delete this.automationDrafts[automation.id];
      } else {
        this.automationDrafts[automation.id] = JSON.parse(JSON.stringify(automation));
        this.loadAutomationRuns(automation);
      }
      toggleExpand(internalItem);
    },
    automationDirty(item) {
      const draft = this.automationDrafts[item.id];
      if (!draft) return false;
      return JSON.stringify(this.automationPayload(draft)) !== JSON.stringify(this.automationPayload(item));
    },
    async saveAutomation(automation) {
      const draft = this.automationDrafts[automation.id];
      if (!draft || !this.automationValid(draft)) return;
      if (!(await this.updateAutomation(draft))) return;
      this.expandedAutomations = this.expandedAutomations.filter(id => id !== automation.id);
      delete this.automationDrafts[automation.id];
    },
    async toggleAutomationEnabled(automation) {
      // The server refuses saves for a kind it doesn't provide.
      if (!this.automationKind(automation.automationKind)) return;
      const updated = Object.assign({}, automation, { enabled: !automation.enabled });
      if (!this.automationValid(updated)) {
        this.$root.showError(this.i18n.agentStudioAutomationAgentUnavailable);
        return;
      }
      await this.updateAutomation(updated);
    },
    async removeAutomation(automation) {
      if (automation.isSystem) return;
      this.$root.startLoading();
      try {
        await this.$root.papi.delete('assistant/automations/' + encodeURIComponent(automation.id));
        this.expandedAutomations = this.expandedAutomations.filter(id => id !== automation.id);
        delete this.automationDrafts[automation.id];
        delete this.automationRuns[automation.id];
        await this.loadAutomations();
      } catch (error) {
        this.$root.showError(error);
      } finally {
        this.$root.stopLoading();
      }
    },
    async duplicateAutomation(automation) {
      await this.createAutomation({
        displayName: this.copyName(automation.displayName, this.automations.map(a => a.displayName)),
        automationKind: automation.automationKind, isSystem: false, enabled: false,
        agent: automation.agent || '', intervalSeconds: automation.intervalSeconds || 0,
        params: JSON.parse(JSON.stringify(automation.params || {})),
      });
    },

    confirmDelete(kind, item) {
      this.deleteTarget = { kind, item };
      this.confirmDeleteDialog = true;
    },
    cancelDelete() {
      this.confirmDeleteDialog = false;
      this.deleteTarget = null;
    },
    async performDelete() {
      const target = this.deleteTarget;
      this.cancelDelete();
      if (!target) return;
      if (target.kind === 'agent') await this.removeAgent(target.item);
      else if (target.kind === 'skill') await this.removeSkill(target.item);
      else if (target.kind === 'automation') await this.removeAutomation(target.item);
    },
    deleteTitle() {
      return ({
        agent: this.i18n.agentStudioDeleteAgentTitle,
        skill: this.i18n.agentStudioDeleteSkillTitle,
        automation: this.i18n.agentStudioDeleteAutomationTitle,
      })[this.deleteTarget.kind];
    },
    deleteConfirmText() {
      return ({
        agent: this.i18n.agentStudioDeleteAgentConfirm,
        skill: this.i18n.agentStudioDeleteSkillConfirm,
        automation: this.i18n.agentStudioDeleteAutomationConfirm,
      })[this.deleteTarget.kind];
    },
    showAddAutomation() {
      const kind = (this.automationKinds[0] || {}).name || '';
      this.newAutomation = {
        displayName: '',
        automationKind: kind,
        isSystem: false,
        enabled: false,
        agent: this.automationAgentItems()[0] || '',
        intervalSeconds: 300,
        params: this.automationParamDefaults(kind),
      };
      this.createAutomationDialog = true;
    },
    onNewAutomationKind(kind) {
      this.newAutomation.automationKind = kind;
      this.newAutomation.params = this.automationParamDefaults(kind);
    },
    async saveNewAutomation() {
      if (!this.automationValid(this.newAutomation)) return;
      if (!(await this.createAutomation(this.newAutomation))) return;
      this.createAutomationDialog = false;
      this.tab = 'automations';
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
