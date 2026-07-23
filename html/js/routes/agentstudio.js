// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

// NOTE: This page is a read-only view of the assistant's agents and skills. The
// data is pulled from the assistant client parameters (/connect/info) and is not
// editable here; agent management is a follow-up (see the advanced Agent Studio).

loadPageTemplate('page-agentstudio', 'pages/agentstudio.html');

routes.push({ path: '/agentstudio', name: 'agentstudio', component: {
  template: '#page-agentstudio',
  data() { return {
    i18n: this.$root.i18n,
    tab: 'agents',

    // Gating: the page renders only once the assistant client parameters have
    // loaded, and only when the assistant is enabled (+ licensed) and running in
    // agentic mode. Mirrors the aimetrics/assistant pages.
    paramsLoaded: false,
    assistantEnabled: false,
    agentic: false,

    sortByAgents: [{ key: 'name', order: 'asc' }],
    sortBySkills: [{ key: 'name', order: 'asc' }],
    expandedAgents: [],
    expandedSkills: [],
    // Per-row active sub-tab, keyed by row id (mirrors the alerts page's activeTabs).
    agentTabs: {},
    skillTabs: {},
    itemsPerPage: 10,
    itemsPerPageOptions: [10, 50, 250, 1000],

    agentHeaders: [
      { title: '', value: 'expand', sortable: false, width: '48px' },
      { title: this.$root.i18n.agentStudioName, value: 'name' },
      { title: this.$root.i18n.agentStudioRole, value: 'role' },
      { title: this.$root.i18n.agentStudioModel, value: 'model' },
      { title: this.$root.i18n.agentStudioSkills, value: 'skills', sortable: false },
      { title: this.$root.i18n.agentStudioDelegatesTo, value: 'canDelegateTo', sortable: false },
    ],
    skillHeaders: [
      { title: '', value: 'expand', sortable: false, width: '48px' },
      { title: this.$root.i18n.agentStudioSkill, value: 'name' },
      { title: this.$root.i18n.agentStudioToolsUnlocked, value: 'tools', sortable: false },
      { title: this.$root.i18n.agentStudioUsedBy, value: 'usedBy', sortable: false },
    ],

    // Models an agent can be mapped to, from assistant.availableModels
    // (/connect/info). Populated in initAssistant.
    models: [],

    // Skill catalog, from assistant.availableSkills. Populated in initAssistant.
    skills: [],

    // Agent definitions, from the assistant client parameters (availableAgents +
    // agentMapping). Populated in initAssistant.
    agents: [],
  }},
  computed: {
    agentNames() {
      return this.agents.map(a => a.name);
    },
  },
  watch: {
    '$route': 'reload',
    'sortByAgents': 'saveLocalSettings',
    'sortBySkills': 'saveLocalSettings',
    'itemsPerPage': 'saveLocalSettings',
  },
  mounted() {
    this.reload();
  },
  methods: {
    // reload pulls the assistant client parameters (models, skills, agents) and
    // renders them read-only. Runs on mount, on navigation, and on refresh.
    reload() {
      this.$root.startLoading();
      this.$root.loadParameters('assistant', this.initAssistant);
    },
    initAssistant(params) {
      params = params || {};
      this.assistantEnabled = params.enabled && this.$root.isLicensed('oai');
      this.agentic = params.agentic || false;
      this.paramsLoaded = true;
      if (this.assistantEnabled && this.agentic) {
        this.models = (params.availableModels || []).map(m => ({
          displayName: m.displayName,
          adapter: m.adapter,
          contextWindow: m.contextLimitLarge || m.contextLimitSmall || 0,
        }));
        this.skills = (params.availableSkills || []).map(s => ({
          id: s.name,
          name: s.name,
          tools: s.tools || [],
        }));
        this.skills.forEach(s => { this.skillTabs[s.id] = 'tools'; });
        this.setAgents(this.agentsFromParams(params));
        this.loadLocalSettings();
      }
      this.$root.stopLoading();
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
    },
    loadLocalSettings() {
      if (localStorage['settings.agentstudio.sortByAgents']) this.sortByAgents[0].key = localStorage['settings.agentstudio.sortByAgents'];
      if (localStorage['settings.agentstudio.sortDescAgents']) this.sortByAgents[0].order = localStorage['settings.agentstudio.sortDescAgents'];

      if (localStorage['settings.agentstudio.sortBySkills']) this.sortBySkills[0].key = localStorage['settings.agentstudio.sortBySkills'];
      if (localStorage['settings.agentstudio.sortDescSkills']) this.sortBySkills[0].order = localStorage['settings.agentstudio.sortDescSkills'];

      if (localStorage['settings.agentstudio.itemsPerPage']) this.itemsPerPage = parseInt(localStorage['settings.agentstudio.itemsPerPage']);
    },
    // agentsFromParams builds the read-only rows from the server's current agent
    // set (availableAgents + agentMapping). Personas are not exposed via params
    // (AgentParameters.Prompt is server-side only), so they are not shown here.
    agentsFromParams(params) {
      const mapping = params.agentMapping || {};
      // Map each model's displayName to its serving adapter (provider) so the
      // model subtab can show where the agent's model runs.
      const modelProviders = new Map((params.availableModels || []).map(m => [m.displayName, m.adapter]));
      return (params.availableAgents || []).map(a => {
        const model = mapping[a.name] || '';
        return {
          id: a.name,
          name: a.name,
          isOrchestrator: !!a.isOrchestrator,
          model: model,
          provider: modelProviders.get(model) || '',
          description: a.agentDescription || '',
          allowedSkills: a.allowedSkills || [],
          canDelegateTo: a.canDelegateTo || [],
        };
      });
    },
    setAgents(agents) {
      this.agents = agents;
      this.agents.forEach(a => { this.agentTabs[a.id] = 'identity'; });
    },
    roleLabel(agent) {
      return agent.isOrchestrator ? this.i18n.agentStudioOrchestrator : this.i18n.agentStudioSpecialist;
    },
    skillUsedBy(skillName) {
      return this.agents.filter(a => a.allowedSkills.includes(skillName)).map(a => a.name);
    },
  }
}});
