// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

loadPageTemplate('component-destinations-manager', 'pages/destinations-manager.html');

components.push({
  name: 'destinations-manager',
  component: {
    template: '#component-destinations-manager',
    props: {
      autoLoad: {
        type: Boolean,
        default: true,
      },
    },
    emits: ['destinations-loaded', 'destination-saved', 'destination-deleted'],
    data() {
      return {
        i18n: this.$root?.i18n || {},
        destinations: [],
        schedules: [],
        now: new Date(),
        activeEvaluationInterval: null,
        destinationHeaders: [
          { title: this.$root?.i18n?.name, value: 'name' },
          { title: this.$root?.i18n?.destinationType, value: 'type' },
          { title: this.$root?.i18n?.severities, value: 'severities', sortable: false },
          { title: this.$root?.i18n?.activationSchedule, value: 'schedule', sortable: false },
          { title: this.$root?.i18n?.status, value: 'status', sortable: false },
          { title: this.$root?.i18n?.actions, value: 'actions', sortable: false, align: 'end' },
        ],
        destinationSortBy: [{ key: 'name', order: 'asc' }],
        destinationItemsPerPage: 10,
        destinationItemsPerPageOptions: [10, 25, 50, 100],
        destinationSearch: '',
        destinationDialog: false,
        deleteDestinationDialog: false,
        destinationToDelete: null,
        testingDestinationId: null,
        isTestingForm: false,
        testResult: null,
        form: {
          isEdit: false,
          valid: false,
          id: '',
          name: '',
          type: 'soc',
          enabled: true,
          scheduleIds: [],
          severities: [],
          params: {},
        },
        channelTypeOptions: [
          { title: this.$root?.i18n?.builtinSOCNotifications, value: 'soc' },
        ],
        severityOptions: [
          { title: this.$root?.i18n?.severityCritical, value: 'critical' },
          { title: this.$root?.i18n?.severityHigh, value: 'high' },
          { title: this.$root?.i18n?.severityMedium, value: 'medium' },
          { title: this.$root?.i18n?.severityLow, value: 'low' },
          { title: this.$root?.i18n?.severityInfo, value: 'info' },
        ],
      };
    },
    computed: {
      scheduleOptions() {
        return (this.schedules || []).map((s) => {
          const statusSuffix = s.enabled !== false
            ? ` (${this.$root?.i18n?.enabled})`
            : ` (${this.$root?.i18n?.disabled})`;
          return {
            title: `${s.name}${statusSuffix}`,
            value: s.id,
          };
        });
      },
    },
    created() {
      if (this.autoLoad) {
        this.loadData();
      }
    },
    mounted() {
      this.now = new Date();
      this.activeEvaluationInterval = setInterval(() => {
        this.now = new Date();
      }, 60000);
    },
    unmounted() {
      if (this.activeEvaluationInterval) {
        clearInterval(this.activeEvaluationInterval);
        this.activeEvaluationInterval = null;
      }
    },
    methods: {
      async loadData() {
        this.$root?.startLoading?.();
        await Promise.all([this.getDestinations(), this.getSchedules()]);
        this.$root?.stopLoading?.();
      },
      async getDestinations() {
        try {
          const response = await this.$root.papi.get('notifications/destinations');
          this.destinations = response && response.data ? response.data : (response || []);
          if (typeof this.$emit === 'function') {
            this.$emit('destinations-loaded', this.destinations);
          }
        } catch (error) {
          if (this.$root) {
            this.$root.error = true;
            this.$root.errorMessage = error?.response?.data?.message || error?.message || (typeof error === 'string' ? error : this.i18n.unknownError);
          }
        }
      },
      async getSchedules() {
        try {
          const response = await this.$root.papi.get('schedules/');
          this.schedules = response && response.data ? response.data : (response || []);
        } catch (error) {
          // If schedules fail to load, proceed with empty list
          this.schedules = [];
        }
      },
      getChannelIcon(type) {
        switch (type) {
          case 'soc':
            return 'fa-envelope';
          case 'smtp':
            return 'fa-at';
          case 'slack':
            return 'fab fa-slack';
          case 'matrix':
            return 'fa-comments';
          case 'msteams':
            return 'fab fa-microsoft';
          case 'pagerduty':
            return 'fa-pager';
          case 'webhook':
            return 'fa-globe';
          default:
            return 'fa-envelope';
        }
      },
      getDestinationName(dest) {
        if (dest && typeof dest.name === 'string' && dest.name.trim() !== '') {
          return dest.name;
        }
        if (dest && dest.type === 'soc') {
          return this.i18n.builtinSOCNotifications;
        }
        return dest?.id || '';
      },
      getChannelLabel(type) {
        switch (type) {
          case 'soc':
            return this.i18n.builtinSOCNotifications;
          case 'smtp':
            return 'SMTP';
          case 'slack':
            return 'Slack';
          case 'matrix':
            return 'Matrix';
          case 'msteams':
            return 'MS Teams';
          case 'pagerduty':
            return 'PagerDuty';
          case 'webhook':
            return 'Webhook';
          default:
            return type;
        }
      },
      getSeverityColor(sev) {
        switch ((sev || '').toLowerCase()) {
          case 'critical':
            return 'red';
          case 'high':
            return 'orange';
          case 'medium':
            return 'amber';
          case 'low':
            return 'blue';
          case 'info':
          default:
            return 'grey';
        }
      },
      getSeverityLabel(sev) {
        switch ((sev || '').toLowerCase()) {
          case 'critical':
            return this.i18n.severityCritical;
          case 'high':
            return this.i18n.severityHigh;
          case 'medium':
            return this.i18n.severityMedium;
          case 'low':
            return this.i18n.severityLow;
          case 'info':
            return this.i18n.severityInfo;
          default:
            return sev;
        }
      },
      showAddDestination() {
        this.form = {
          isEdit: false,
          valid: false,
          id: '',
          name: '',
          type: 'soc',
          enabled: true,
          scheduleIds: [],
          severities: [],
          params: {},
        };
        this.testResult = null;
        this.destinationDialog = true;
      },
      showEditDestination(dest) {
        this.form = {
          isEdit: true,
          valid: true,
          id: dest.id,
          name: dest.name,
          type: dest.type || 'soc',
          enabled: dest.enabled !== false,
          scheduleIds: Array.isArray(dest.scheduleIds) ? [...dest.scheduleIds] : [],
          severities: Array.isArray(dest.severities) ? [...dest.severities] : [],
          params: dest.params ? JSON.parse(JSON.stringify(dest.params)) : {},
        };
        this.testResult = null;
        this.destinationDialog = true;
      },
      isDefaultDestination(dest) {
        return dest?.id === 'soc-bell';
      },
      showDeleteDestination(dest) {
        if (this.isDefaultDestination(dest)) {
          return;
        }
        this.destinationToDelete = dest;
        this.deleteDestinationDialog = true;
      },
      hideDeleteDestination() {
        this.destinationToDelete = null;
        this.deleteDestinationDialog = false;
      },
      async saveDestination() {
        if (!this.form.name) {
          return;
        }

        const payload = {
          id: this.form.id || undefined,
          name: this.form.name.trim(),
          type: this.form.type || 'soc',
          enabled: this.form.enabled !== false,
          scheduleIds: Array.isArray(this.form.scheduleIds) ? this.form.scheduleIds.filter(Boolean) : [],
          severities: Array.isArray(this.form.severities) ? this.form.severities : [],
          params: this.form.params || {},
        };

        this.$root?.startLoading?.();
        try {
          if (this.form.isEdit && this.form.id) {
            await this.$root.papi.put(`notifications/destinations/${encodeURIComponent(this.form.id)}`, payload);
          } else {
            await this.$root.papi.post('notifications/destinations', payload);
          }
          this.destinationDialog = false;
          await this.loadData();
          if (typeof this.$emit === 'function') {
            this.$emit('destination-saved', payload);
          }
        } catch (error) {
          if (this.$root) {
            this.$root.error = true;
            this.$root.errorMessage = error?.response?.data?.message || error?.message || (typeof error === 'string' ? error : this.i18n.unknownError);
          }
        } finally {
          this.$root?.stopLoading?.();
        }
      },
      async deleteDestination() {
        if (!this.destinationToDelete) {
          return;
        }

        const deletedId = this.destinationToDelete.id;
        this.$root?.startLoading?.();
        try {
          await this.$root.papi.delete(`notifications/destinations/${encodeURIComponent(deletedId)}`);
          this.hideDeleteDestination();
          await this.loadData();
          if (typeof this.$emit === 'function') {
            this.$emit('destination-deleted', deletedId);
          }
        } catch (error) {
          if (this.$root) {
            this.$root.error = true;
            this.$root.errorMessage = error?.response?.data?.message || error?.message || (typeof error === 'string' ? error : this.i18n.unknownError);
          }
        } finally {
          this.$root?.stopLoading?.();
        }
      },
      async testDestination(dest) {
        if (!dest || !dest.id) {
          return;
        }
        this.testingDestinationId = dest.id;
        try {
          await this.$root.papi.post(`notifications/destinations/${encodeURIComponent(dest.id)}/test`);
          if (this.$root) {
            this.$root.notificationMessage = this.i18n.testNotificationSent;
            this.$root.notification = true;
          }
        } catch (error) {
          if (this.$root) {
            this.$root.error = true;
            this.$root.errorMessage = error?.response?.data?.message || error?.message || (typeof error === 'string' ? error : this.i18n.testNotificationFailed);
          }
        } finally {
          this.testingDestinationId = null;
        }
      },
      async testCurrentForm() {
        if (!this.form.id) {
          return;
        }
        this.isTestingForm = true;
        this.testResult = null;
        try {
          await this.$root.papi.post(`notifications/destinations/${encodeURIComponent(this.form.id)}/test`);
          this.testResult = {
            success: true,
            message: this.i18n.testNotificationSent,
          };
        } catch (error) {
          this.testResult = {
            success: false,
            message: error?.response?.data?.message || error?.message || (typeof error === 'string' ? error : this.i18n.testNotificationFailed),
          };
        } finally {
          this.isTestingForm = false;
        }
      },
      getDestinationScheduleNames(dest) {
        if (!dest) return [];
        const ids = Array.isArray(dest.scheduleIds) ? dest.scheduleIds : [];
        return ids.map((id) => {
          const sched = (this.schedules || []).find((s) => s.id === id);
          return sched ? sched.name : id;
        });
      },
      isDestinationScheduleActive(dest) {
        if (!dest) return true;
        const ids = Array.isArray(dest.scheduleIds) ? dest.scheduleIds : [];
        if (ids.length === 0) {
          return true;
        }
        return ids.some((id) => {
          const sched = (this.schedules || []).find((s) => s.id === id);
          if (!sched) {
            return true;
          }
          return this.isScheduleActive(sched, this.now);
        });
      },
      isScheduleActive(schedule, atTime = new Date(), allSchedules = this.schedules, visited = new Set()) {
        if (!schedule) {
          return true;
        }
        if (schedule.enabled === false) {
          return false;
        }
        if ((!schedule.definitions || schedule.definitions.length === 0) && (!schedule.excludeScheduleIds || schedule.excludeScheduleIds.length === 0)) {
          return true;
        }

        if (visited.has(schedule.id)) {
          return false;
        }
        visited.add(schedule.id);

        let timezone = schedule.timezone || schedule.Timezone || 'UTC';
        let targetMoment;
        try {
          if (typeof moment !== 'undefined' && moment.tz) {
            targetMoment = moment(atTime).tz(timezone);
          }
        } catch (e) {
          timezone = 'UTC';
        }
        if (!targetMoment) {
          targetMoment = moment.utc(atTime);
        }

        let baseActive = false;
        if (!schedule.definitions || schedule.definitions.length === 0) {
          baseActive = true;
        } else {
          for (let i = 0; i < schedule.definitions.length; i++) {
            if (this.isDefinitionActive(schedule.definitions[i], targetMoment)) {
              baseActive = true;
              break;
            }
          }
        }

        if (!baseActive) {
          return false;
        }

        if (Array.isArray(schedule.excludeScheduleIds) && schedule.excludeScheduleIds.length > 0) {
          for (let i = 0; i < schedule.excludeScheduleIds.length; i++) {
            const excId = schedule.excludeScheduleIds[i];
            const excSched = (allSchedules || []).find((s) => s.id === excId);
            if (excSched && this.isScheduleActive(excSched, atTime, allSchedules, new Set(visited))) {
              return false;
            }
          }
        }

        return true;
      },
      isDefinitionActive(def, m) {
        if (!def) return false;
        const currentMins = m.hours() * 60 + m.minutes();
        let timeActive = false;
        if (def.allDay) {
          timeActive = true;
        } else {
          const [startH, startM] = (def.startTime || '00:00').split(':').map(Number);
          const [endH, endM] = (def.endTime || '24:00').split(':').map(Number);
          const startMins = startH * 60 + startM;
          const endMins = endH * 60 + endM;

          if (startMins <= endMins) {
            timeActive = currentMins >= startMins && currentMins < endMins;
          } else {
            timeActive = currentMins >= startMins || currentMins < endMins;
          }
        }

        if (!timeActive) {
          return false;
        }

        const weekday = m.day();
        const dayOfMonth = m.date();
        const month = m.month() + 1;

        if (def.type === 'daily') {
          return true;
        }
        if (def.type === 'weekly') {
          return Array.isArray(def.daysOfWeek) && def.daysOfWeek.includes(weekday);
        }
        if (def.type === 'monthly') {
          return this.matchesMonthlyOrAnnual(def, m, weekday, dayOfMonth);
        }
        if (def.type === 'annually') {
          if (Array.isArray(def.months) && def.months.length > 0 && !def.months.includes(month)) {
            return false;
          }
          return this.matchesMonthlyOrAnnual(def, m, weekday, dayOfMonth);
        }
        return false;
      },
      matchesMonthlyOrAnnual(def, m, weekday, dayOfMonth) {
        if (Array.isArray(def.daysOfMonth) && def.daysOfMonth.length > 0) {
          if (def.daysOfMonth.includes(dayOfMonth)) {
            return true;
          }
          if (def.daysOfMonth.includes(-1)) {
            const isLastDay = m.clone().add(1, 'day').month() !== m.month();
            if (isLastDay) {
              return true;
            }
          }
        }
        if (Array.isArray(def.weekNumbers) && def.weekNumbers.length > 0 && Array.isArray(def.daysOfWeek) && def.daysOfWeek.length > 0) {
          if (def.daysOfWeek.includes(weekday)) {
            const nth = Math.floor((dayOfMonth - 1) / 7) + 1;
            const isLast = m.clone().add(7, 'days').month() !== m.month();
            for (let i = 0; i < def.weekNumbers.length; i++) {
              const wn = def.weekNumbers[i];
              if (wn === nth || (wn === -1 && isLast)) {
                return true;
              }
            }
          }
        }
        return false;
      },
    },
  },
});
