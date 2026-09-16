// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

loadPageTemplate('component-schedules-manager', 'pages/schedules-manager.html');

components.push({
  name: 'schedules-manager',
  component: {
    template: '#component-schedules-manager',
    props: {
      autoLoad: {
        type: Boolean,
        default: true,
      },
    },
    emits: ['schedules-loaded', 'schedule-saved', 'schedule-deleted'],
    data() {
      const daysOfMonthList = [];
      for (let i = 1; i <= 31; i++) {
        daysOfMonthList.push({
          title: `${this.$root?.i18n?.dayPrefix || 'Day'} ${i}`,
          value: i,
        });
      }
      daysOfMonthList.push({
        title: this.$root?.i18n?.lastDayOfMonth || 'Last Day of Month',
        value: -1,
      });

      return {
        i18n: this.$root?.i18n || {},
        schedules: [],
        now: new Date(),
        activeEvaluationInterval: null,
        scheduleHeaders: [
          { title: this.$root?.i18n?.name || 'Name', value: 'name' },
          { title: this.$root?.i18n?.timezone || 'Timezone', value: 'timezone' },
          { title: this.$root?.i18n?.recurrenceSummary || 'Recurrence Summary', value: 'summary', sortable: false },
          { title: this.$root?.i18n?.status || 'Status', value: 'status', sortable: false },
          { title: this.$root?.i18n?.actions || 'Actions', value: 'actions', sortable: false, align: 'end' },
        ],
        scheduleSortBy: [{ key: 'name', order: 'asc' }],
        scheduleItemsPerPage: 10,
        scheduleItemsPerPageOptions: [10, 25, 50, 100],
        scheduleSearch: '',
        scheduleDialog: false,
        deleteScheduleDialog: false,
        scheduleToDelete: null,
        expandedDefinitions: [],
        form: {
          isEdit: false,
          valid: false,
          id: '',
          name: '',
          description: '',
          enabled: true,
          timezone: 'UTC',
          definitions: [],
          excludeScheduleIds: [],
        },
        timezones: [],
        daysOfWeekOptions: [
          { title: this.$root?.i18n?.daySunday || 'Sunday', value: 0 },
          { title: this.$root?.i18n?.dayMonday || 'Monday', value: 1 },
          { title: this.$root?.i18n?.dayTuesday || 'Tuesday', value: 2 },
          { title: this.$root?.i18n?.dayWednesday || 'Wednesday', value: 3 },
          { title: this.$root?.i18n?.dayThursday || 'Thursday', value: 4 },
          { title: this.$root?.i18n?.dayFriday || 'Friday', value: 5 },
          { title: this.$root?.i18n?.daySaturday || 'Saturday', value: 6 },
        ],
        weekNumberOptions: [
          { title: this.$root?.i18n?.ordinalFirst || '1st', value: 1 },
          { title: this.$root?.i18n?.ordinalSecond || '2nd', value: 2 },
          { title: this.$root?.i18n?.ordinalThird || '3rd', value: 3 },
          { title: this.$root?.i18n?.ordinalFourth || '4th', value: 4 },
          { title: this.$root?.i18n?.ordinalFifth || '5th', value: 5 },
          { title: this.$root?.i18n?.ordinalLast || 'Last', value: -1 },
        ],
        monthOptions: [
          { title: this.$root?.i18n?.monthJan || 'January', value: 1 },
          { title: this.$root?.i18n?.monthFeb || 'February', value: 2 },
          { title: this.$root?.i18n?.monthMar || 'March', value: 3 },
          { title: this.$root?.i18n?.monthApr || 'April', value: 4 },
          { title: this.$root?.i18n?.monthMay || 'May', value: 5 },
          { title: this.$root?.i18n?.monthJun || 'June', value: 6 },
          { title: this.$root?.i18n?.monthJul || 'July', value: 7 },
          { title: this.$root?.i18n?.monthAug || 'August', value: 8 },
          { title: this.$root?.i18n?.monthSep || 'September', value: 9 },
          { title: this.$root?.i18n?.monthOct || 'October', value: 10 },
          { title: this.$root?.i18n?.monthNov || 'November', value: 11 },
          { title: this.$root?.i18n?.monthDec || 'December', value: 12 },
        ],
        daysOfMonthOptions: daysOfMonthList,
        patternModeOptions: [
          { title: this.$root?.i18n?.onDay || 'On day of month', value: 'dayOfMonth' },
          { title: this.$root?.i18n?.onNthWeekday || 'On the Nth weekday', value: 'nthWeekday' },
        ],
        recurrenceTypes: [
          { title: this.$root?.i18n?.daily || 'Daily', value: 'daily' },
          { title: this.$root?.i18n?.weekly || 'Weekly', value: 'weekly' },
          { title: this.$root?.i18n?.monthly || 'Monthly', value: 'monthly' },
          { title: this.$root?.i18n?.annually || 'Annually', value: 'annually' },
        ],
      };
    },
    computed: {
      eligibleExceptionSchedules() {
        return this.getEligibleExceptionSchedules(this.form.id, this.schedules);
      },
    },
    created() {
      this.initTimezones();
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
      initTimezones() {
        if (typeof moment !== 'undefined' && moment.tz && typeof moment.tz.names === 'function') {
          this.timezones = moment.tz.names();
        } else {
          this.timezones = ['UTC', 'America/New_York', 'America/Chicago', 'America/Denver', 'America/Los_Angeles', 'Europe/London', 'Europe/Paris', 'Asia/Tokyo'];
        }
      },
      detectBrowserTimezone() {
        try {
          if (typeof moment !== 'undefined' && moment.tz && typeof moment.tz.guess === 'function') {
            this.form.timezone = moment.tz.guess();
          } else if (typeof Intl !== 'undefined' && Intl.DateTimeFormat) {
            this.form.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
          } else {
            this.form.timezone = 'UTC';
          }
        } catch (e) {
          this.form.timezone = 'UTC';
        }
      },
      async loadData() {
        this.$root?.startLoading?.();
        await this.getSchedules();
        this.$root?.stopLoading?.();
      },
      async getSchedules() {
        try {
          const response = await this.$root.papi.get('schedules/');
          this.schedules = response && response.data ? response.data : (response || []);
          if (typeof this.$emit === 'function') {
            this.$emit('schedules-loaded', this.schedules);
          }
        } catch (error) {
          if (this.$root) {
            this.$root.error = true;
            this.$root.errorMessage = error?.response?.data?.message || error?.message || (typeof error === 'string' ? error : (this.i18n.unknownError || 'An error occurred'));
          }
        }
      },
      normalizeDefinition(d) {
        const hasNth = Array.isArray(d.weekNumbers) && d.weekNumbers.length > 0;
        return {
          type: d.type || 'daily',
          mode: hasNth ? 'nthWeekday' : 'dayOfMonth',
          allDay: d.allDay || false,
          startTime: d.startTime || '08:00',
          endTime: d.endTime || '17:00',
          daysOfWeek: Array.isArray(d.daysOfWeek) && d.daysOfWeek.length > 0 ? [...d.daysOfWeek] : [1, 2, 3, 4, 5],
          daysOfMonth: Array.isArray(d.daysOfMonth) && d.daysOfMonth.length > 0 ? [...d.daysOfMonth] : [1],
          weekNumbers: Array.isArray(d.weekNumbers) && d.weekNumbers.length > 0 ? [...d.weekNumbers] : [1],
          months: Array.isArray(d.months) && d.months.length > 0 ? [...d.months] : [1],
        };
      },
      showAddSchedule() {
        this.form = {
          isEdit: false,
          valid: false,
          id: '',
          name: '',
          description: '',
          enabled: true,
          timezone: (typeof moment !== 'undefined' && moment.tz && typeof moment.tz.guess === 'function') ? moment.tz.guess() : 'UTC',
          excludeScheduleIds: [],
          definitions: [
            this.normalizeDefinition({
              type: 'weekly',
              allDay: false,
              startTime: '08:00',
              endTime: '17:00',
              daysOfWeek: [1, 2, 3, 4, 5],
            }),
          ],
        };
        this.expandedDefinitions = [0];
        this.scheduleDialog = true;
      },
      showEditSchedule(schedule) {
        this.form = {
          isEdit: true,
          valid: true,
          id: schedule.id,
          name: schedule.name,
          description: schedule.description || '',
          enabled: schedule.enabled !== false,
          timezone: schedule.timezone || 'UTC',
          excludeScheduleIds: Array.isArray(schedule.excludeScheduleIds) ? [...schedule.excludeScheduleIds] : [],
          definitions: (schedule.definitions || []).map((d) => this.normalizeDefinition(d)),
        };
        this.expandedDefinitions = (this.form.definitions || []).map((_, i) => i);
        this.scheduleDialog = true;
      },
      duplicateSchedule(schedule) {
        this.form = {
          isEdit: false,
          valid: true,
          id: '',
          name: `${schedule.name} ${this.i18n.scheduleCopySuffix || '(Copy)'}`,
          description: schedule.description || '',
          enabled: schedule.enabled !== false,
          timezone: schedule.timezone || 'UTC',
          excludeScheduleIds: Array.isArray(schedule.excludeScheduleIds) ? [...schedule.excludeScheduleIds] : [],
          definitions: (schedule.definitions || []).map((d) => this.normalizeDefinition(d)),
        };
        this.expandedDefinitions = (this.form.definitions || []).map((_, i) => i);
        this.scheduleDialog = true;
      },
      addDefinition() {
        this.form.definitions.push(this.normalizeDefinition({
          type: 'weekly',
          allDay: false,
          startTime: '08:00',
          endTime: '17:00',
          daysOfWeek: [1, 2, 3, 4, 5],
        }));
        this.expandedDefinitions.push(this.form.definitions.length - 1);
      },
      removeDefinition(index) {
        this.form.definitions.splice(index, 1);
      },
      canReach(fromId, targetId, allSchedules, visited = new Set()) {
        if (fromId === targetId) {
          return true;
        }
        if (visited.has(fromId)) {
          return false;
        }
        visited.add(fromId);

        const sched = (allSchedules || []).find((s) => s.id === fromId);
        if (!sched || !Array.isArray(sched.excludeScheduleIds)) {
          return false;
        }

        for (const childId of sched.excludeScheduleIds) {
          if (this.canReach(childId, targetId, allSchedules, visited)) {
            return true;
          }
        }

        return false;
      },
      getEligibleExceptionSchedules(currentScheduleId, allSchedules) {
        if (!Array.isArray(allSchedules)) {
          return [];
        }
        if (!currentScheduleId) {
          return allSchedules;
        }
        return allSchedules.filter((candidate) => {
          if (candidate.id === currentScheduleId) {
            return false;
          }
          return !this.canReach(candidate.id, currentScheduleId, allSchedules);
        });
      },
      async saveSchedule() {
        if (!this.form.name || !this.form.name.trim()) {
          return;
        }

        const payload = {
          name: this.form.name.trim(),
          description: (this.form.description || '').trim(),
          enabled: this.form.enabled,
          timezone: this.form.timezone || 'UTC',
          excludeScheduleIds: Array.isArray(this.form.excludeScheduleIds) ? this.form.excludeScheduleIds : [],
          definitions: (this.form.definitions || []).map((d) => {
            const def = {
              type: d.type || 'daily',
              allDay: d.allDay || false,
            };
            if (!d.allDay) {
              def.startTime = d.startTime || '00:00';
              def.endTime = d.endTime || '24:00';
            }
            if (d.type === 'weekly') {
              if (Array.isArray(d.daysOfWeek) && d.daysOfWeek.length > 0) {
                def.daysOfWeek = d.daysOfWeek;
              }
            } else if (d.type === 'monthly') {
              if (d.mode === 'nthWeekday') {
                if (Array.isArray(d.weekNumbers) && d.weekNumbers.length > 0) {
                  def.weekNumbers = d.weekNumbers;
                }
                if (Array.isArray(d.daysOfWeek) && d.daysOfWeek.length > 0) {
                  def.daysOfWeek = d.daysOfWeek;
                }
              } else {
                if (Array.isArray(d.daysOfMonth) && d.daysOfMonth.length > 0) {
                  def.daysOfMonth = d.daysOfMonth;
                }
              }
            } else if (d.type === 'annually') {
              if (Array.isArray(d.months) && d.months.length > 0) {
                def.months = d.months;
              }
              if (d.mode === 'nthWeekday') {
                if (Array.isArray(d.weekNumbers) && d.weekNumbers.length > 0) {
                  def.weekNumbers = d.weekNumbers;
                }
                if (Array.isArray(d.daysOfWeek) && d.daysOfWeek.length > 0) {
                  def.daysOfWeek = d.daysOfWeek;
                }
              } else {
                if (Array.isArray(d.daysOfMonth) && d.daysOfMonth.length > 0) {
                  def.daysOfMonth = d.daysOfMonth;
                }
              }
            }
            return def;
          }),
        };

        if (this.form.id) {
          payload.id = this.form.id.trim();
        }

        this.$root?.startLoading?.();
        try {
          if (this.form.isEdit) {
            await this.$root.papi.put(`schedules/${this.form.id}`, payload);
          } else {
            await this.$root.papi.post('schedules/', payload);
          }
          this.scheduleDialog = false;
          if (typeof this.$emit === 'function') {
            this.$emit('schedule-saved', payload);
          }
          await this.getSchedules();
        } catch (error) {
          if (this.$root) {
            this.$root.error = true;
            this.$root.errorMessage = error?.response?.data?.message || error?.message || (this.i18n.unknownError || 'An error occurred');
          }
        } finally {
          this.$root?.stopLoading?.();
        }
      },
      showDeleteSchedule(schedule) {
        this.scheduleToDelete = schedule;
        this.deleteScheduleDialog = true;
      },
      hideDeleteSchedule() {
        this.scheduleToDelete = null;
        this.deleteScheduleDialog = false;
      },
      async deleteSchedule() {
        if (!this.scheduleToDelete) return;
        const deletedId = this.scheduleToDelete.id;
        this.$root?.startLoading?.();
        try {
          await this.$root.papi.delete(`schedules/${deletedId}`);
          this.hideDeleteSchedule();
          if (typeof this.$emit === 'function') {
            this.$emit('schedule-deleted', deletedId);
          }
          await this.getSchedules();
        } catch (error) {
          if (this.$root) {
            this.$root.error = true;
            this.$root.errorMessage = error?.response?.data?.message || error?.message || (this.i18n.unknownError || 'An error occurred');
          }
        } finally {
          this.$root?.stopLoading?.();
        }
      },
      formatScheduleSummary(schedule) {
        if (!schedule) {
          return this.i18n.alwaysActive || 'Always Active';
        }
        let summary = '';
        if (!schedule.definitions || schedule.definitions.length === 0) {
          summary = this.i18n.alwaysActive || 'Always Active';
        } else {
          summary = schedule.definitions.map((d) => this.formatDefinitionSummary(d)).join('; ');
        }
        if (Array.isArray(schedule.excludeScheduleIds) && schedule.excludeScheduleIds.length > 0) {
          const exceptionNames = schedule.excludeScheduleIds
            .map((id) => {
              const match = (this.schedules || []).find((s) => s.id === id);
              return match ? match.name : id;
            })
            .join(', ');
          if (exceptionNames) {
            summary += ` (${this.i18n.exceptionsPrefix || 'Exceptions'}: ${exceptionNames})`;
          }
        }
        return summary;
      },
      formatDefinitionSummary(def) {
        if (!def) return '';
        const dayNames = [
          this.i18n.daySunAbbr || 'Sun',
          this.i18n.dayMonAbbr || 'Mon',
          this.i18n.dayTueAbbr || 'Tue',
          this.i18n.dayWedAbbr || 'Wed',
          this.i18n.dayThuAbbr || 'Thu',
          this.i18n.dayFriAbbr || 'Fri',
          this.i18n.daySatAbbr || 'Sat',
        ];
        const monthNames = [
          '',
          this.i18n.monthJanAbbr || 'Jan',
          this.i18n.monthFebAbbr || 'Feb',
          this.i18n.monthMarAbbr || 'Mar',
          this.i18n.monthAprAbbr || 'Apr',
          this.i18n.monthMayAbbr || 'May',
          this.i18n.monthJunAbbr || 'Jun',
          this.i18n.monthJulAbbr || 'Jul',
          this.i18n.monthAugAbbr || 'Aug',
          this.i18n.monthSepAbbr || 'Sep',
          this.i18n.monthOctAbbr || 'Oct',
          this.i18n.monthNovAbbr || 'Nov',
          this.i18n.monthDecAbbr || 'Dec',
        ];
        const ordinals = {
          1: this.i18n.ordinalFirst || '1st',
          2: this.i18n.ordinalSecond || '2nd',
          3: this.i18n.ordinalThird || '3rd',
          4: this.i18n.ordinalFourth || '4th',
          5: this.i18n.ordinalFifth || '5th',
          '-1': this.i18n.ordinalLast || 'Last',
        };
        const timeStr = def.allDay ? (this.i18n.allDay || 'All Day') : `${def.startTime} - ${def.endTime}`;

        if (def.type === 'daily') {
          return `${this.i18n.daily || 'Daily'} (${timeStr})`;
        }
        if (def.type === 'weekly') {
          const days = (def.daysOfWeek || []).map((d) => dayNames[d]).join(', ');
          return `${this.i18n.weekly || 'Weekly'}: ${days} (${timeStr})`;
        }
        if (def.type === 'monthly') {
          if (def.daysOfMonth && def.daysOfMonth.length > 0) {
            const doms = def.daysOfMonth.map((d) => (d === -1 ? (this.i18n.lastDayOfMonth || 'Last Day of Month') : `${this.i18n.dayPrefix || 'Day'} ${d}`)).join(', ');
            return `${this.i18n.monthly || 'Monthly'}: ${doms} (${timeStr})`;
          }
          if (def.weekNumbers && def.weekNumbers.length > 0 && def.daysOfWeek && def.daysOfWeek.length > 0) {
            const ords = def.weekNumbers.map((w) => ordinals[w] || `${w}`).join(', ');
            const days = def.daysOfWeek.map((d) => dayNames[d]).join(', ');
            return `${this.i18n.monthly || 'Monthly'}: ${ords} ${days} (${timeStr})`;
          }
          return `${this.i18n.monthly || 'Monthly'} (${timeStr})`;
        }
        if (def.type === 'annually') {
          const months = (def.months || []).map((m) => monthNames[m]).join(', ');
          if (def.daysOfMonth && def.daysOfMonth.length > 0) {
            const doms = def.daysOfMonth.map((d) => (d === -1 ? (this.i18n.lastDayOfMonth || 'Last Day of Month') : `${this.i18n.dayPrefix || 'Day'} ${d}`)).join(', ');
            return `${this.i18n.annually || 'Annually'}: ${months}, ${doms} (${timeStr})`;
          }
          if (def.weekNumbers && def.weekNumbers.length > 0 && def.daysOfWeek && def.daysOfWeek.length > 0) {
            const ords = def.weekNumbers.map((w) => ordinals[w] || `${w}`).join(', ');
            const days = def.daysOfWeek.map((d) => dayNames[d]).join(', ');
            return `${this.i18n.annually || 'Annually'}: ${months}, ${ords} ${days} (${timeStr})`;
          }
          return `${this.i18n.annually || 'Annually'}: ${months} (${timeStr})`;
        }
        return `${timeStr}`;
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

        if (schedule.id && visited.has(schedule.id)) {
          return false;
        }
        if (schedule.id) {
          visited.add(schedule.id);
        }

        let baseActive = !schedule.definitions || schedule.definitions.length === 0;
        if (schedule.definitions && schedule.definitions.length > 0) {
          let localMoment;
          if (typeof moment !== 'undefined' && moment.tz) {
            localMoment = moment(atTime).tz(schedule.Timezone || schedule.timezone || 'UTC');
          } else {
            localMoment = {
              day: () => atTime.getUTCDay(),
              date: () => atTime.getUTCDate(),
              month: () => atTime.getUTCMonth(),
              format: (f) => {
                if (f === 'HH:mm') {
                  const hh = String(atTime.getUTCHours()).padStart(2, '0');
                  const mm = String(atTime.getUTCMinutes()).padStart(2, '0');
                  return `${hh}:${mm}`;
                }
                return '';
              },
              clone: function() { return this; },
              add: function() { return this; },
              daysInMonth: () => 30,
            };
          }

          for (const def of schedule.definitions) {
            if (this.isDefinitionActive(def, localMoment)) {
              baseActive = true;
              break;
            }
          }
        }

        if (!baseActive) {
          return false;
        }

        // If base is active, check exclusions
        if (Array.isArray(schedule.excludeScheduleIds) && schedule.excludeScheduleIds.length > 0 && Array.isArray(allSchedules)) {
          for (const excludeId of schedule.excludeScheduleIds) {
            const excludeSched = allSchedules.find((s) => s.id === excludeId);
            if (excludeSched && excludeSched.enabled !== false) {
              const visitedCopy = new Set(visited);
              if (this.isScheduleActive(excludeSched, atTime, allSchedules, visitedCopy)) {
                return false;
              }
            }
          }
        }

        return true;
      },
      isDefinitionActive(def, localMoment) {
        if (!def) return false;
        const currentStr = localMoment.format('HH:mm');
        const isOvernight = !def.allDay && def.startTime && def.endTime && def.startTime > def.endTime;

        if (isOvernight) {
          if (this.matchesDay(def, localMoment) && currentStr >= def.startTime) {
            return true;
          }
          const yesterday = localMoment.clone ? localMoment.clone().add(-1, 'days') : localMoment;
          if (this.matchesDay(def, yesterday) && currentStr < def.endTime) {
            return true;
          }
          return false;
        }

        if (!this.matchesDay(def, localMoment)) {
          return false;
        }
        if (def.allDay) {
          return true;
        }
        if (!def.startTime || !def.endTime) {
          return false;
        }
        return currentStr >= def.startTime && currentStr < def.endTime;
      },
      matchesDay(def, m) {
        const weekday = m.day();
        const dayOfMonth = m.date();
        const monthNum = m.month() + 1; // 1-12

        if (def.type === 'daily') {
          return true;
        }
        if (def.type === 'weekly') {
          return Array.isArray(def.daysOfWeek) && def.daysOfWeek.includes(weekday);
        }
        if (def.type === 'monthly') {
          return this.matchesMonthlyRecurrence(def, m);
        }
        if (def.type === 'annually') {
          if (Array.isArray(def.months) && def.months.length > 0 && !def.months.includes(monthNum)) {
            return false;
          }
          if ((!def.daysOfMonth || def.daysOfMonth.length === 0) && (!def.weekNumbers || def.weekNumbers.length === 0)) {
            return true;
          }
          return this.matchesMonthlyRecurrence(def, m);
        }
        return false;
      },
      matchesMonthlyRecurrence(def, m) {
        const dayOfMonth = m.date();
        const weekday = m.day();
        const daysInMonth = m.daysInMonth ? m.daysInMonth() : 30;

        if (Array.isArray(def.daysOfMonth) && def.daysOfMonth.length > 0) {
          for (const dom of def.daysOfMonth) {
            if (dom === dayOfMonth) return true;
            if (dom === -1 && dayOfMonth === daysInMonth) return true;
          }
        }

        if (Array.isArray(def.weekNumbers) && def.weekNumbers.length > 0 && Array.isArray(def.daysOfWeek) && def.daysOfWeek.length > 0) {
          if (def.daysOfWeek.includes(weekday)) {
            const nth = Math.floor((dayOfMonth - 1) / 7) + 1;
            const isLast = dayOfMonth + 7 > daysInMonth;
            for (const wn of def.weekNumbers) {
              if (wn === nth || (wn === -1 && isLast)) return true;
            }
          }
        }
        return false;
      },
    },
  },
});
