// Copyright 2019 Jason Ertel (jertel). All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

routes.push({ path: '/sensors', name: 'sensors', component: {
  template: '#page-sensors',
  data() { return {
    i18n: this.$root.i18n,
    sensors: [],
    headers: [
      { text: this.$root.i18n.id, value: 'id' },
      { text: this.$root.i18n.description, value: 'description' },
      { text: this.$root.i18n.version, value: 'version' },
      { text: this.$root.i18n.dateOnline, value: 'onlineTime' },
      { text: this.$root.i18n.dateUpdated, value: 'updateTime' },
      { text: this.$root.i18n.dateDataEpoch, value: 'epochTime' },
      { text: this.$root.i18n.uptime, value: 'uptimeSeconds' },
    ],
    sortBy: 'id',
    sortDesc: false,
    itemsPerPage: 10,
    footerProps: { 'items-per-page-options': [10,50,250,1000] },
  }},
  created() { this.loadData() },
  watch: {
    '$route': 'loadData',
    'sortBy': 'saveLocalSettings',
    'sortDesc': 'saveLocalSettings',
    'itemsPerPage': 'saveLocalSettings',
  },
  methods: {
    async loadData() {
      this.$root.startLoading();
      try {
        const response = await this.$root.papi.get('sensors');
        this.sensors = response.data;
        this.loadLocalSettings();
      } catch (error) {
        this.$root.showError(error);
      }
      this.$root.stopLoading();
      this.$root.subscribe("sensor", this.updateSensor);
    },
    saveLocalSettings() {
      localStorage['settings.sensors.sortBy'] = this.sortBy;
      localStorage['settings.sensors.sortDesc'] = this.sortDesc;
      localStorage['settings.sensors.itemsPerPage'] = this.itemsPerPage;
    },
    loadLocalSettings() {
      if (localStorage['settings.sensors.sortBy']) {
        this.sortBy = localStorage['settings.sensors.sortBy'];
        this.sortDesc = localStorage['settings.sensors.sortDesc'] == "true";
        this.itemsPerPage = parseInt(localStorage['settings.sensors.itemsPerPage']);
      }
    },
    updateSensor(sensor) {
      for (var i = 0; i < this.sensors.length; i++) {
        if (this.sensors[i].id == sensor.id) {
          this.$set(this.sensors, i, sensor);
          break;
        }
      }
    }
  }
}});
