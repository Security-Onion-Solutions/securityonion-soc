// Copyright 2019 Jason Ertel (jertel). All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

routes.push({ path: '/job/:jobId', name: 'job', component: {
  template: '#page-job',
  data() { return {
    i18n: this.$root.i18n,
    job: {},
    packetView: 'hex',
    packetsLoading: false,
    search: '',
    expandAll: false,
    expanded: [],
    captureLayout: 'packets',
    packets: [],
    headers: [
      { text: this.$root.i18n.number, value: 'number' },
      { text: this.$root.i18n.timestamp, value: 'timestamp' },
      { text: this.$root.i18n.type, value: 'type' },
      { text: this.$root.i18n.srcIp, value: 'srcIp' },
      { text: this.$root.i18n.dstIp, value: 'dstIp' },
      { text: this.$root.i18n.flags, value: 'flags' },
      { text: this.$root.i18n.length, value: 'length' },
    ],
    sortBy: 'number',
    sortDesc: false,
    itemsPerPage: 10,
    footerProps: { 'items-per-page-options': [10,50,250,1000] },
    count: 500,
  }},
  created() {
    Vue.filter('formatPacketView', this.formatPacketView);
    Vue.filter('colorType', this.colorType);
    Vue.filter('colorFlag', this.colorFlag);
    this.loadData();
  },
  destroyed() {
    this.$root.unsubscribe("job", this.updateJob);
  },
  watch: {
    '$route': 'loadData',
    'packets': 'packetsUpdated',
    'packetView': 'saveLocalSettings',
    'expandAll': 'saveLocalSettings',
    'captureLayout': 'saveLocalSettings',
    'sortBy': 'saveLocalSettings',
    'sortDesc': 'saveLocalSettings',
    'itemsPerPage': 'saveLocalSettings',
  },
  methods: {
    getPacketColumnSpan() {
        return this.captureLayout == 'packets' ? this.headers.length : 1;
    },
    getPacketClass(packet) {
      var cls = "default";
      if (packet.srcIp == this.job.filter.srcIp && packet.srcPort == this.job.filter.srcPort) {
        cls = "src";
      } else if (packet.srcIp == this.job.filter.dstIp && packet.srcPort == this.job.filter.dstPort) {
        cls = "dst";
      }
      return "packet " + cls;
    },
    expandRow(row) {
      for (var i = 0; i < this.expanded.length; i++) {
        if (this.expanded[i] == row) {
          this.expanded.splice(i, 1);
          return;
        }
      }
      this.expanded.push(row);
    },
    expandPackets(enabled) {
      this.expandAll = enabled;
      this.expanded = [];
      if (enabled) {
        for (var i = 0; i < this.packets.length; i++) {
          this.expandRow(this.packets[i]);
        }
      } else {
        this.captureLayout = 'packets';
      }
    },
    captureLayoutAsStream() {
      this.expandPackets(true);
      this.sortBy = 'number';
      this.sortDesc = false;
    },
    packetsUpdated() {
      if (this.expandAll) {
        this.expandPackets(true);
      }
    },
    downloadUrl() {
      return this.$root.apiUrl + "stream?jobId=" + this.job.id;
    },
    showAll() {

    },
    async loadPackets() {
      this.packetsLoading = true;
      try {
        const response = await this.$root.papi.get('packets', { params: {
          jobId: this.$route.params.jobId,
          offset: this.packets.length,
          count: this.count
        }});
        if (response.data) {
          this.packets = this.packets.concat(response.data);
          this.loadLocalSettings();
        }
      } catch (error) {
        if (error.response != undefined && error.response.status == 404) {
        } else {
          this.$root.showError(error);
        }
      }
      this.packetsLoading = false;
    },
    async loadData() {
      this.$root.startLoading();
      try {
        const response = await this.$root.papi.get('job', { params: {
            jobId: this.$route.params.jobId
        }});
        this.job = response.data;
        this.loadPackets();
      } catch (error) {
        if (error.response != undefined && error.response.status == 404) {
          this.$root.showError(this.i18n.jobNotFound);
        } else {
          this.$root.showError(error);
        }
      }
      this.$root.stopLoading();
      this.$root.subscribe("job", this.updateJob);
    },
    saveLocalSettings() {
      if (!this.packetsLoading) {
        localStorage['settings.job.packetView'] = this.packetView;
        localStorage['settings.job.captureLayout'] = this.captureLayout;
        localStorage['settings.job.expandAll'] = this.expandAll;
        localStorage['settings.job.sortBy'] = this.sortBy;
        localStorage['settings.job.sortDesc'] = this.sortDesc;
        localStorage['settings.job.itemsPerPage'] = this.itemsPerPage;
      }
    },
    loadLocalSettings() {
      if (localStorage['settings.job.sortBy']) {
        this.packetView = localStorage['settings.job.packetView'];
        this.captureLayout = localStorage['settings.job.captureLayout'];
        this.expandAll = localStorage['settings.job.expandAll'] == "true";
        this.sortBy = localStorage['settings.job.sortBy'];
        this.sortDesc = localStorage['settings.job.sortDesc'] == "true";
        this.itemsPerPage = parseInt(localStorage['settings.job.itemsPerPage']);
      }
    },
    updateJob(job) {
      if (this.job.status != job.status) {
        this.loadPackets();
      }
      this.job = job;
    },
    colorType(type) {
      if (type.startsWith("ICMP")) return "error";
      if (type.startsWith("DHCP")) return "warning";
      if (type.startsWith("ARP")) return "secondary";
      if (type.startsWith("DNS")) return "accent";
      if (type.startsWith("TCP")) return "primary";
      if (type.startsWith("UDP")) return "success";
      return "";
    },
    colorFlag(flag) {
      if (flag == "SYN") return "success";
      if (flag == "PSH") return "primary";
      if (flag == "RST") return "error";
      if (flag == "FIN") return "warning";
      return "";
    },
    formatPacketView(packet) {
      var view = "";
      if (packet.payload) {
        var bytes = atob(packet.payload);
        if (this.captureLayout != 'packets' && packet.payloadOffset > 0) {
          bytes = bytes.slice(packet.payloadOffset);
        }
        if (this.packetView == 'hex') {
          view = this.formatHexView(bytes);
        } else {
          view = this.formatAsciiView(bytes);
        }
      }
      return view;
    },
    formatHexView(input) {
      var view = "";
      var ascii = "";
      for (var idx = 0, len = input.length; idx < len; idx++) {
        view += (idx % 16 == 0 ? ("" + idx).padStart(4,"0") + "  " : "");
        var code = input.charCodeAt(idx);
        ascii += (code < 32 || code > 126) ? "." : input[idx];
        var hex = code.toString(16).toUpperCase();
        if (hex.length < 2) hex = "0" + hex;
        view += hex
        var idxMod16 = (idx+1) % 16;
        if (idxMod16 == 0 || (idx+1) == len) {
          if (idxMod16 != 0) {
            for (var i = 0; i < (16-idxMod16); i++) {
              view += "   ";
            }
            if (idxMod16 < 9) view += " ";
          }
          view += "   " + ascii + "\n";
          ascii = "";
        } else {
          view += ((idx+1) % 8 == 0 ? "  " : " ");
        }
      }
      return view;
    },
    formatAsciiView(input) {
      var view = "";
      for (var idx = 0, len = input.length; idx < len; idx++) {
        var code = input.charCodeAt(idx);
        view += (code < 32 || code > 126) && code != 13 && code != 10 ? "." : input[idx];
      }
      return view;
    }
  }
}});

