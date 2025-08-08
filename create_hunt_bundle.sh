#\!/bin/bash
# Create a bundled hunt.js from the modular files

echo "// Copyright 2019 Jason Ertel (github.com/jertel)."
echo "// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one"
echo "// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at"
echo "// https://securityonion.net/license; you may not use this file except in compliance with the"
echo "// Elastic License 2.0."
echo ""
echo ""
echo "loadPageTemplate('page-hunt', 'pages/hunt.html');"
echo ""

# Extract data object
echo "const huntData = $(grep -A 1000 "^export default" html/js/routes/hunt/data.js | sed '1s/export default//' | sed '$ s/$/;/')"
echo ""

# Extract each methods object
echo "const queryMethods = $(grep -A 1000 "^export default" html/js/routes/hunt/query.js | sed '1s/export default//' | sed '$ s/$/;/')"
echo ""
echo "const routingMethods = $(grep -A 1000 "^export default" html/js/routes/hunt/routing.js | sed '1s/export default//' | sed '$ s/$/;/')"
echo ""
echo "const dataHandlerMethods = $(grep -A 1000 "^export default" html/js/routes/hunt/dataHandlers.js | sed '1s/export default//' | sed '$ s/$/;/')"
echo ""
echo "const actionMethods = $(grep -A 1000 "^export default" html/js/routes/hunt/actions.js | sed '1s/export default//' | sed '$ s/$/;/')"
echo ""
echo "const chartMethods = $(grep -A 1000 "^export default" html/js/routes/hunt/charts.js | sed '1s/export default//' | sed '$ s/$/;/')"
echo ""
echo "const playbookMethods = $(grep -A 1000 "^export default" html/js/routes/hunt/playbook.js | sed '1s/export default//' | sed '$ s/$/;/')"
echo ""
echo "const aiMethods = $(grep -A 1000 "^export default" html/js/routes/hunt/ai.js | sed '1s/export default//' | sed '$ s/$/;/')"
echo ""
echo "const uiMethods = $(grep -A 1000 "^export default" html/js/routes/hunt/ui.js | sed '1s/export default//' | sed '$ s/$/;/')"
echo ""
echo "const localStorageMethods = $(grep -A 1000 "^export default" html/js/routes/hunt/localStorage.js | sed '1s/export default//' | sed '$ s/$/;/')"
echo ""

# Create hunt component
cat << 'COMPONENT'
const huntComponent = {
  template: '#page-hunt',
  data() {
   const data = huntData;
   data.i18n = this.$root.i18n;
   data.bulkActions = [
     { title: this.$root.i18n.enable, value: 'enable' },
     { title: this.$root.i18n.disable, value: 'disable' },
     { title: this.$root.i18n.delete, value: 'delete' },
   ];
   return data;
 },
  created() {
    this.$root.initializeCharts();
    this.initializeTimeAndIntervals();
  },
  beforeUnmount() {
    this.$root.setSubtitle("");
    this.stopRefreshTimer();
    this.$root.unsubscribe('detections:bulkUpdate', this.bulkUpdateReport);
    this.$root.unsubscribe('related:bulkCreate', this.bulkUpdateReport);

    if (this.isCategory('alerts')) {
      window.removeEventListener('resize', this.calculateEventColumnWidth);
    }
  },
  mounted() {
    this.$root.startLoading();
    this.category = this.$route.path.replace("/", "");
    this.$root.loadParameters(this.category, this.initHunt);

    if (this.isCategory('detections')) {
      this.$root.subscribe('detections:bulkUpdate', this.bulkUpdateReport);
    }

    if (this.isCategory('alerts') || this.isCategory('hunt')) {
      this.$root.subscribe('related:bulkCreate', this.bulkUpdateReport);
    }

    if (this.isCategory('alerts')) {
      window.addEventListener('resize', this.calculateEventColumnWidth);
    }
  },
  watch: {
    '$route': 'loadData',
    'groupBySortBy': 'saveLocalSettings',
    'groupBySortDesc': 'saveLocalSettings',
    'groupByItemsPerPage': 'groupByItemsPerPageChanged',
    'groupByLimit': 'groupByLimitChanged',
    'sortBy': 'saveLocalSettings',
    'sortDesc': 'saveLocalSettings',
    'itemsPerPage': 'itemsPerPageChanged',
    'eventLimit': 'eventLimitChanged',
    'relativeTimeValue': 'saveLocalSettings',
    'relativeTimeUnit': 'saveLocalSettings',
    'autohunt': 'saveLocalSettings',
    'autoRefreshInterval': 'resetRefreshTimer',
    'showDetailsPanel': 'toggleShowDetailsPanel',
    'advanced': 'saveLocalSettings',
  },
  methods: {
    ...queryMethods,
    ...routingMethods,
    ...dataHandlerMethods,
    ...actionMethods,
    ...chartMethods,
    ...playbookMethods,
    ...aiMethods,
    ...uiMethods,
    ...localStorageMethods,
    ...huntMethods,
  }
};

routes.push({ path: '/hunt', name: 'hunt', component: huntComponent});

const alertsComponent = Object.assign({}, huntComponent);
routes.push({ path: '/alerts', name: 'alerts', component: alertsComponent});

const casesComponent = Object.assign({}, huntComponent);
routes.push({ path: '/cases', name: 'cases', component: casesComponent});

const dashboardsComponent = Object.assign({}, huntComponent);
routes.push({ path: '/dashboards', name: 'dashboards', component: dashboardsComponent});

const detectionsComponent = Object.assign({}, huntComponent);
routes.push({ path: '/detections', name: 'detections', component: detectionsComponent });
COMPONENT

