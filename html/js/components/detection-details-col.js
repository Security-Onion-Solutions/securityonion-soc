// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

loadPageTemplate('component-detection-details-col', 'pages/detection-details-col.html');

components.push({
	name: "DetectionDetailsCol", component: {
		props: {
			detect: { type: Object, required: true },
		},
		emits: ['save', 'duplicate'],
		setup(_, { emit }) {
			return { emit };
		},
		template: '#component-detection-details-col',
		data() {
			return {
				i18n: this.$root.i18n,
				panel: [0, 1, 2],
				confirmDeleteDialog: false,
			};
		},
		methods: {
			isNew() {
				return this.$route.params.id === 'create';
			},
			deleteDetection() {
				this.confirmDeleteDialog = true;
			},
			cancelDeleteDetection() {
				this.confirmDeleteDialog = false;
			},
			async confirmDeleteDetection() {
				this.cancelDeleteDetection();
				try {
					this.$root.startLoading();
					await this.$root.papi.delete('/detection/' + encodeURIComponent(this.$route.params.id));
					this.$router.push({ name: 'detections' });
					this.$root.showTip(this.i18n.detectionDeleteSuccessful);
				} catch (error) {
					this.$root.showError(error);
				} finally {
					this.$root.stopLoading();
				}
			},
		},
	}
});
