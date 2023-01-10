// Copyright 2020-2023 Security Onion Solutions. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

routes.push({ path: '/user/:id', name: 'user', component: {
  template: '#page-user',
  data() { return {
    i18n: this.$root.i18n,
    form: {
      valid: false,
      email: null,
      firstName: null,
      lastName: null,
      note: null,
    },
    rules: {
      required: value => !!value || this.$root.i18n.required,
    },
  }},
  created() {
    this.loadData()
  },
  watch: {
    '$route': 'loadData',
  },
  methods: {
    async loadData() {
      this.$root.startLoading();
      try {
        const response = await this.$root.papi.get('user/' + this.$route.params.id);
        if (response.status == 200) {
          this.form.email = response.data.email;
          this.form.firstName = response.data.firstName;
          this.form.lastName = response.data.lastName;
          this.form.note = response.data.note;
        } else {
          this.$root.showError(response.statusText);
        }
      } catch (error) {
        this.$root.showError(error);
      }
      this.$root.stopLoading();
    },
    async updateUser() {
      try {
        if (!this.form.email) {
          this.$root.showError(this.i18n.emailRequired);
        } else {
          const response = await this.$root.papi.put('user/' + this.$route.params.id, {
            email: this.form.email,
            firstName: this.form.firstName,
            lastName: this.form.lastName,
            note: this.form.note,
          });
          if (response.status == 200) {
            this.$root.showInfo(this.i18n.updateSuccessful);
          } else {
            this.$root.showError(response.statusText);
          }
        }
      } catch (error) {
         this.$root.showError(error);
      }
    },
  }
}});
