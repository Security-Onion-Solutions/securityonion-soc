describe('Downloads', () => {
    beforeEach(() => {
        cy.visit('/#/downloads')
    })

    it('should have a list of packages to download', () => {
        const packages = [
            'MSI (Windows)',
            'DEB (Debian)',
            'RPM (RPM)',
            'PKG (MacOS)'
        ]

        const package_links = [
            '/packages/launcher.msi',
            '/packages/launcher.deb',
            '/packages/launcher.rpm',
            '/packages/launcher.pkg'
        ]

        cy.get('#osquery-packages')
            .contains('Packages')
            .next('ul')
            .children()
            .should('have.length', 4)
            .each((el, index) => {
                cy
                    .get(el)
                    .contains(packages[index])
                    .should('have.attr', 'href', package_links[index])
            })
    })

    it('should have a list of configs to download', () => {
        const configs = [
            'RPM & DEB Flag File',
            'MSI Flag File'
        ]

        const config_links = [
            '/packages/launcher.flags',
            '/packages/launcher-msi.flags'
        ]

        cy.get('#osquery-configs')
            .contains('Configs')
            .next('ul')
            .children()
            .should('have.length', 2)
            .each((el, index) => {
                cy
                    .get(el)
                    .contains(configs[index])
                    .should('have.attr', 'href', config_links[index])
            })
    })
})