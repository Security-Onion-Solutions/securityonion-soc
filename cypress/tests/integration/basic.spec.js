describe('Page navigation', () => {
    beforeEach(() => {
        cy.visit('/#/')
    })

    it('should start on overview page', () => {
        cy.get('.v-content__wrap')
            .find('.container')
            .find('h2')
            .contains('Overview')
    })
    
    it('navbar toggle should be visible', () => {
        cy.get('.v-app-bar__nav-icon.v-btn')
            .should('be.visible')
    })
    
    it('should hide sidebar when toggle clicked', () => {
        cy.get('header')
            .find('.v-app-bar__nav-icon.v-btn')
            .should('be.visible')
            .click()
        cy.get('.v-navigation-drawer')
            .should('have.attr', 'style')
            .should('contain', 'transform: translateX(-100%)')
        // cy.get('.v-application--wrap')
        //     .click()
    })
    
    it('should nav to onionhunt clicked', () => {
        cy.get('i.fa-crosshairs')
            .click()
        cy.get('.v-content__wrap')
            .find('.container')
            .find('h2')
            .contains('Hunt')
    })
    
    it('should nav to pcap page when clicked', () => {
        cy.get('i.fa-tasks')
            .click()
        cy.get('.v-content__wrap')
            .find('.container')
            .find('h2')
            .contains('PCAP')
    })
    
    it('should nav to sensors page when clicked', () => {
        cy.get('i.fa-ethernet')
            .click()
        cy.get('.v-content__wrap')
            .find('.container')
            .find('h2')
            .contains('Sensors')
    })
})

describe('Sidebar content', () => {
    beforeEach(() => {
        cy.visit('/#/')
    })

    it('should have correct links to external tools', () => {
        const externalTools = [
            'Kibana',
            'Grafana',
            'CyberChef',
            'Playbook',
            'Fleet',
            'TheHive',
            'Navigator'
        ]
            
        cy.get('#external-tools-list')
            .should('be.visible')
            .find('.v-subheader')
            .should('have.text', 'Tools')
        cy.get('#external-tools-list')
            .children('a')
            .should('have.length', 7)
    })
})

describe('Top menu', () => {
    beforeEach(() => {
        cy.visit('/#/')
    })

    it('should start hidden', () => {
        cy.get('div.v-menu__content')
            .should('not.be.visible')
    })

    it('should show when user icon clicked', () => {
        cy.get('header')
            .find('.fa-user')
            .click()
        cy.get('#top-menu')
            .should('be.visible')
    })

    it('should contain correct options', () => {
        const topMenuOptions = [ 'Dark Mode', 'Help', 'Blog', 'Logout' ]

        cy.get('header')
            .find('.fa-user')
            .click()
        cy.get('#top-menu')
            .children(':not(hr)')
            .should('have.length', 4)
            .each((el, index) => {
                cy.get(el).contains(topMenuOptions[index])
            })
    })
})

describe('Changes list', () => {
    beforeEach(() => {
        cy.visit('/#/')
    })
    
    it('should have correct title', () => {
        cy.fixture('changes.json').its('title').then((title) => {
            cy.get('#change-details')
                .find('.title')
                .contains(title)
        })
        
    })
    it('should have correct number of items', () => {
        cy.fixture('changes.json').its('changes').then((changes) => {
            cy.get('#change-details')
                .find('ul')
                .children('li')
                .each((el, index) => {
                    cy.get(el).contains(changes[index].summary)
                })
        })
    })
})