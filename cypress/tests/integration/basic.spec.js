
beforeEach(() => {
    cy.visit('localhost:9822')
})

describe('Page navigation', () => {
    it('should start on overview page', () => {
        cy
            .get('.v-content__wrap')
            .find('.container')
            .find('h2')
            .contains('Overview')
    })
    
    it('navbar toggle should be visible', () => {
        cy
            .get('.v-app-bar__nav-icon.v-btn')
            .should('be.visible')
    })
    
    it('should hide sidebar when toggle clicked', () => {
        cy
            .get('header')
            .find('.v-app-bar__nav-icon.v-btn')
            .should('be.visible')
            .click()
            .get('.v-navigation-drawer')
            .should('have.attr', 'style')
            .should('contain', 'transform: translateX(-100%)')
            .get('.v-application--wrap')
            .click()
    })
    
    it('should nav to onionhunt clicked', () => {
        cy
            .get('i.fa-crosshairs')
            .click()
            .get('.v-content__wrap')
            .find('.container')
            .find('h2')
            .contains('Hunt')
    })
    
    it('should nav to pcap page when clicked', () => {
        cy
            .get('i.fa-tasks')
            .click()
            .get('.v-content__wrap')
            .find('.container')
            .find('h2')
            .contains('PCAP')
    })
    
    it('should nav to sensors page when clicked', () => {
        cy
            .get('i.fa-ethernet')
            .click()
            .get('.v-content__wrap')
            .find('.container')
            .find('h2')
            .contains('Sensors')
    })
})

describe('Top menu', () => {
    it('should start hidden', () => {
        cy
            .get('div.v-menu__content')
            .should('not.be.visible')
    })

    it('should show top menu when clicked', () => {
        cy
            .get('header')
            .find('.fa-user')
            .click()
            .get('div.v-menu__content')
            .should('be.visible')
    })

    it('should contain correct options', () => {
        cy
            .get('header')
            .find('.fa-user')
            .click()
            .get('div.v-menu__content')
            .contains('Dark Mode')
            .get('div.v-menu__content')
            .contains('Help')
            .get('div.v-menu__content')
            .contains('Blog')
            .get('div.v-menu__content')
            .contains('Logout')
    })
})