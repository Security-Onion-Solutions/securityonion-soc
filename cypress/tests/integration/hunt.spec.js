
describe('OQL input', () => {
    beforeEach(() => {
        cy.visit('/#/hunt')
    })
    
    it('should contain the default query', () => {
        cy.get('#hunt-query-input').should('have.value', "* | groupby observer.name")
    })
    
    it.skip('should push run query to recent query list', () => {
        cy.get('#hunt-query-input')
            .click().clear()
            .type('* | groupby source.ip')
        cy.get('#hunt')
            .click()
            // TODO: complete this chain
    })

    it('should have correct number of items in the dropdown', () => {
        cy.get('#hunt-query-dropdown-button')
                .click()
        cy.get('#hunt-query-dropdown-list')
            .find('hr')
            .nextAll('div')
            .should('have.length', 61)
    })
})

describe('Hunt time window', () => {
    beforeEach(() => {
        cy.visit('/#/hunt')
    })
    
    it.skip('should convert relative to absolute correctly', () => {
        // TODO: new Date() is consitently slow by a second
        cy.get('#huntrelativetimevalue')
            .click({force: true}).clear()
            .type('12')
        cy.get('#show-absolute-time')
            .click()
        const current = new Date()
        const dateRange = cy.get('#huntdaterange')
        let dd = 'AM'
        let pastDd = 'AM'
        let hours = current.getHours()
        let pastHours = current.getHours() - 12
        if (hours >= 12) {
            hours -= 12
            dd = 'PM'
        }
        if (hours == 0) hours = 12
        if (pastHours >= 12) {
            pastHours -= 12
            pastDd = 'PM'
        }
        if (pastHours == 0) pastHours = 12
        let timeString = 
            `${('0' + hours).slice(-2)}:${('0' + current.getMinutes()).slice(-2)}:`
        let pastTimeString = 
            `${('0' + pastHours).slice(-2)}:${('0' + current.getMinutes()).slice(-2)}:`
        
        dateRange.should('contain.value', `/${current.getDate()}`)
        dateRange.should('contain.value', timeString)
        dateRange.should('contain.value', pastTimeString)
        if (current.getHours() < 12) {
            const past = new Date(current)
            past.setDate(past.getDate() - 1)
            dateRange.should('contain.value', `/${past.getDate()}`)
        }
    })
})
