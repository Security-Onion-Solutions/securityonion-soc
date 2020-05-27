describe(('PCAP job creation'), () => {
    beforeEach(() => {
        cy.visit('/#/jobs')
    })
    
    it('should show job creation window when (+) clicked', () => {
        let placeholderArray = [
            'Sensor ID',
            'Source IP',
            'Source Port',
            'Destination IP',
            'Destination Port',
            'Filter Begin',
            'Filter End'
        ]
        cy.get('#add-pcap-job-button')
            .click()
        .get('#pcap-job-dialog')
            .should('be.visible')
            .children('form')
            .find('input')
            .should('have.length', 7)
            .each((el, index) => {
                cy.get(el).should('have.attr', 'placeholder', placeholderArray[index])
            })
    })
})