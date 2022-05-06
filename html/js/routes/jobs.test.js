require('../test_common.js')
require('./jobs.js')

const comp = getComponent('jobs');

test('isKind', () => {
    comp.kind = '';
    expect(comp.isKind('pcap')).toBe(true);
    expect(comp.isKind('foo')).toBe(false);
    comp.kind = 'pcap';
    expect(comp.isKind('pcap')).toBe(true);
    expect(comp.isKind('foo')).toBe(false);
    comp.kind = 'foo';
    expect(comp.isKind('pcap')).toBe(false);
    expect(comp.isKind('foo')).toBe(true);
});
