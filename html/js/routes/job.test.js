// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js')
require('./job.js')

const comp = getComponent('job');

test('packetArrayTranscript', () => {
    // Setup
    const packetArr = [
        { }, // no payload, should be filtered
        { payload: 'SUdOT1JFLlRISVMuVGVzdC5TdHJpbmcuMTIzLmFzZGZhc2RmLmFzZGZhc2Q=', payloadOffset: 0 }, // payloadOffset == 0, should be filtered
        { payload: 'SUdOT1JFLlRISVMuVGVzdC5TdHJpbmcuMTIzLmFzZGZhc2RmLmFzZGZhc2Q=', payloadOffset: 12 },
        { payload: 'SUdOT1JFLlRISVMuVGhpcy5pcy5hLnNlY29uZC50ZXN0LnBhY2tldC4xMjM=', payloadOffset: 12 }
    ];
    comp.packets = packetArr;

    expectedTranscript = `\
0000  54 65 73 74 2E 53 74 72  69 6E 67 2E 31 32 33 2E   Test.String.123.
0016  61 73 64 66 61 73 64 66  2E 61 73 64 66 61 73 64   asdfasdf.asdfasd
0000  54 68 69 73 2E 69 73 2E  61 2E 73 65 63 6F 6E 64   This.is.a.second
0016  2E 74 65 73 74 2E 70 61  63 6B 65 74 2E 31 32 33   .test.packet.123
`;

    // Test
    const transcript = comp.packetArrayTranscript();
    expect(transcript).toBe(expectedTranscript);
});

test('transcriptCyberChef_testing', () => {
    // Setup
    const path = '/cyberchef/#recipe=From_Hexdump()';
    localStorage['settings.flags.testing'] = 'true';
    const mockedOpen = jest.fn();
    mockedOpen.mockReturnValue({});
    const originalOpen = window.open;
    window.open = mockedOpen;

    // Test
    comp.transcriptCyberChef();
    expect(mockedOpen).toBeCalledWith(path, '_self');

    // Cleanup
    window.open = originalOpen;
});
