// Copyright 2019 Jason Ertel (github.com/jertel).
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
    expect(mockedOpen).toHaveBeenCalledWith(path, '_self');

    // Cleanup
    window.open = originalOpen;
});

test('downloadUrl', () => {
  // Setup
  comp.$root = { apiUrl: 'https://api.example.com/' };
  comp.job = { id: '123' };
  comp.packetOptions = ['packets']; // unwrap not enabled

  // Test without grid and unwrap false
  let url = comp.downloadUrl();
  expect(url).toBe('https://api.example.com/stream?jobId=123&ext=pcap&unwrap=false');

  // Test with unwrap true
  comp.packetOptions = ['unwrap'];
  url = comp.downloadUrl();
  expect(url).toBe('https://api.example.com/stream?jobId=123&ext=pcap&unwrap=true');

  // Test with grid
  comp.$root.selectedGridId = 'grid1';
  comp.packetOptions = ['packets'];
  url = comp.downloadUrl();
  expect(url).toBe('https://api.example.com/stream?jobId=123&ext=pcap&unwrap=false&gridId=grid1');
});

test('colorType', () => {
  expect(comp.colorType('TCP')).toBe('primary');
  expect(comp.colorType('UDP')).toBe('success');
  expect(comp.colorType('ICMP')).toBe('cyan');
  expect(comp.colorType('DHCP')).toBe('teal');
  expect(comp.colorType('ARP')).toBe('secondary');
  expect(comp.colorType('DNS')).toBe('accent');
  expect(comp.colorType('DecodeFailure')).toBe('error');
  expect(comp.colorType('UNKNOWN')).toBe('');
});

test('loadPackets passes excludeErrors and unwrap params', async () => {
  comp.$root.papi = { get: jest.fn().mockResolvedValue({ data: [] }) };
  comp.$root.batchLookup = jest.fn();
  comp.$root.showError = jest.fn();
  comp.job = { id: 123 };
  comp.packets = [];

  // Without excludeErrors
  comp.packetOptions = ['packets', 'hex'];
  await comp.loadPackets(false, false);
  expect(comp.$root.papi.get).toHaveBeenCalledWith('packets', {
    params: {
      jobId: 123,
      offset: 0,
      count: 500,
      unwrap: false,
      excludeErrors: false
    }
  });

  // With excludeErrors
  comp.packetOptions = ['packets', 'hex', 'excludeErrors'];
  await comp.loadPackets(false, true);
  expect(comp.$root.papi.get).toHaveBeenCalledWith('packets', {
    params: {
      jobId: 123,
      offset: 0,
      count: 500,
      unwrap: false,
      excludeErrors: true
    }
  });
});

test('hasDecodeFailures', () => {
  comp.packets = [
    { number: 1, type: 'TCP' },
    { number: 2, type: 'UDP' },
  ];
  expect(comp.hasDecodeFailures()).toBe(false);

  comp.packets.push({ number: 3, type: 'DecodeFailure' });
  expect(comp.hasDecodeFailures()).toBe(true);

  comp.packets = [
    { number: 1, type: 'TCP', error: 'Decode issue' },
  ];
  expect(comp.hasDecodeFailures()).toBe(true);
});

test('onPacketOptionsChanged triggers loadPackets when unwrap or excludeErrors changes', () => {
  const origLoadPackets = comp.loadPackets;
  comp.loadPackets = jest.fn();
  comp.job = { id: 123 };
  comp.lastLoadedUnwrap = false;
  comp.lastLoadedExcludeErrors = false;

  // Toggle excludeErrors on
  comp.onPacketOptionsChanged(['packets', 'hex', 'excludeErrors']);
  expect(comp.loadPackets).toHaveBeenCalledWith(false, true);

  // Toggle hex only (no reload needed)
  comp.loadPackets.mockClear();
  comp.lastLoadedExcludeErrors = true;
  comp.onPacketOptionsChanged(['packets', 'excludeErrors']);
  expect(comp.loadPackets).not.toHaveBeenCalled();

  // Toggle unwrap on
  comp.loadPackets.mockClear();
  comp.onPacketOptionsChanged(['packets', 'unwrap', 'excludeErrors']);
  expect(comp.loadPackets).toHaveBeenCalledWith(true, true);

  comp.loadPackets = origLoadPackets;
});

test('loadPackets updates hasDecodeErrors from header and packet items', async () => {
  comp.job = { id: 123 };
  comp.packets = [];

  // When header says true
  comp.$root.papi = { get: jest.fn().mockResolvedValue({
    data: [{ number: 1, type: 'TCP' }],
    headers: { 'x-decode-errors-present': 'true' }
  })};
  await comp.loadPackets(false, false);
  expect(comp.hasDecodeErrors).toBe(true);

  // When header says false
  comp.packets = [];
  comp.$root.papi = { get: jest.fn().mockResolvedValue({
    data: [{ number: 1, type: 'TCP' }],
    headers: { 'x-decode-errors-present': 'false' }
  })};
  await comp.loadPackets(false, false);
  expect(comp.hasDecodeErrors).toBe(false);
});
