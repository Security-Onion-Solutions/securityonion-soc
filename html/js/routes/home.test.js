require('../test_common.js');
require('./home.js');

let comp;

beforeEach(() => {
  comp = getComponent("home");
  resetPapi();
});

test('loadChanges', async () => {
  const showErrorMock = mockShowError();
  const data = 'MOTD';
  var mock = mockPapi('get', { data: data });

  // test
  await comp.loadChanges();

  // verify
  expect(showErrorMock).toHaveBeenCalledTimes(0);
  expect(mock).toHaveBeenCalledTimes(1);
  expect(mock).toHaveBeenCalledWith(expect.stringMatching(/motd.md\?v=\d+/));
  expect(comp.motd).toBe(data);
});

test('loadChanges error', async () => {
  const showErrorMock = mockShowError();
  mock = mockPapi('get', null, new Error('test error'));

  // test
  await comp.loadChanges();

  // verify
  expect(mock).toHaveBeenCalledTimes(1);
  expect(mock).toHaveBeenCalledWith(expect.stringMatching(/motd.md\?v=\d+/));
  expect(showErrorMock).toHaveBeenCalledTimes(1);
  expect(comp.motd).toBe('');
});