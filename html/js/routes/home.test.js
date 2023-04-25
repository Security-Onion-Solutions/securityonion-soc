require('../test_common.js');
require('./home.js');

let home = getComponent('home');

test('loadChanges', async () => {
  // save original functions
  const createApi = home.$root.createApi;
  const showErrorMock = mockShowError();
  const data = 'MOTD';

  // mock functions for sunny day path
  const mockGoodGetter = jest.fn().mockReturnValue({data: data});
  home.$root.createApi = jest.fn().mockReturnValue({
    get: mockGoodGetter,
  });

  // test
  await home.loadChanges();

  // verify
  expect(showErrorMock).toHaveBeenCalledTimes(0);
  expect(home.$root.createApi).toHaveBeenCalledTimes(1);
  expect(mockGoodGetter).toHaveBeenCalledTimes(1);
  expect(mockGoodGetter).toHaveBeenCalledWith(expect.stringMatching(/motd.md\?v=\d+/));
  expect(home.motd).toBe(data);

  // reset
  home.motd = '';

  // mock functions for rainy day path
  const mockBadGetter = jest.fn().mockImplementation(() => { throw new Error() });
  home.$root.createApi = jest.fn().mockReturnValue({
    get: mockBadGetter,
  });

  // test
  await home.loadChanges();

  // verify
  expect(showErrorMock).toHaveBeenCalledTimes(1);
  expect(home.$root.createApi).toHaveBeenCalledTimes(1);
  expect(mockBadGetter).toHaveBeenCalledTimes(1);
  expect(mockBadGetter).toHaveBeenCalledWith(expect.stringMatching(/motd.md\?v=\d+/));
  expect(home.motd).toBe('');

  // restore original functions
  home.$root.createApi = createApi;
});