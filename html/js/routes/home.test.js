require('../test_common.js');
require('./home.js');

let home = getComponent('home');

test('loadChanges', async () => {
  // save original functions
  const createApi = home.$root.createApi;
  const showError = home.$root.showError;

  // mock functions
  // since we're testing the rainy day path, throw an error on the first call
  home.$root.createApi = jest.fn().mockReturnValue({
    get: () => { throw new Error() },
  })

  // count how many times this function is called
  let callCount = 0;
  home.$root.showError = () => {
    callCount++;
  };

  // test
  await home.loadChanges();

  // verify
  expect(home.motd).toBe('');
  expect(callCount).toBe(1);

  // reset
  callCount = 0;

  // mock functions for second, sunny day path
  const data = 'MOTD';
  home.$root.createApi = jest.fn().mockReturnValue({
    get: jest.fn().mockReturnValue({ data: data }),
  })

  // test
  await home.loadChanges();

  // verify
  expect(home.motd).toBe(data);
  expect(callCount).toBe(0);

  // restore original functions
  home.$root.createApi = createApi;
  home.$root.showError = showError;
});