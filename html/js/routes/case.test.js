// Copyright 2020,2021 Security Onion Solutions. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

require('../test_common.js');
require('./case.js');

const fakePriority = 33;
const fakeSeverity = 31;
const fakeEmail = 'my@email.invalid';
const fakeAssigneeEmail = 'assignee@email.invalid';
const fakeCase = {
  userId: 'myUserId',
  id: 'myCaseId',
  title: 'myTitle',
  description: 'myDescription',
  severity: fakeSeverity,
  priority: fakePriority,
  tlp: 'myTlp',
  pap: 'myPap',
  category: 'myCategory',
  tags: ['tag1', 'tag2'],
  assigneeId: 'myAssigneeId',
  status: 'open',
};
const fakeUsers = [
  {'id': 'myUserId', 'email': fakeEmail},
  {'id': 'myAssigneeId', 'email': fakeAssigneeEmail}
  ];
const fakeComment = {
  userId: 'myUserId',
  id: 'myCommentId',
  description: 'myDescription',
};

var comp;

beforeEach(() => {
  comp = getComponent("case");
  resetPapi();
});

test('initParams', () => {
  comp.mruCases.push({id:"123"});
  comp.saveLocalSettings()
  comp.mruCases = [];
  comp.initCase({"foo":"bar", "mostRecentlyUsedLimit": 23});
  expect(comp.params.foo).toBe("bar");
  expect(comp.mruCaseLimit).toBe(23);
  expect(comp.mruCases.length).toBe(1)
});

test('addMRUCaseObj', () => {
  const case1 = {id:'1'};
  const case2 = {id:'2'};
  const case3 = {id:'3'};
  const case4 = {id:'4'};
  const case5 = {id:'5'};
  const case6 = {id:'6'};
  expect(comp.mruCases.length).toBe(0);
  comp.addMRUCaseObj(case1);
  expect(comp.mruCases.length).toBe(1);
  comp.addMRUCaseObj(case1);
  expect(comp.mruCases.length).toBe(1); // still one
  expect(comp.mruCases[0]).toBe(case1);

  comp.addMRUCaseObj(case2);
  expect(comp.mruCases.length).toBe(2);
  expect(comp.mruCases[0]).toBe(case2);
  expect(comp.mruCases[1]).toBe(case1);

  comp.addMRUCaseObj(case3);
  expect(comp.mruCases.length).toBe(3);
  expect(comp.mruCases[0]).toBe(case3);
  expect(comp.mruCases[1]).toBe(case2);
  expect(comp.mruCases[2]).toBe(case1);

  comp.addMRUCaseObj(case2);
  expect(comp.mruCases.length).toBe(3);
  expect(comp.mruCases[0]).toBe(case2); // back on top
  expect(comp.mruCases[1]).toBe(case3);
  expect(comp.mruCases[2]).toBe(case1);

  comp.addMRUCaseObj(case4);
  expect(comp.mruCases.length).toBe(4);
  expect(comp.mruCases[0]).toBe(case4);
  expect(comp.mruCases[1]).toBe(case2);
  expect(comp.mruCases[2]).toBe(case3);
  expect(comp.mruCases[3]).toBe(case1);

  comp.addMRUCaseObj(case5);
  expect(comp.mruCases.length).toBe(5);
  expect(comp.mruCases[0]).toBe(case5);
  expect(comp.mruCases[1]).toBe(case4);
  expect(comp.mruCases[2]).toBe(case2);
  expect(comp.mruCases[3]).toBe(case3);
  expect(comp.mruCases[4]).toBe(case1);

  comp.addMRUCaseObj(case6);
  expect(comp.mruCases.length).toBe(5);
  expect(comp.mruCases[0]).toBe(case6);
  expect(comp.mruCases[1]).toBe(case5);
  expect(comp.mruCases[2]).toBe(case4);
  expect(comp.mruCases[3]).toBe(case2);
  expect(comp.mruCases[4]).toBe(case3);
});

test('loadAssociations', () => {
  comp.caseObj = {id: 'myCaseId'};
  comp.loadAssociation = jest.fn();
  comp.loadAssociations();
  expect(comp.loadAssociation).toHaveBeenCalledWith('comments');
  expect(comp.associatedForms["comments"].caseId).toBe('myCaseId')
  expect(comp.loadAssociation).toHaveBeenCalledWith('tasks');
  expect(comp.associatedForms["tasks"].caseId).toBe('myCaseId')
  expect(comp.loadAssociation).toHaveBeenCalledWith('artifacts');
  expect(comp.associatedForms["artifacts"].caseId).toBe('myCaseId')
  expect(comp.loadAssociation).toHaveBeenCalledWith('events');
  expect(comp.loadAssociation).toHaveBeenCalledWith('history');
  expect(comp.associationsLoading).toBe(false);
});

test('loadAssociation', async () => {
  const params = { params: {
          id: 'myUserId',
          offset: 0,
          count: comp.count,
        }};

  resetPapi();
  // API call #1 is to get the comment list
  mockPapi("get", {'data':[fakeComment]});
  // API call #2 is to get the user list
  mock = mockPapi("get", {'data':fakeUsers});

  comp.$route.params.id = 'myUserId';
  const showErrorMock = mockShowError();

  await comp.loadAssociation('comments');

  expect(mock).toHaveBeenCalledWith('case/comments', params);
  expect(showErrorMock).toHaveBeenCalledTimes(0);
  expect(comp.associations['comments'].length).toBe(1);
  expect(comp.associations['comments'][0].owner).toBe(fakeEmail);
  expect(comp.$root.loading).toBe(false);
});

test('loadAssociationError', async () => {
  const showErrorMock = mockShowError();
  resetPapi().mockPapi("get", null, new Error("something bad"));
  await comp.loadAssociation('comments');
  expect(showErrorMock).toHaveBeenCalledTimes(1);
});

expectCaseDetails = () => {
  expect(comp.form.id).toBe(fakeCase.id);
  expect(comp.form.title).toBe(fakeCase.title);
  expect(comp.form.description).toBe(fakeCase.description);
  expect(comp.form.severity).toBe(fakeCase.severity);
  expect(comp.form.priority).toBe(fakeCase.priority);
  expect(comp.form.status).toBe(fakeCase.status);
  expect(comp.form.tlp).toBe(fakeCase.tlp);
  expect(comp.form.pap).toBe(fakeCase.pap);
  expect(comp.form.category).toBe(fakeCase.category);
  expect(comp.form.tags).toBe(fakeCase.tags.join(", "));
  expect(comp.caseObj).toBe(fakeCase);
  expect(comp.caseObj.owner).toBe(fakeEmail);
  expect(comp.caseObj.assignee).toBe(fakeAssigneeEmail);
}

test('loadData', async () => {
  const params = { params: {
          id: 'myCaseId'
        }};

  // API call #1 is to get the comment list
  mockPapi("get", {'data':fakeCase});
  // API call #2 is to get the user list
  mock = mockPapi("get", {'data':fakeUsers});

  comp.$route.params.id = 'myCaseId';
  const showErrorMock = mockShowError();
  comp.loadAssociations = jest.fn();

  await comp.loadData();

  expect(mock).toHaveBeenCalledWith('case/', params);
  expect(showErrorMock).toHaveBeenCalledTimes(0);
  expect(comp.loadAssociations).toHaveBeenCalledTimes(1);
  expectCaseDetails();
  expect(comp.$root.loading).toBe(false);
});

test('loadDataNotFound', async () => {
  const showErrorMock = mockShowError();
  const error = new Error("not found")
  error.response = { status: 404 };
  mockPapi("get", null, error);
  await comp.loadData();
  expect(showErrorMock).toHaveBeenCalledWith(comp.i18n.notFound);
});

test('loadDataError', async () => {
  const showErrorMock = mockShowError();
  mockPapi("get", null, new Error("something bad"));
  await comp.loadData();
  expect(showErrorMock).toHaveBeenCalledTimes(1);
});

test('modifyCase', async () => {
  // API call #1 is to get the comment list
  const putMock = mockPapi("put", {'data':fakeCase});
  // API call #2 is to get the user list
  const getMock = mockPapi("get", {'data':fakeUsers});

  comp.form.priority = '' + fakePriority;
  comp.form.severity = '' + fakeSeverity;
  comp.form.id = 'myCaseId';
  comp.form.title = 'myTitle';
  comp.form.description = 'myDescription';
  comp.form.status = 'open';
  comp.form.tlp = 'myTlp';
  comp.form.pap = 'myPap';
  comp.form.category = 'myCategory';
  comp.form.tags = 'tag1,tag2';
  comp.form.assigneeId = 'myAssigneeId';
  const showErrorMock = mockShowError(true);

  expect(comp.mruCases.length).toBe(0);

  await comp.modifyCase();

  const body =  "{\"valid\":false,\"id\":\"myCaseId\",\"title\":\"myTitle\",\"description\":\"myDescription\",\"status\":\"open\",\"severity\":31,\"priority\":33,\"assigneeId\":\"myAssigneeId\",\"tags\":[\"tag1\",\"tag2\"],\"tlp\":\"myTlp\",\"pap\":\"myPap\",\"category\":\"myCategory\"}";
  expect(putMock).toHaveBeenCalledWith('case/', body);
  expect(showErrorMock).toHaveBeenCalledTimes(0);
  expectCaseDetails();
  expect(comp.associations['history'].length).toBe(0);
  expect(comp.$root.loading).toBe(false);
  expect(comp.mruCases.length).toBe(1);
});

test('modifyCaseNotFound', async () => {
  const showErrorMock = mockShowError();
  const error = new Error("not found")
  error.response = { status: 404 };
  mockPapi("put", null, error);
  await comp.modifyCase();
  expect(showErrorMock).toHaveBeenCalledWith(comp.i18n.notFound);
});

test('modifyCaseError', async () => {
  const showErrorMock = mockShowError();
  mockPapi("put", null, new Error("something bad"));
  await comp.modifyCase();
  expect(showErrorMock).toHaveBeenCalledTimes(1);
});

test('addAssociation', async () => {
  const mock = mockPapi("post", {'data':fakeComment});

  comp.associatedForms['comments'].id = 'myCommentId';
  comp.associatedForms['comments'].description = 'myDescription';
  const showErrorMock = mockShowError();
  expect(comp.associations['comments'].length).toBe(0);

  await comp.addAssociation('comments');

  const body =  "{\"id\":\"myCommentId\",\"caseId\":\"\",\"description\":\"myDescription\",\"valid\":false}";
  expect(mock).toHaveBeenCalledWith('case/comments', body);
  expect(showErrorMock).toHaveBeenCalledTimes(0);
  expect(comp.associations['comments'].length).toBe(1);
  expect(comp.$root.loading).toBe(false);
});

test('addAssociationError', async () => {
  const showErrorMock = mockShowError();
  mockPapi("post", null, new Error("something bad"));
  await comp.addAssociation('comments');
  expect(showErrorMock).toHaveBeenCalledTimes(1);
});

test('modifyAssociation', async () => {
  const fakeComment2 = {
    id: fakeComment.id,
    description: 'myDescription2',
    caseId: fakeCase.id,
    userId: 'myUserId',
  }
  const mock = mockPapi("put", {'data':fakeComment2});
  const showErrorMock = mockShowError();

  comp.associatedForms['comments'].id = fakeComment.id;
  comp.associatedForms['comments'].description = 'myDescription2';
  comp.associations['comments'] = [fakeComment];
  await comp.modifyAssociation('comments');

  const body =  "{\"id\":\"myCommentId\",\"caseId\":\"\",\"description\":\"myDescription2\",\"valid\":false}";
  expect(mock).toHaveBeenCalledWith('case/comments', body);
  expect(showErrorMock).toHaveBeenCalledTimes(0);
  expect(comp.associations['comments'].length).toBe(1);
  expect(comp.associations['comments'][0].description).toBe('myDescription2');
  expect(comp.$root.loading).toBe(false);
});

test('modifyAssociationNotFound', async () => {
  const showErrorMock = mockShowError();
  const error = new Error("not found")
  error.response = { status: 404 };
  mockPapi("put", null, error);
  comp.associatedForms['comments'].id = fakeComment.id;
  comp.associations['comments'] = [fakeComment];
  await comp.modifyAssociation('comments');
  expect(showErrorMock).toHaveBeenCalledWith(comp.i18n.notFound);
});

test('modifyAssociationError', async () => {
  const showErrorMock = mockShowError();
  mockPapi("put", null, new Error("something bad"));
  comp.associatedForms['comments'].id = fakeComment.id;
  comp.associations['comments'] = [fakeComment];
  await comp.modifyAssociation('comments');
  expect(showErrorMock).toHaveBeenCalledTimes(1);
});

test('deleteAssociation', async () => {
  const params = {
    params: {
      id: 'myCommentId'
    }
  };
  const mock = mockPapi("delete");

  const showErrorMock = mockShowError();

  comp.associations['comments'] = [fakeComment];
  await comp.deleteAssociation('comments', fakeComment);

  expect(mock).toHaveBeenCalledWith('case/comments', params);
  expect(showErrorMock).toHaveBeenCalledTimes(0);
  expect(comp.associations['comments'].length).toBe(0);
  expect(comp.$root.loading).toBe(false);
});

test('deleteAssociationNotFound', async () => {
  const showErrorMock = mockShowError();
  const error = new Error("not found")
  error.response = { status: 404 };
  mockPapi("delete", null, error);
  comp.associations['comments'] = [fakeComment];
  await comp.deleteAssociation('comments', fakeComment);
  expect(showErrorMock).toHaveBeenCalledWith(comp.i18n.notFound);
});

test('deleteAssociationError', async () => {
  const showErrorMock = mockShowError();
  mockPapi("delete", null, new Error("something bad"));
  comp.associations['comments'] = [fakeComment];
  await comp.deleteAssociation('comments', fakeComment);
  expect(showErrorMock).toHaveBeenCalledTimes(1);
});

test('editComment', () => {
  comp.editComment(fakeComment);
  expect(comp.associatedForms['comments'].id).toBe(fakeComment.id);
  expect(comp.associatedForms['comments'].description).toBe(fakeComment.description);
});

test('cancelComment', () => {
  comp.cancelComment(fakeComment);
  expect(comp.associatedForms['comments'].id).toBe("");
  expect(comp.associatedForms['comments'].description).toBe("");
});
