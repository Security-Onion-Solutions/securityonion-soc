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
const fakeSeverity = 'High';
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
const fakeFormKeyStr = 'description';
const fakeEditVal = 'fakeVal';
const fakeId = 'fakeId';
const fakeEditFieldObj = {
  val: fakeEditVal,
  id: fakeId
};

let comp;

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

test('loadSingleAssociation', async () => {
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

test('loadSignleAssociationError', async () => {
  const showErrorMock = mockShowError();
  resetPapi().mockPapi("get", null, new Error("something bad"));
  await comp.loadAssociation('comments');
  expect(showErrorMock).toHaveBeenCalledTimes(1);
});

expectCaseDetails = () => {
  expect(comp.mainForm.id).toBe(fakeCase.id);
  expect(comp.mainForm.title).toBe(fakeCase.title);
  expect(comp.mainForm.description).toBe(fakeCase.description);
  expect(comp.mainForm.severity).toBe(fakeCase.severity);
  expect(comp.mainForm.priority).toBe(fakeCase.priority);
  expect(comp.mainForm.status).toBe(fakeCase.status);
  expect(comp.mainForm.tlp).toBe(fakeCase.tlp);
  expect(comp.mainForm.pap).toBe(fakeCase.pap);
  expect(comp.mainForm.category).toBe(fakeCase.category);
  expect(comp.mainForm.tags).toBe(fakeCase.tags);
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

  comp.mainForm.priority = '' + fakePriority;
  comp.mainForm.severity = '' + fakeSeverity;
  comp.mainForm.id = 'myCaseId';
  comp.mainForm.title = 'myTitle';
  comp.mainForm.description = 'myDescription';
  comp.mainForm.status = 'open';
  comp.mainForm.tlp = 'myTlp';
  comp.mainForm.pap = 'myPap';
  comp.mainForm.category = 'myCategory';
  comp.mainForm.tags = ['tag1', 'tag2'];
  comp.mainForm.assigneeId = 'myAssigneeId';
  const showErrorMock = mockShowError(true);

  expect(comp.mruCases.length).toBe(0);

  await comp.modifyCase();

  const body =  "{\"valid\":false,\"title\":\"myTitle\",\"assigneeId\":\"myAssigneeId\",\"status\":\"open\",\"id\":\"myCaseId\",\"description\":\"myDescription\",\"severity\":\"High\",\"priority\":33,\"tags\":[\"tag1\",\"tag2\"],\"tlp\":\"myTlp\",\"pap\":\"myPap\",\"category\":\"myCategory\"}";
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

  const body = "{\"id\":\"myCommentId\",\"caseId\":\"\",\"description\":\"myDescription2\",\"valid\":false}";
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

test('presets', () => {
  expect(comp.isPresetCustomEnabled('foo')).toBe(false); // Presets not loaded
  expect(comp.getPresets('foo').length).toBe(0);

  comp.presets = {
    "category": {
      "labels": [
        "catLabel2",
        "catLabel1"
      ],
      "customEnabled": true
    },
    "tag": {
      "labels": [
        "tagLabel1"
      ]
    },
    "severity": {
      "labels": [
      ],
      "customEnabled": false
    }
  };
  expect(comp.isPresetCustomEnabled('foo')).toBe(false); // Doesn't exist
  expect(comp.getPresets('foo').length).toBe(0);

  expect(comp.isPresetCustomEnabled('category')).toBe(true);
  expect(comp.getPresets('category')[0]).toBe('catLabel2'); // order is preserved as admin has defined them (do not sort!)
  expect(comp.getPresets('category')[1]).toBe('catLabel1');

  expect(comp.isPresetCustomEnabled('tag')).toBe(false);  // missing, assume false
  expect(comp.getPresets('tag')[0]).toBe('tagLabel1');

  expect(comp.isPresetCustomEnabled('severity')).toBe(false);
  expect(comp.getPresets('severity').length).toBe(0);   // none defined
});

test('isEdit', () => {
  comp.editField = fakeEditFieldObj;
  expect(comp.isEdit('fakeId')).toBe(true);
})

test('isEdit_False', () => {
  comp.editField = fakeEditFieldObj;

  expect(comp.isEdit('otherFakeId')).toBe(false);
})

test('startEdit', () => {

  comp.startEdit(fakeEditVal, fakeId);

  const expectedObj = { val: 'fakeVal', id: 'fakeId' };
  expect(comp.editField).toStrictEqual(expectedObj);
})

test('stopEdit', () => {
  comp.editField = fakeEditFieldObj;

  comp.stopEdit();

  expect(comp.editField).toStrictEqual({})
})

test('saveEdit', async () => {
  comp.mainForm[fakeFormKeyStr] = 'fakeValOld';
  comp.editField.val = fakeEditVal;

  comp.stopEdit = jest.fn();
  comp.modifyCase = jest.fn();

  await comp.saveEdit('description')

  expect(comp.stopEdit).toHaveBeenCalledTimes(0);
  expect(comp.modifyCase).toHaveBeenCalledTimes(1);
  expect(comp.modifyCase).toHaveBeenCalledWith('description');
})

test('saveEdit_NoChanges', async () => {
  comp.mainForm[fakeFormKeyStr] = fakeEditVal;
  comp.editField.val = fakeEditVal;
  comp.stopEdit = jest.fn();
  comp.modifyCase = jest.fn();

  await comp.saveEdit('description');

  expect(comp.stopEdit).toHaveBeenCalledTimes(1);
  expect(comp.modifyCase).toHaveBeenCalledTimes(0);
})

test('updateCollapsible_HeightOverflow', () => {
  const fakeElement = {
    offsetHeight: 10,
    scrollHeight: 11
  };
  document.getElementById = jest.fn(_ => fakeElement);
  comp.updateCollapsible(fakeId);

  expect(comp.collapsible).toStrictEqual(['fakeId']);
})

test('updateCollapsible_WidthOverflow', () => {
  const fakeElement = {
    offsetWidth: 10,
    scrollWidth: 11
  };
  document.getElementById = jest.fn(_ => fakeElement);
  comp.updateCollapsible(fakeId);

  expect(comp.collapsible).toStrictEqual(['fakeId']);
})

test('updateCollapsible_NoOverflow', () => {
  const fakeElement = {
    offsetHeight: 10,
    scrollHeight: 10
  };
  document.getElementById = jest.fn(_ => fakeElement);
  comp.updateCollapsible(fakeId);

  expect(comp.collapsible).toStrictEqual([]);
})

test('updateCollapsible_RemoveId', () => {
  const fakeElement = {
    offsetHeight: 10,
    scrollHeight: 10
  };
  comp.collapsible = [fakeId]

  document.getElementById = jest.fn(_ => fakeElement);
  comp.updateCollapsible(fakeId);

  expect(comp.collapsible).toStrictEqual([]);
})

test('updateCollapsible_StillCollapsible', () => {
  const fakeElement = {
    offsetHeight: 10,
    scrollHeight: 11
  };
  comp.collapsible = [fakeId]

  document.getElementById = jest.fn(_ => fakeElement);
  comp.updateCollapsible(fakeId);

  expect(comp.collapsible).toStrictEqual(['fakeId']);
})

test('isCollapsible', () => {
  comp.collapsible = [ fakeId ];

  expect(comp.isCollapsible('fakeId')).toBe(true);
})

test('isCollapsible_False', () => {
  comp.collapsible =  [];

  expect(comp.isCollapsible('fakeId')).toBe(false);
})

test('isCollapsed', () => {
  comp.collapsed = [ fakeId ];

  expect(comp.isCollapsed('fakeId')).toBe(true);
})

test('isCollapsed_False', () => {
  comp.collapsed =  [];

  expect(comp.isCollapsed('fakeId')).toBe(false);
})


test('toggleCollapse_Add', () => {
  comp.collapsed = [];
  
  comp.toggleCollapse(fakeId);

  expect(comp.collapsed).toStrictEqual(['fakeId']);
})

test('toggleCollapse_Remove', () => {
  comp.collapsed = [fakeId];
  
  comp.toggleCollapse('fakeId');

  expect(comp.collapsed).toStrictEqual([]);
})

test('selectList', () => {
  comp.presets = {
    'severity': {
      'labels': [
        'presetSeverity1',
        'presetSeverity2'
      ],
      'customEnabled': false
    },
  }
  
  const expectedList = [
    'presetSeverity1',
    'presetSeverity2'
  ]

  expect(comp.selectList('severity')).toStrictEqual(expectedList)
})

test('selectList_CustomEnabledNoCustomVal', () => {
  comp.presets = {
    'severity': {
      'labels': [
        'presetSeverity1',
        'presetSeverity2'
      ],
      'customEnabled': true
    },
  }
  
  const expectedList = [
    'presetSeverity1',
    'presetSeverity2',
  ]

  expect(comp.selectList('severity')).toStrictEqual(expectedList)
})

test('selectList_CustomEnabledAndCustomVal', () => {
  comp.presets = {
    'severity': {
      'labels': [
        'presetSeverity1',
        'presetSeverity2'
      ],
      'customEnabled': true
    },
  }

  comp.mainForm['severity'] = 'customSeverity1'
  
  const expectedList = [
    'presetSeverity1',
    'presetSeverity2',
    'customSeverity1'
  ]

  expect(comp.selectList('severity')).toStrictEqual(expectedList)
})
