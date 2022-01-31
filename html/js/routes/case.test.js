// Copyright 2020-2022 Security Onion Solutions. All rights reserved.
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
const fakeComment2 = {
  userId: 'myUserId2',
  id: 'myCommentId2',
  description: 'myDescription2',
};
const fakeFormKeyStr = 'description';
const fakeEditVal = 'fakeVal';
const fakeId = 'fakeId';
const fakeEditFieldObj = {
  val: fakeEditVal,
  field: fakeId
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
  expect(comp.loadAssociation).toHaveBeenCalledWith('tasks');
  expect(comp.loadAssociation).toHaveBeenCalledWith('evidence');
  expect(comp.loadAssociation).toHaveBeenCalledWith('events');
  expect(comp.loadAssociation).toHaveBeenCalledWith('history');
});

test('loadSingleAssociation', async () => {
  const params = { params: {
          id: 'myUserId',
          offset: 0,
          count: 500,
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
  expect(comp.$root.loading).toBe(false);
});

test('loadSingleAssociationError', async () => {
  const showErrorMock = mockShowError();
  resetPapi().mockPapi("get", null, new Error("something bad"));
  await comp.loadAssociation('comments');
  expect(showErrorMock).toHaveBeenCalledTimes(1);
});

expectCaseDetails = () => {
  expect(comp.caseObj).toBe(fakeCase);
  expect(comp.caseObj.owner).toBe(fakeEmail);
  expect(comp.caseObj.assignee).toBe(fakeAssigneeEmail);
}

test('createCase', async () => {
  const params = { 
    "description": comp.i18n.caseDefaultDescription,
    "title": comp.i18n.caseDefaultTitle,
  };

  // API call #1 is to get the comment list
  mockPapi("post", {'data':fakeCase});

  comp.$route.params.id = 'myCaseId';
  const showErrorMock = mockShowError();
  comp.loadAssociations = jest.fn();
  comp.$router.replace = jest.fn();

  await comp.createCase();

  expect(mock).toHaveBeenCalledWith('case/', params);
  expect(showErrorMock).toHaveBeenCalledTimes(0);
  expect(comp.$router.replace).toHaveBeenCalledWith({ name: 'case', params: { id: fakeCase.id }});
  expect(comp.$root.loading).toBe(false);
});

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

  comp.caseObj.priority = '' + fakePriority;
  comp.caseObj.severity = fakeSeverity;
  comp.caseObj.id = 'myCaseId';
  comp.caseObj.title = 'myTitle';
  comp.caseObj.description = 'myDescription';
  comp.caseObj.status = 'open';
  comp.caseObj.tlp = 'myTlp';
  comp.caseObj.pap = 'myPap';
  comp.caseObj.category = 'myCategory';
  comp.caseObj.tags = ['tag1', 'tag2'];
  comp.caseObj.assigneeId = 'myAssigneeId';
  comp.editForm.val = "myNewDescription";
  comp.editForm.field = "description"
  const showErrorMock = mockShowError();

  expect(comp.mruCases.length).toBe(0);

  await comp.modifyCase();

  const body =  "{\"priority\":\"33\",\"severity\":\"High\",\"id\":\"myCaseId\",\"title\":\"myTitle\",\"description\":\"myNewDescription\",\"status\":\"open\",\"tlp\":\"myTlp\",\"pap\":\"myPap\",\"category\":\"myCategory\",\"tags\":[\"tag1\",\"tag2\"],\"assigneeId\":\"myAssigneeId\"}";
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

  comp.caseObj.description = 'myDescription';
  comp.editForm.val = "myNewDescription";
  comp.editForm.field = "description"

  await comp.modifyCase();
  expect(showErrorMock).toHaveBeenCalledWith(comp.i18n.notFound);
});

test('modifyCaseError', async () => {
  const showErrorMock = mockShowError();
  mockPapi("put", null, new Error("something bad"));

  comp.caseObj.description = 'myDescription';
  comp.editForm.val = "myNewDescription";
  comp.editForm.field = "description"

  await comp.modifyCase();
  expect(showErrorMock).toHaveBeenCalledTimes(1);
});

test('addAssociation', async () => {
  const mock = mockPapi("post", {'data':fakeComment});
  getApp().showTip = jest.fn();

  comp.associatedForms['comments'].description = 'myDescription';
  comp.caseObj.id = 'myCaseId';
  const showErrorMock = mockShowError();
  expect(comp.associations['comments'].length).toBe(0);

  await comp.addAssociation('comments');

  const body =  "{\"description\":\"myDescription\",\"caseId\":\"myCaseId\",\"id\":\"\"}";
  expect(mock).toHaveBeenCalledWith('case/comments', body, undefined);
  expect(showErrorMock).toHaveBeenCalledTimes(0);
  expect(comp.associations['comments'].length).toBe(1);
  expect(comp.$root.loading).toBe(false);
  expect(getApp().showTip).toHaveBeenCalledWith(comp.i18n.saveSuccess);
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

  comp.caseObj.id = 'myCaseId';
  comp.editForm.val = 'myDescription2';
  comp.editForm.field = 'description';
  comp.associations['comments'] = [fakeComment];
  await comp.modifyAssociation('comments', fakeComment);

  const body = "{\"userId\":\"myUserId\",\"id\":\"myCommentId\",\"description\":\"myDescription2\",\"owner\":\"my@email.invalid\"}";
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
  comp.editForm.val = fakeComment.id;
  comp.associations['comments'] = [fakeComment];
  await comp.modifyAssociation('comments', fakeComment, fakeId);
  expect(showErrorMock).toHaveBeenCalledWith(comp.i18n.notFound);
});

test('modifyAssociationError', async () => {
  const showErrorMock = mockShowError();
  mockPapi("put", null, new Error("something bad"));
  comp.editForm.val = "new desc";
  comp.editForm.field = "description";
  comp.associations['comments'] = [fakeComment];
  await comp.modifyAssociation('comments', fakeComment, fakeId);
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

test('resetFormComments', () => {
  comp.associatedForms['comments'].description = "something";
  comp.resetForm('comments');
  expect(comp.associatedForms['comments'].description).toBe(undefined);
});

test('resetFormEvidence', () => {
  comp.associatedForms['evidence'].description = "something";
  comp.resetForm('evidence');
  expect(comp.associatedForms['evidence'].description).toBe(undefined);
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
  comp.editForm.roId = "fakeId";
  expect(comp.isEdit('fakeId')).toBe(true);
})

test('isEdit_False', () => {
  comp.editForm = fakeEditFieldObj;

  expect(comp.isEdit('otherFakeId')).toBe(false);
})

test('startEdit', async () => {
  const fn = jest.fn();

  await comp.startEdit('myFid', 'myVal', 'myRoId', 'myField', fn, ['foo'], true);

  const expectedObj = { 
    callback: fn,
    callbackArgs: ['foo'],
    field: 'myField',
    focusId: 'myFid',
    isMultiline: true,
    orig: 'myVal',
    roId: 'myRoId',
    val: 'myVal',
    valid: true,    
  };
  expect(comp.editForm).toStrictEqual(expectedObj);
})

test('stopEdit', () => {
  comp.editForm = fakeEditFieldObj;

  comp.stopEdit();

  expect(comp.editForm).toStrictEqual({valid:true})
})

test('stopEditSave', async () => {
  const fn = jest.fn();
  comp.editForm.field = 'fakeValOld';
  comp.editForm.val = 'fakeEditVal';
  comp.editForm.valid = true
  comp.editForm.callback = fn;
  comp.modifyCase = jest.fn();

  await comp.stopEdit(true)

  expect(fn).toHaveBeenCalledTimes(1);
})

test('saveEditInvalidForm', async () => {
  const fn = jest.fn();
  comp.editForm.field = 'fakeValOld';
  comp.editForm.val = 'fakeEditVal';
  comp.editForm.valid = false
  comp.editForm.callback = fn;
  comp.modifyCase = jest.fn();

  await comp.stopEdit(true)

  expect(fn).toHaveBeenCalledTimes(0);
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

  const expectedList = [
    'presetSeverity1',
    'presetSeverity2',
    'new value'
  ]

  expect(comp.selectList('severity', 'new value')).toStrictEqual(expectedList)
})

test('expandRow', () => {
  comp.expandRow('comments', fakeComment);
  expect(comp.associatedTable['comments'].expanded.length).toBe(1);
  comp.expandRow('comments', fakeComment2);
  expect(comp.associatedTable['comments'].expanded.length).toBe(2);
  comp.expandRow('comments', fakeComment);
  expect(comp.associatedTable['comments'].expanded.length).toBe(1);
})

test('withDefault', () => {
  expect(comp.withDefault('foo', 'bar')).toBe('foo');
  expect(comp.withDefault('', 'bar')).toBe('bar');
  expect(comp.withDefault(null, 'bar')).toBe('bar');
  expect(comp.withDefault(undefined, 'bar')).toBe('bar');
})

test('getAttachmentHelp', () => {
  expect(comp.getAttachmentHelp()).toBe('Click to attach a file to upload. (Note: max upload size is 26,214,400 bytes)');
});

test('isEdited', () => {
  const fakeArtifact1 = {
    createTime: "12/25/2021, 6:01:21 PM",
    updateTime: "12/25/2021, 6:01:20 PM",
  };
  const fakeArtifact2 = {
    createTime: "12/25/2021, 6:01:21 PM",
    updateTime: "12/25/2021, 6:01:21 PM",
  };
  expect(comp.isEdited(fakeArtifact1)).toBe(true);
  expect(comp.isEdited(fakeArtifact2)).toBe(false);
});

test('mapArtifactTypeFromValue', () => {
  expect(comp.mapArtifactTypeFromValue('sub.subber.short.com')).toBe('fqdn')
  expect(comp.mapArtifactTypeFromValue('sub.short.io')).toBe('fqdn')
  expect(comp.mapArtifactTypeFromValue('short.io')).toBe('domain')
  expect(comp.mapArtifactTypeFromValue('sensoroni.com')).toBe('domain')
  expect(comp.mapArtifactTypeFromValue('/var/log/syslog.tgz')).toBe('filename')
  expect(comp.mapArtifactTypeFromValue('c:/windows/system32/malware.exe')).toBe('filename')
  expect(comp.mapArtifactTypeFromValue('/some/path/around/there')).toBe('uri_path')
  expect(comp.mapArtifactTypeFromValue('/some/path')).toBe('uri_path')
  expect(comp.mapArtifactTypeFromValue('file://some/file/path.txt')).toBe('url')
  expect(comp.mapArtifactTypeFromValue('https://some.where/out?there=foo')).toBe('url')
  expect(comp.mapArtifactTypeFromValue('2.3.113.234')).toBe('ip')
  expect(comp.mapArtifactTypeFromValue('ff02::1:ffc5:a922')).toBe('ip')
  expect(comp.mapArtifactTypeFromValue('ff02::16')).toBe('ip')
  expect(comp.mapArtifactTypeFromValue('0e2fc59194659497c8d0aec1762add1324ad2e02549bb3e41d58ca8f39e14843')).toBe('hash')
  expect(comp.mapArtifactTypeFromValue('3b43c8fadd64750525a2e285d83fa01d62227999')).toBe('hash')
  expect(comp.mapArtifactTypeFromValue('0e2fc59194659497c8d0aec1762add1324ad2e02549bb3e41d58ca8f39e14843')).toBe('hash')
  expect(comp.mapArtifactTypeFromValue('ea04541a17986a92e4d68f57e97d477845e778721044d0dcf96d380a7eddfc427a7ff0528931c39c35428cf78176da2c9741023b9c298be82521c96d547d68e8')).toBe('hash')
});

test('mapAssociatedPath', () => {
  expect(comp.mapAssociatedPath('comments')).toBe('comments');
  expect(comp.mapAssociatedPath('comments', true)).toBe('comments');
  expect(comp.mapAssociatedPath('evidence')).toBe('artifacts');
  expect(comp.mapAssociatedPath('evidence', true)).toBe('artifacts/evidence');
  expect(comp.mapAssociatedPath('attachments')).toBe('artifacts');
  expect(comp.mapAssociatedPath('attachments', true)).toBe('artifacts/attachments');
});

test('buildHuntQuery', () => {
  const fakeEvent = { fields: { soc_id: 'xyz' }};
  expect(comp.buildHuntQuery(fakeEvent)).toBe('_id: "xyz"');
});

test('getEventId', () => {
  const fakeEvent = { fields: { soc_id: 'xyz' }};
  expect(comp.getEventId(fakeEvent)).toBe('xyz');
  expect(comp.getEventId({ fields: {}})).toBe(comp.i18n.caseEventIdAggregation);
});

test('duplicateEventFields', () => {
    obj = { fields: { 'event.dataset': 'foo', 'event.module': 'bar', 'event.category': 'sho', 'event.blah': 'nope' }};
    comp.duplicateEventFields(obj);
    expect(obj.fields['event.dataset']).toBe('foo');
    expect(obj.fields['event.module']).toBe('bar');
    expect(obj.fields['event.category']).toBe('sho');
    expect(obj.fields['event.blah']).toBe('nope');
    expect(obj.fields['___event_dataset']).toBe('foo');
    expect(obj.fields['___event_module']).toBe('bar');
    expect(obj.fields['___event_category']).toBe('sho');
    expect(obj.fields['___event_blah']).toBe(undefined);
});

test('populateAddObservableForm', () => {
  comp.presets['artifactType'] = {labels:['ip']};
  comp.activeTab = 'something';

  comp.populateAddObservableForm('foo', 'bar');
  expect(comp.associatedForms['evidence'].value).toBe('bar');
  expect(comp.associatedForms['evidence'].description).toBe('foo');
  expect(comp.associatedForms['evidence'].artifactType).toBe(undefined);
  expect(comp.activeTab).toBe('evidence');

  comp.populateAddObservableForm('foo', '3b43c8fadd64750525a2e285d83fa01d62227999');
  expect(comp.associatedForms['evidence'].value).toBe('3b43c8fadd64750525a2e285d83fa01d62227999');
  expect(comp.associatedForms['evidence'].description).toBe('foo');
  expect(comp.associatedForms['evidence'].artifactType).toBe(undefined);

  comp.populateAddObservableForm('foo', '12.34.56.78');
  expect(comp.associatedForms['evidence'].value).toBe('12.34.56.78');
  expect(comp.associatedForms['evidence'].description).toBe('foo');
  expect(comp.associatedForms['evidence'].artifactType).toBe('ip');
});

test('getUnrenderedCount', () => {
  // Empty list
  expect(comp.getUnrenderedCount('comments')).toBe(0);

  // Not quite enough to hide any
  for (var i = 0; i < 30; i++) {
    comp.associations['comments'].push({id:i});
  }
  expect(comp.getUnrenderedCount('comments')).toBe(0);

  // Now some are hidden
  for (var i = 0; i < 10; i++) {
    comp.associations['comments'].push({id:i});
  }
  expect(comp.getUnrenderedCount('comments')).toBe(10);
});

test('renderAllAssociations', () => {
  expect(comp.associatedTable['comments'].showAll).toBe(false);
  comp.renderAllAssociations('comments');
  expect(comp.associatedTable['comments'].showAll).toBe(true);
});


test('shouldRenderShowAll', () => {
  // Empty list
  expect(comp.shouldRenderShowAll('comments', 0)).toBe(false);
  expect(comp.shouldRenderShowAll('comments', 10)).toBe(false);

  // Not quite enough to hide any
  for (var i = 0; i < 30; i++) {
    comp.associations['comments'].push({id:i});
  }
  expect(comp.shouldRenderShowAll('comments', 0)).toBe(false);
  expect(comp.shouldRenderShowAll('comments', 10)).toBe(false);
  expect(comp.shouldRenderShowAll('comments', 14)).toBe(false);
  expect(comp.shouldRenderShowAll('comments', 20)).toBe(false);
  expect(comp.shouldRenderShowAll('comments', 30)).toBe(false);

  // Now some are hidden
  for (var i = 0; i < 30; i++) {
    comp.associations['comments'].push({id:i});
  }
  expect(comp.shouldRenderShowAll('comments', 0)).toBe(false);
  expect(comp.shouldRenderShowAll('comments', 10)).toBe(false);
  expect(comp.shouldRenderShowAll('comments', 14)).toBe(true);
  expect(comp.shouldRenderShowAll('comments', 20)).toBe(false);
  expect(comp.shouldRenderShowAll('comments', 30)).toBe(false);
});

test('shouldRenderAssociationRecord', () => {
  // Empty list
  expect(comp.shouldRenderAssociationRecord('comments', null, 0)).toBe(true);
  expect(comp.shouldRenderAssociationRecord('comments', null, 10)).toBe(true);

  // Not quite enough to hide any
  for (var i = 0; i < 30; i++) {
    comp.associations['comments'].push({id:i});
  }
  expect(comp.shouldRenderAssociationRecord('comments', null, 0)).toBe(true);
  expect(comp.shouldRenderAssociationRecord('comments', null, 10)).toBe(true);
  expect(comp.shouldRenderAssociationRecord('comments', null, 14)).toBe(true);
  expect(comp.shouldRenderAssociationRecord('comments', null, 20)).toBe(true);
  expect(comp.shouldRenderAssociationRecord('comments', null, 30)).toBe(true);

  // Now some are hidden
  for (var i = 0; i < 30; i++) {
    comp.associations['comments'].push({id:i});
  }
  expect(comp.shouldRenderAssociationRecord('comments', null, 0)).toBe(true);
  expect(comp.shouldRenderAssociationRecord('comments', null, 10)).toBe(true);
  expect(comp.shouldRenderAssociationRecord('comments', null, 14)).toBe(true);
  expect(comp.shouldRenderAssociationRecord('comments', null, 15)).toBe(false);
  expect(comp.shouldRenderAssociationRecord('comments', null, 20)).toBe(false);
  expect(comp.shouldRenderAssociationRecord('comments', null, 30)).toBe(false);
  expect(comp.shouldRenderAssociationRecord('comments', null, 44)).toBe(false);
  expect(comp.shouldRenderAssociationRecord('comments', null, 45)).toBe(true);
  expect(comp.shouldRenderAssociationRecord('comments', null, 50)).toBe(true);
  expect(comp.shouldRenderAssociationRecord('comments', null, 59)).toBe(true);
});