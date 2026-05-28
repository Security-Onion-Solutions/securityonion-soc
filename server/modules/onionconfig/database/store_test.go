package database

import (
	"context"
	"errors"
	"testing"
	"time"

	mockdb "github.com/security-onion-solutions/securityonion-soc/db/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func sp(s string) *string { return &s }

func TestMapSort(t *testing.T) {
	tests := []struct {
		name     string
		sort     string
		order    string
		expected string
	}{
		{"default desc", "", "", "ts DESC"},
		{"default asc", "", "asc", "ts ASC"},
		{"user alias", "user", "", "user_id DESC"},
		{"userId", "userId", "", "user_id DESC"},
		{"userId asc", "userId", "asc", "user_id ASC"},
		{"settingId", "settingId", "", "setting_id DESC"},
		{"node alias", "node", "", "node_id DESC"},
		{"nodeId", "nodeId", "", "node_id DESC"},
		{"oldValue", "oldValue", "", "old_value DESC"},
		{"newValue", "newValue", "", "new_value DESC"},
		{"unknown sort", "unknown", "", "ts DESC"},
		{"unknown sort asc", "unknown", "asc", "ts ASC"},
	}

	s := &Store{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, s.mapSort(tt.sort, tt.order))
		})
	}
}

func TestGetAuditHistory(t *testing.T) {
	ctx := context.Background()
	mDB := new(mockdb.MockDB)
	mRow := new(mockdb.MockRow)
	mRows := new(mockdb.MockRows)
	store := &Store{db: mDB}

	mDB.On("QueryRow", mock.Anything, mock.Anything, "s1", "n1").Return(mRow)
	mRow.On("Scan", mock.Anything).Return(nil).Run(func(args mock.Arguments) {
		*args[0].(*int) = 2
	})

	mDB.On("Query", mock.Anything, mock.Anything, "s1", "n1", 10, 0).Return(mRows, nil)
	mRows.On("Next").Return(true).Once()
	mRows.On("Next").Return(true).Once()
	mRows.On("Next").Return(false).Once()
	mRows.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Twice()
	mRows.On("Close").Return()
	mRows.On("Err").Return(nil)

	results, total, err := store.GetAuditHistory(ctx, "s1", "n1", 10, 0, "ts", "desc")
	assert.NoError(t, err)
	assert.Equal(t, 2, total)
	assert.Len(t, results, 2)
}

func TestGetAuditHistory_CountError(t *testing.T) {
	ctx := context.Background()
	mDB := new(mockdb.MockDB)
	mRow := new(mockdb.MockRow)
	store := &Store{db: mDB}

	mDB.On("QueryRow", mock.Anything, mock.Anything, "s1", "n1").Return(mRow)
	mRow.On("Scan", mock.Anything).Return(errors.New("count fail"))

	results, total, err := store.GetAuditHistory(ctx, "s1", "n1", 10, 0, "", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "GetAuditHistory count")
	assert.Nil(t, results)
	assert.Equal(t, 0, total)
}

func TestGetAuditHistory_QueryError(t *testing.T) {
	ctx := context.Background()
	mDB := new(mockdb.MockDB)
	mRow := new(mockdb.MockRow)
	mRows := new(mockdb.MockRows)
	store := &Store{db: mDB}

	mDB.On("QueryRow", mock.Anything, mock.Anything, "s1", "n1").Return(mRow)
	mRow.On("Scan", mock.Anything).Return(nil).Run(func(args mock.Arguments) {
		*args[0].(*int) = 0
	})
	mDB.On("Query", mock.Anything, mock.Anything, "s1", "n1", 10, 0).Return(mRows, errors.New("query fail"))
	mRows.On("Close").Return()

	results, total, err := store.GetAuditHistory(ctx, "s1", "n1", 10, 0, "", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "GetAuditHistory")
	assert.Nil(t, results)
	assert.Equal(t, 0, total)
}

func TestGetAuditHistory_ScanError(t *testing.T) {
	ctx := context.Background()
	mDB := new(mockdb.MockDB)
	mRow := new(mockdb.MockRow)
	mRows := new(mockdb.MockRows)
	store := &Store{db: mDB}

	mDB.On("QueryRow", mock.Anything, mock.Anything, "s1", "n1").Return(mRow)
	mRow.On("Scan", mock.Anything).Return(nil).Run(func(args mock.Arguments) {
		*args[0].(*int) = 1
	})

	mDB.On("Query", mock.Anything, mock.Anything, "s1", "n1", 10, 0).Return(mRows, nil)
	mRows.On("Next").Return(true).Once()
	mRows.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(errors.New("scan fail"))
	mRows.On("Close").Return()

	results, total, err := store.GetAuditHistory(ctx, "s1", "n1", 10, 0, "", "")
	assert.Error(t, err)
	assert.Nil(t, results)
	assert.Equal(t, 0, total)
}

func TestGetAuditHistory_RowsErr(t *testing.T) {
	ctx := context.Background()
	mDB := new(mockdb.MockDB)
	mRow := new(mockdb.MockRow)
	mRows := new(mockdb.MockRows)
	store := &Store{db: mDB}

	mDB.On("QueryRow", mock.Anything, mock.Anything, "s1", "n1").Return(mRow)
	mRow.On("Scan", mock.Anything).Return(nil).Run(func(args mock.Arguments) {
		*args[0].(*int) = 0
	})

	mDB.On("Query", mock.Anything, mock.Anything, "s1", "n1", 10, 0).Return(mRows, nil)
	mRows.On("Next").Return(false).Once()
	mRows.On("Close").Return()
	mRows.On("Err").Return(errors.New("rows err"))

	results, total, err := store.GetAuditHistory(ctx, "s1", "n1", 10, 0, "", "")
	assert.Error(t, err)
	assert.Equal(t, 0, total)
	assert.Nil(t, results)
}

func TestGetAllAuditHistory(t *testing.T) {
	ctx := context.Background()
	mDB := new(mockdb.MockDB)
	mRow := new(mockdb.MockRow)
	mRows := new(mockdb.MockRows)
	store := &Store{db: mDB}

	mDB.On("QueryRow", mock.Anything, mock.Anything).Return(mRow)
	mRow.On("Scan", mock.Anything).Return(nil).Run(func(args mock.Arguments) {
		*args[0].(*int) = 1
	})

	mDB.On("Query", mock.Anything, mock.Anything, 10, 0).Return(mRows, nil)
	mRows.On("Next").Return(true).Once()
	mRows.On("Next").Return(false).Once()
	mRows.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	mRows.On("Close").Return()
	mRows.On("Err").Return(nil)

	results, total, err := store.GetAllAuditHistory(ctx, 10, 0, "ts", "desc")
	assert.NoError(t, err)
	assert.Equal(t, 1, total)
	assert.Len(t, results, 1)
}

func TestGetAllAuditHistory_CountError(t *testing.T) {
	ctx := context.Background()
	mDB := new(mockdb.MockDB)
	mRow := new(mockdb.MockRow)
	store := &Store{db: mDB}

	mDB.On("QueryRow", mock.Anything, mock.Anything).Return(mRow)
	mRow.On("Scan", mock.Anything).Return(errors.New("count fail"))

	results, total, err := store.GetAllAuditHistory(ctx, 10, 0, "", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "GetAllAuditHistory count")
	assert.Nil(t, results)
	assert.Equal(t, 0, total)
}

func TestGetAllAuditHistory_QueryError(t *testing.T) {
	ctx := context.Background()
	mDB := new(mockdb.MockDB)
	mRow := new(mockdb.MockRow)
	mRows := new(mockdb.MockRows)
	store := &Store{db: mDB}

	mDB.On("QueryRow", mock.Anything, mock.Anything).Return(mRow)
	mRow.On("Scan", mock.Anything).Return(nil).Run(func(args mock.Arguments) {
		*args[0].(*int) = 0
	})
	mDB.On("Query", mock.Anything, mock.Anything, 10, 0).Return(mRows, errors.New("query fail"))
	mRows.On("Close").Return()

	results, total, err := store.GetAllAuditHistory(ctx, 10, 0, "", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "GetAllAuditHistory")
	assert.Nil(t, results)
	assert.Equal(t, 0, total)
}

func TestGetRevertState(t *testing.T) {
	ctx := context.Background()
	mDB := new(mockdb.MockDB)
	mRows := new(mockdb.MockRows)
	store := &Store{db: mDB}

	ts := time.Now()

	mDB.On("Query", mock.Anything, mock.Anything, mock.Anything).Return(mRows, nil)
	mRows.On("Next").Return(true).Once()
	mRows.On("Scan", mock.Anything, mock.Anything, mock.Anything).Return(nil).Run(func(args mock.Arguments) {
		*(args[0].(*string)) = "s1"
		*(args[1].(*string)) = "n1"
		val := `"old"`
		*(args[2].(**string)) = &val
	}).Once()
	mRows.On("Next").Return(false).Once()
	mRows.On("Close").Return()
	mRows.On("Err").Return(nil)

	results, err := store.GetRevertState(ctx, ts)
	assert.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "s1", results[0].SettingID)
	assert.Equal(t, "n1", results[0].NodeID)
	assert.Equal(t, `"old"`, *results[0].Value)
}

func TestGetRevertState_QueryError(t *testing.T) {
	ctx := context.Background()
	mDB := new(mockdb.MockDB)
	mRows := new(mockdb.MockRows)
	store := &Store{db: mDB}

	mDB.On("Query", mock.Anything, mock.Anything, mock.Anything).Return(mRows, errors.New("query fail"))
	mRows.On("Close").Return()

	results, err := store.GetRevertState(ctx, time.Now())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "GetRevertState")
	assert.Nil(t, results)
}

func TestGetRevertState_ScanError(t *testing.T) {
	ctx := context.Background()
	mDB := new(mockdb.MockDB)
	mRows := new(mockdb.MockRows)
	store := &Store{db: mDB}

	mDB.On("Query", mock.Anything, mock.Anything, mock.Anything).Return(mRows, nil)
	mRows.On("Next").Return(true).Once()
	mRows.On("Scan", mock.Anything, mock.Anything, mock.Anything).Return(errors.New("scan fail"))
	mRows.On("Close").Return()

	results, err := store.GetRevertState(ctx, time.Now())
	assert.Error(t, err)
	assert.Nil(t, results)
}

func TestGetRevertState_RowsErr(t *testing.T) {
	ctx := context.Background()
	mDB := new(mockdb.MockDB)
	mRows := new(mockdb.MockRows)
	store := &Store{db: mDB}

	mDB.On("Query", mock.Anything, mock.Anything, mock.Anything).Return(mRows, nil)
	mRows.On("Next").Return(false).Once()
	mRows.On("Close").Return()
	mRows.On("Err").Return(errors.New("rows err"))

	results, err := store.GetRevertState(ctx, time.Now())
	assert.Error(t, err)
	assert.Nil(t, results)
}

func TestGetAuditEntryAtTimestamp(t *testing.T) {
	ctx := context.Background()
	mDB := new(mockdb.MockDB)
	mRow := new(mockdb.MockRow)
	store := &Store{db: mDB}

	ts := time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC)

	mDB.On("QueryRow", mock.Anything, mock.Anything, "s1", "n1", mock.Anything).Return(mRow)
	mRow.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Run(func(args mock.Arguments) {
		*(args[0].(*string)) = "s1"
		*(args[1].(*string)) = "n1"
		*(args[2].(*time.Time)) = ts
		*(args[3].(*string)) = "user1"
		oldVal := `"old"`
		*(args[4].(**string)) = &oldVal
		newVal := `"new"`
		*(args[5].(**string)) = &newVal
		*(args[6].(*string)) = "test note"
	})

	entry, err := store.GetAuditEntryAtTimestamp(ctx, "s1", "n1", ts)
	assert.NoError(t, err)
	assert.Equal(t, "s1", entry.SettingID)
	assert.Equal(t, "n1", entry.NodeID)
	assert.Equal(t, "user1", entry.UserID)
	assert.Equal(t, "test note", entry.Note)
	assert.Equal(t, `"old"`, *entry.OldValue)
	assert.Equal(t, `"new"`, *entry.NewValue)
}

func TestGetAuditEntryAtTimestamp_NotFound(t *testing.T) {
	ctx := context.Background()
	mDB := new(mockdb.MockDB)
	mRow := new(mockdb.MockRow)
	store := &Store{db: mDB}

	mDB.On("QueryRow", mock.Anything, mock.Anything, "s1", "n1", mock.Anything).Return(mRow)
	mRow.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(errors.New("no rows"))

	entry, err := store.GetAuditEntryAtTimestamp(ctx, "s1", "n1", time.Now())
	assert.Error(t, err)
	assert.Nil(t, entry)
}

func TestUpdateSettingWithAudit_Upsert(t *testing.T) {
	ctx := context.Background()
	mDB := new(mockdb.MockDB)
	mTx := new(mockdb.MockTx)
	store := &Store{db: mDB}

	row := SettingRow{
		SettingID: "s1",
		Value:     sp(`"val"`),
		NodeID:    "n1",
	}
	audit := AuditEntry{
		SettingID: "s1",
		NodeID:    "n1",
		Timestamp: time.Now(),
		UserID:    "u1",
		OldValue:  sp(`"old"`),
		NewValue:  sp(`"new"`),
		Note:      "changed",
	}

	mDB.On("Begin", mock.Anything).Return(mTx, nil)
	mTx.On("Exec", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	mTx.On("Exec", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	mTx.On("Commit", mock.Anything).Return(nil)
	mTx.On("Rollback", mock.Anything).Return(nil)

	err := store.UpdateSettingWithAudit(ctx, row, audit, false)
	assert.NoError(t, err)
}

func TestUpdateSettingWithAudit_Delete(t *testing.T) {
	ctx := context.Background()
	mDB := new(mockdb.MockDB)
	mTx := new(mockdb.MockTx)
	store := &Store{db: mDB}

	row := SettingRow{SettingID: "s1", NodeID: "n1"}
	audit := AuditEntry{
		SettingID: "s1",
		NodeID:    "n1",
		Timestamp: time.Now(),
		UserID:    "u1",
		OldValue:  sp(`"old"`),
		NewValue:  nil,
		Note:      "removed",
	}

	mDB.On("Begin", mock.Anything).Return(mTx, nil)
	mTx.On("Exec", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	mTx.On("Exec", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	mTx.On("Commit", mock.Anything).Return(nil)
	mTx.On("Rollback", mock.Anything).Return(nil)

	err := store.UpdateSettingWithAudit(ctx, row, audit, true)
	assert.NoError(t, err)
}

func TestUpdateSettingWithAudit_BeginError(t *testing.T) {
	ctx := context.Background()
	mDB := new(mockdb.MockDB)
	mTx := new(mockdb.MockTx)
	store := &Store{db: mDB}

	mDB.On("Begin", mock.Anything).Return(mTx, errors.New("begin fail"))
	mTx.On("Rollback", mock.Anything).Return(nil)

	err := store.UpdateSettingWithAudit(ctx, SettingRow{}, AuditEntry{}, false)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "begin transaction")
}

func TestUpdateSettingWithAudit_UpsertError(t *testing.T) {
	ctx := context.Background()
	mDB := new(mockdb.MockDB)
	mTx := new(mockdb.MockTx)
	store := &Store{db: mDB}

	row := SettingRow{SettingID: "s1", NodeID: "n1"}
	audit := AuditEntry{SettingID: "s1", NodeID: "n1", Timestamp: time.Now()}

	mDB.On("Begin", mock.Anything).Return(mTx, nil)
	mTx.On("Exec", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(errors.New("upsert fail")).Once()
	mTx.On("Rollback", mock.Anything).Return(nil)

	err := store.UpdateSettingWithAudit(ctx, row, audit, false)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "upsert setting")
}

func TestUpdateSettingWithAudit_DeleteError(t *testing.T) {
	ctx := context.Background()
	mDB := new(mockdb.MockDB)
	mTx := new(mockdb.MockTx)
	store := &Store{db: mDB}

	row := SettingRow{SettingID: "s1", NodeID: "n1"}
	audit := AuditEntry{SettingID: "s1", NodeID: "n1", Timestamp: time.Now()}

	mDB.On("Begin", mock.Anything).Return(mTx, nil)
	mTx.On("Exec", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(errors.New("delete fail")).Once()
	mTx.On("Rollback", mock.Anything).Return(nil)

	err := store.UpdateSettingWithAudit(ctx, row, audit, true)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "delete setting")
}

func TestUpdateSettingWithAudit_InsertAuditError(t *testing.T) {
	ctx := context.Background()
	mDB := new(mockdb.MockDB)
	mTx := new(mockdb.MockTx)
	store := &Store{db: mDB}

	row := SettingRow{SettingID: "s1", Value: sp(`"v"`), NodeID: "n1"}
	audit := AuditEntry{SettingID: "s1", NodeID: "n1", Timestamp: time.Now()}

	mDB.On("Begin", mock.Anything).Return(mTx, nil)
	mTx.On("Exec", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	mTx.On("Exec", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(errors.New("audit fail")).Once()
	mTx.On("Rollback", mock.Anything).Return(nil)

	err := store.UpdateSettingWithAudit(ctx, row, audit, false)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "insert audit")
}

func TestUpdateSettingWithAudit_CommitError(t *testing.T) {
	ctx := context.Background()
	mDB := new(mockdb.MockDB)
	mTx := new(mockdb.MockTx)
	store := &Store{db: mDB}

	row := SettingRow{SettingID: "s1", Value: sp(`"v"`), NodeID: "n1"}
	audit := AuditEntry{SettingID: "s1", NodeID: "n1", Timestamp: time.Now()}

	mDB.On("Begin", mock.Anything).Return(mTx, nil)
	mTx.On("Exec", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	mTx.On("Exec", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	mTx.On("Commit", mock.Anything).Return(errors.New("commit fail"))
	mTx.On("Rollback", mock.Anything).Return(nil)

	err := store.UpdateSettingWithAudit(ctx, row, audit, false)
	assert.Error(t, err)
	assert.Equal(t, "commit fail", err.Error())
}

func TestUpdateSettingWithAudit_DuplicatedFromID(t *testing.T) {
	ctx := context.Background()
	mDB := new(mockdb.MockDB)
	mTx := new(mockdb.MockTx)
	store := &Store{db: mDB}

	row := SettingRow{
		SettingID:        "s1",
		Value:            sp(`"val"`),
		DuplicatedFromID: "orig",
		NodeID:           "n1",
	}
	audit := AuditEntry{SettingID: "s1", NodeID: "n1", Timestamp: time.Now()}

	mDB.On("Begin", mock.Anything).Return(mTx, nil)
	mTx.On("Exec", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	mTx.On("Exec", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	mTx.On("Commit", mock.Anything).Return(nil)
	mTx.On("Rollback", mock.Anything).Return(nil)

	err := store.UpdateSettingWithAudit(ctx, row, audit, false)
	assert.NoError(t, err)
}

func TestRecordAudit(t *testing.T) {
	ctx := context.Background()
	mDB := new(mockdb.MockDB)
	mTx := new(mockdb.MockTx)
	store := &Store{db: mDB}

	audit := AuditEntry{
		SettingID: "s1",
		NodeID:    "n1",
		Timestamp: time.Now(),
		UserID:    "u1",
		OldValue:  sp(`"old"`),
		NewValue:  sp(`"new"`),
		Note:      "test",
	}

	mDB.On("Begin", mock.Anything).Return(mTx, nil)
	mTx.On("Exec", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	mTx.On("Commit", mock.Anything).Return(nil)
	mTx.On("Rollback", mock.Anything).Return(nil)

	err := store.RecordAudit(ctx, audit)
	assert.NoError(t, err)
}

func TestRecordAudit_BeginError(t *testing.T) {
	ctx := context.Background()
	mDB := new(mockdb.MockDB)
	mTx := new(mockdb.MockTx)
	store := &Store{db: mDB}

	mDB.On("Begin", mock.Anything).Return(mTx, errors.New("begin fail"))
	mTx.On("Rollback", mock.Anything).Return(nil)

	err := store.RecordAudit(ctx, AuditEntry{})
	assert.Error(t, err)
	assert.Equal(t, "begin fail", err.Error())
}

func TestRecordAudit_InsertAuditError(t *testing.T) {
	ctx := context.Background()
	mDB := new(mockdb.MockDB)
	mTx := new(mockdb.MockTx)
	store := &Store{db: mDB}

	mDB.On("Begin", mock.Anything).Return(mTx, nil)
	mTx.On("Exec", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(errors.New("insert fail")).Once()
	mTx.On("Rollback", mock.Anything).Return(nil)

	err := store.RecordAudit(ctx, AuditEntry{})
	assert.Error(t, err)
	assert.Equal(t, "insert fail", err.Error())
}

func TestRecordAudit_CommitError(t *testing.T) {
	ctx := context.Background()
	mDB := new(mockdb.MockDB)
	mTx := new(mockdb.MockTx)
	store := &Store{db: mDB}

	mDB.On("Begin", mock.Anything).Return(mTx, nil)
	mTx.On("Exec", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	mTx.On("Commit", mock.Anything).Return(errors.New("commit fail"))
	mTx.On("Rollback", mock.Anything).Return(nil)

	err := store.RecordAudit(ctx, AuditEntry{})
	assert.Error(t, err)
	assert.Equal(t, "commit fail", err.Error())
}

func TestGetAllAuditHistory_ScanError(t *testing.T) {
	ctx := context.Background()
	mDB := new(mockdb.MockDB)
	mRow := new(mockdb.MockRow)
	mRows := new(mockdb.MockRows)
	store := &Store{db: mDB}

	mDB.On("QueryRow", mock.Anything, mock.Anything).Return(mRow)
	mRow.On("Scan", mock.Anything).Return(nil).Run(func(args mock.Arguments) {
		*args[0].(*int) = 1
	})

	mDB.On("Query", mock.Anything, mock.Anything, 10, 0).Return(mRows, nil)
	mRows.On("Next").Return(true).Once()
	mRows.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(errors.New("scan fail"))
	mRows.On("Close").Return()

	results, total, err := store.GetAllAuditHistory(ctx, 10, 0, "", "")
	assert.Error(t, err)
	assert.Nil(t, results)
	assert.Equal(t, 0, total)
}

func TestGetAllAuditHistory_RowsErr(t *testing.T) {
	ctx := context.Background()
	mDB := new(mockdb.MockDB)
	mRow := new(mockdb.MockRow)
	mRows := new(mockdb.MockRows)
	store := &Store{db: mDB}

	mDB.On("QueryRow", mock.Anything, mock.Anything).Return(mRow)
	mRow.On("Scan", mock.Anything).Return(nil).Run(func(args mock.Arguments) {
		*args[0].(*int) = 0
	})

	mDB.On("Query", mock.Anything, mock.Anything, 10, 0).Return(mRows, nil)
	mRows.On("Next").Return(false).Once()
	mRows.On("Close").Return()
	mRows.On("Err").Return(errors.New("rows err"))

	results, total, err := store.GetAllAuditHistory(ctx, 10, 0, "", "")
	assert.Error(t, err)
	assert.Nil(t, results)
	assert.Equal(t, 0, total)
}
