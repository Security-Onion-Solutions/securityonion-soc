package thehive

import (
	"strconv"
	"time"
	"github.com/security-onion-solutions/securityonion-soc/model"
)

func convertToTheHiveCase(inputCase *model.Case) (*TheHiveCase, error) {
	outputCase := NewTheHiveCase()
	outputCase.Severity = inputCase.Severity
	if outputCase.Severity > CASE_SEVERITY_HIGH {
		outputCase.Severity = CASE_SEVERITY_HIGH
	} else if outputCase.Severity < CASE_SEVERITY_LOW {
		outputCase.Severity = CASE_SEVERITY_LOW
	}
	outputCase.Title = inputCase.Title
	outputCase.Description = inputCase.Description
	outputCase.Tags = append(outputCase.Tags, "SecurityOnion")
	outputCase.Tlp = CASE_TLP_AMBER
	return outputCase, nil
}

func convertFromTheHiveCase(inputCase *TheHiveCase) (*model.Case, error) {
	outputCase := model.NewCase()
	outputCase.Severity = inputCase.Severity
	outputCase.Title = inputCase.Title
	outputCase.Description = inputCase.Description
	outputCase.Id = strconv.Itoa(inputCase.Id)
	outputCase.Status = inputCase.Status
	outputCase.CreateTime = time.Unix(inputCase.CreateDate / 1000, 0)
	outputCase.StartTime = time.Unix(inputCase.StartDate / 1000, 0)
	outputCase.CompleteTime = time.Unix(inputCase.EndDate / 1000, 0)
	return outputCase, nil
}