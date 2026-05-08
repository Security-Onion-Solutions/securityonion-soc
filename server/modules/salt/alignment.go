// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package salt

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/security-onion-solutions/securityonion-soc/json"
	"github.com/security-onion-solutions/securityonion-soc/model"
)

func AlignInt64List(newValue string) ([]int64, error) {
	var newList []int64
	if len(newValue) > 0 {
		tmp := strings.Split(newValue, "\n")
		newList = make([]int64, 0)
		for _, str := range tmp {
			i, err := strconv.ParseInt(str, 10, 64)
			if err != nil {
				return nil, err
			}
			newList = append(newList, i)
		}
	}
	return newList, nil
}

func AlignBoolList(newValue string) ([]bool, error) {
	var newList []bool
	if len(newValue) > 0 {
		tmp := strings.Split(newValue, "\n")
		newList = make([]bool, 0)
		for _, str := range tmp {
			b, err := strconv.ParseBool(str)
			if err != nil {
				return nil, err
			}
			newList = append(newList, b)
		}
	}
	return newList, nil
}

func AlignFloat64List(newValue string) ([]float64, error) {
	var newList []float64
	if len(newValue) > 0 {
		tmp := strings.Split(newValue, "\n")
		newList = make([]float64, 0)
		for _, str := range tmp {
			f, err := strconv.ParseFloat(str, 64)
			if err != nil {
				return nil, err
			}
			newList = append(newList, f)
		}
	}
	return newList, nil
}

func AlignListList(newValue string) ([][]interface{}, error) {
	var newList [][]interface{}
	if len(newValue) > 0 {
		tmp := strings.Split(newValue, "\n")
		newList = make([][]interface{}, 0)
		for _, str := range tmp {
			l := make([]interface{}, 0)
			err := json.LoadJson([]byte(str), &l)
			if err != nil {
				return nil, err
			}
			newList = append(newList, l)
		}
	}
	return newList, nil
}

func AlignMapList(newValue string) ([]map[string]interface{}, error) {
	var newList []map[string]interface{}
	if len(newValue) > 0 {
		tmp := strings.Split(newValue, "\n")
		newList = make([]map[string]interface{}, 0)
		for _, str := range tmp {
			m := make(map[string]interface{})
			err := json.LoadJson([]byte(str), &m)
			if err != nil {
				return nil, err
			}
			newList = append(newList, m)
		}
	}
	return newList, nil
}

func InterfaceToString(v any) string {
	switch val := v.(type) {
	case string:
		return val
	case float64:
		if val == float64(int64(val)) {
			return strconv.FormatInt(int64(val), 10)
		}
		return strconv.FormatFloat(val, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(val)
	case []any:
		parts := make([]string, len(val))
		for i, item := range val {
			parts[i] = InterfaceToString(item)
		}
		return strings.Join(parts, "\n")
	default:
		return fmt.Sprintf("%v", v)
	}
}

func CoerceMapListFieldTypes(list []map[string]any, uiElements []model.UiElement) ([]map[string]any, error) {
	for _, m := range list {
		for _, uiElement := range uiElements {
			if uiElement.ForcedType == "" || uiElement.Field == "" {
				continue
			}
			fieldVal, exists := m[uiElement.Field]
			if !exists {
				continue
			}
			coerced, err := ForceType(InterfaceToString(fieldVal), uiElement.ForcedType)
			if err != nil {
				if uiElement.Required {
					return nil, fmt.Errorf("field %q: %w", uiElement.Field, err)
				} else {
					coerced = ZeroForType(uiElement.ForcedType)
				}
			}
			m[uiElement.Field] = coerced
		}
	}
	return list, nil
}

func AlignBestGuess(newValue string) interface{} {
	i, err := strconv.ParseInt(newValue, 10, 64)
	if err == nil {
		return i
	}
	f, err := strconv.ParseFloat(newValue, 64)
	if err == nil {
		return f
	}
	b, err := strconv.ParseBool(newValue)
	if err == nil {
		return b
	}
	if strings.Contains(newValue, "\n") {
		output, _ := AlignBestGuessList(newValue)
		return output
	}

	if strings.HasPrefix(newValue, "{") && strings.HasSuffix(newValue, "}") {
		tmp := make(map[string]interface{})
		err := json.LoadJson([]byte(newValue), &tmp)
		if err == nil {
			return tmp
		}
	}
	if strings.HasPrefix(newValue, "[") && strings.HasSuffix(newValue, "]") {
		tmp := make([]interface{}, 0)
		err := json.LoadJson([]byte(newValue), &tmp)
		if err == nil {
			return tmp
		}
	}
	return newValue
}

func ForceType(newValue string, forcedType string) (interface{}, error) {
	switch forcedType {
	case "float":
		return strconv.ParseFloat(newValue, 64)
	case "int":
		return strconv.ParseInt(newValue, 10, 64)
	case "bool":
		return strconv.ParseBool(newValue)
	case "string":
		return newValue, nil
	case "[]int":
		return AlignInt64List(newValue)
	case "[]bool":
		return AlignBoolList(newValue)
	case "[]float":
		return AlignFloat64List(newValue)
	case "[]string":
		if len(newValue) > 0 {
			return strings.Split(newValue, "\n"), nil
		}
		return make([]string, 0), nil
	case "[][]":
		return AlignListList(newValue)
	case "[]{}":
		return AlignMapList(newValue)
	}
	return "", errors.New("Unsupported forced type: " + forcedType)
}

func ZeroForType(typ string) any {
	switch typ {
	case "float":
		return float64(0)
	case "int":
		return int64(0)
	case "bool":
		return false
	case "string":
		return ""
	case "[]int":
		return make([]int64, 0)
	case "[]bool":
		return make([]bool, 0)
	case "[]float":
		return make([]float64, 0)
	case "[]string":
		return make([]string, 0)
	case "[][]":
		return make([][]interface{}, 0)
	case "[]{}":
		return make([]map[string]interface{}, 0)
	}

	return nil
}

func AlignBestGuessList(newValue string) (interface{}, error) {
	var newList []string
	if len(newValue) > 0 {
		newList = strings.Split(newValue, "\n")
		if len(newList) > 0 {
			firstValue := newList[0]
			bestGuess := AlignBestGuess(firstValue)
			switch bestGuess.(type) {
			case int:
				return AlignInt64List(newValue)
			case int64:
				return AlignInt64List(newValue)
			case bool:
				return AlignBoolList(newValue)
			case float32:
				return AlignFloat64List(newValue)
			case float64:
				return AlignFloat64List(newValue)
			case []interface{}:
				return AlignListList(newValue)
			case map[string]interface{}:
				return AlignMapList(newValue)
			}
		}
	}
	return newList, nil
}

func AlignType(oldValue interface{}, newValue string) (interface{}, error) {
	if oldValue != nil {
		switch oldValue.(type) {
		case float64:
			return strconv.ParseFloat(newValue, 64)
		case int:
			return strconv.ParseInt(newValue, 10, 64)
		case bool:
			return strconv.ParseBool(newValue)
		case []interface{}:
			newList := oldValue.([]interface{})
			if len(newList) > 0 {
				switch newList[0].(type) {
				case int:
					return AlignInt64List(newValue)
				case int64:
					return AlignInt64List(newValue)
				case bool:
					return AlignBoolList(newValue)
				case float32:
					return AlignFloat64List(newValue)
				case float64:
					return AlignFloat64List(newValue)
				case []interface{}:
					return AlignListList(newValue)
				case map[string]interface{}:
					return AlignMapList(newValue)
				}
			}
			return AlignBestGuessList(newValue)
		case []string:
			return strings.Split(newValue, "\n"), nil
		case []int64:
			return AlignInt64List(newValue)
		case []bool:
			return AlignBoolList(newValue)
		case []float64:
			return AlignFloat64List(newValue)
		}
	}
	return AlignBestGuess(newValue), nil
}


