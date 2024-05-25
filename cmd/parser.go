package main

import (
	"encoding/json"
	"errors"
)

type ActiveResponseInput struct {
	Version int               `json:"version"`
	Origin  map[string]string `json:"origin"`
	Command string            `json:"command"`
	Params  map[string]any    `json:"parameters"`
}

func ParseArg(arg *string) (*ActiveResponseInput, error) {

	var inputObj ActiveResponseInput

	if err := json.Unmarshal([]byte(*arg), &inputObj); err != nil {
		return nil, err
	}

	return &inputObj, nil

}

func ParseWazuhArg(a []string) (*map[string]any, error) {

	var inputObj *ActiveResponseInput
	var jsonString string = a[1]

	inputObj, err := ParseArg(&jsonString)

	if err != nil {
		return nil, err
	}

	alertField, ok := inputObj.Params["alert"]
	if !ok {
		return nil, errors.New("input json doesn't contain any alert")
	}

	// fmt.Println(alertField)
	// fmt.Printf("\n\nalert type: %T\n\n", alertField)

	//get the actual alert contents
	var alertContent map[string]any = alertField.(map[string]any)

	return &alertContent, nil

}
