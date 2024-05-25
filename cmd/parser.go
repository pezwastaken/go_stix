package main

import (
	"encoding/json"
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
