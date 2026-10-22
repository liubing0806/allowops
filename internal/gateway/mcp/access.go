package mcp

import (
	"connectrpc.com/connect"
	"errors"
)

func accessError(code connect.Code, message string) error {
	return connect.NewError(code, errors.New(message))
}
