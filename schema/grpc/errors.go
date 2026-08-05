// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package grpc

import "errors"

// ErrNotDescriptorSet reports input that is not a serialized FileDescriptorSet.
//
// Distinguished so a caller can tell "you passed the wrong file" from "your
// descriptors describe nothing gwaf can use", which are very different problems
// and have very different fixes.
var ErrNotDescriptorSet = errors.New("grpc: not a FileDescriptorSet")
