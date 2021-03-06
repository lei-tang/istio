// Copyright 2019 Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package istioio

import (
	"path/filepath"

	"istio.io/istio/pkg/test/env"
)

// FileSelector selects a file based on the test Context.
type FileSelector interface {
	SelectFile(ctx Context) string
}

var _ FileSelector = File("")

// File is a FileSelector for a constant file.
type File string

func (f File) SelectFile(ctx Context) string {
	return string(f)
}

// IstioSrc returns a FileSelector for a file relative to the Istio source directory.
func IstioSrc(relativePath string) FileSelector {
	return File(filepath.Join(env.IstioSrc, relativePath))
}

// FileFunc returns a FileSelector from the given selection function.
func FileFunc(fn func(ctx Context) string) FileSelector {
	return &funcSelector{fn: fn}
}

type funcSelector struct {
	fn func(Context) string
}

func (s *funcSelector) SelectFile(ctx Context) string {
	return s.fn(ctx)
}
