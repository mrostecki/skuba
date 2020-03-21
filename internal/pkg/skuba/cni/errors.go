/*
 * Copyright (c) 2020 SUSE LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package cni

import (
	"github.com/pkg/errors"
)

var (
	ErrCiliumDsNotReady      = errors.New("cilium daemonset is not ready")
	ErrCiliumNotFound        = errors.New("could not find cilium pod")
	ErrCiliumPodUnsuccessful = errors.New("cilium pod has unsuccessful state")
)

func IsErrCiliumDsNotReady(err error) bool {
	return err == ErrCiliumDsNotReady
}

func IsErrCiliumNotFound(err error) bool {
	return err == ErrCiliumNotFound
}
