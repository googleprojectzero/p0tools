// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "mte.h"

#include <sys/prctl.h>

void mte_enable(bool sync, uint16_t tag_mask) {
  int ctrl = PR_TAGGED_ADDR_ENABLE | (sync ? PR_MTE_TCF_SYNC : PR_MTE_TCF_ASYNC);
  ctrl |= tag_mask << PR_MTE_TAG_SHIFT;
  assert(0 == prctl(PR_SET_TAGGED_ADDR_CTRL, ctrl, 0, 0, 0));
}

void mte_disable() {
  assert(0 == prctl(PR_SET_TAGGED_ADDR_CTRL, PR_MTE_TCF_NONE, 0, 0, 0));
}
