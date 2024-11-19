/*
Copyright 2024 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <string>
#include <unordered_map>
#include <unordered_set>

uint64_t get_symbol_address(const char *name);

void *load(char *filename, bool rebased, std::unordered_map<uint64_t, uint64_t> &address_replacements, std::unordered_map<std::string, uint64_t> &symbol_replacements);
