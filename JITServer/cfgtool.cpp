/*

Copyright 2018 Google LLC

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

// This code is intended for security research purposes

#include <stdio.h>
#include "windows.h"

struct location {
	size_t original_address;
	size_t original_value;
	location *ptrvalue;
	location *reverseptr;
	unsigned int hops;
	unsigned int offset;
};

struct region {
	size_t base_address;
	size_t size;
	location *data;
};

struct resultline {
	size_t address;
	unsigned offset;
	size_t address2;
	size_t dest;
	bool goal;
};

region *regions;
size_t numregions;
size_t minaddress;
size_t maxaddress;

size_t start_min;
size_t start_max;
size_t goal_min;
size_t goal_max;

resultline *resultbuf;

unsigned int maxhops;
unsigned int maxoffset;

region *findregion(size_t address) {
	if (address < minaddress) return NULL;
	if (address > maxaddress) return NULL;
	long long l = 0;
	long long r = numregions - 1;
	long long m;
	while (l <= r) {
		m = (l + r) / 2;
		if (address > (regions[m].base_address + regions[m].size - 1)) {
			l = m + 1;
		} else if (address < regions[m].base_address) {
			r = m - 1;
		} else {
			return &(regions[m]);
		}
	}

	return NULL;
}

location* findlocation(size_t address) {
	region *r = findregion(address);
	if (!r) return 0;
	return &(r->data[(address - r->base_address) / sizeof(void *)]);
}

void printresult(location *loc) {
	location *data;
	size_t index;
	location *offset0;
	location *withoffset;

	bool goal = true;
	int resultsize = 0;

	printf("\nGoal reached:\n");
	withoffset = loc;
	while (1) {
		data = findregion(withoffset->original_address)->data;
		index = ((size_t)withoffset - (size_t)data) / sizeof(location);
		offset0 = &(data[index - data[index].offset / sizeof(void *)]);

		resultbuf[resultsize].address = offset0->original_address;
		resultbuf[resultsize].offset = withoffset->offset;
		resultbuf[resultsize].address2 = withoffset->original_address;
		resultbuf[resultsize].goal = goal;
		if (goal) {
			resultbuf[resultsize].dest = 0;
			goal = false;
		}
		else {
			resultbuf[resultsize].dest = withoffset->ptrvalue->original_address;
		}

		if (offset0->hops == 0) break;
		withoffset = offset0->reverseptr;
		resultsize++;
	}

	for (int i = resultsize; i >= 0; i--) {
		if (resultbuf[i].goal) {
			printf("%p + %x = %p (goal address)\n", (void *)resultbuf[i].address, resultbuf[i].offset, (void *)resultbuf[i].address2);
		} else {
			printf("%p + %x = %p -> %p\n", (void *)resultbuf[i].address, resultbuf[i].offset, (void *)resultbuf[i].address2, (void *)resultbuf[i].dest);
		}
	}
}

bool markaddressrange(size_t minaddress, size_t maxaddress, unsigned int hopsvalue, unsigned int offsetvalue) {
	bool ret = false;
	for (size_t address = minaddress; address < maxaddress; ) {
		region *r = findregion(address);
		if (!r) {
			address += sizeof(void *);
			continue;
		}
		size_t startindex = (address - r->base_address) / sizeof(void *);
		size_t endindex = r->size / sizeof(void *);
		location *data = r->data;
		for (size_t i = startindex; i < endindex; i++) {
			data[i].hops = hopsvalue;
			data[i].offset = offsetvalue;
			address += sizeof(void *);
			ret = true;
			if (address >= maxaddress) break;
		}
	}
	return ret;
}

void propagatepointers() {
	for (size_t i = 0; i < numregions; i++) {
		location *data = regions[i].data;
		size_t numlocs = regions[i].size / sizeof(void *);
		for (size_t j = 0; j < numlocs; j++) {
			if (!data[j].ptrvalue) continue;
			if (data[j].hops >= 0xfffffff0) continue;
			if (data[j].ptrvalue->hops > (data[j].hops + 1)) {
				bool goal = (data[j].ptrvalue->hops == 0xfffffffe);
				data[j].ptrvalue->hops = data[j].hops + 1;
				data[j].ptrvalue->offset = 0;
				data[j].ptrvalue->reverseptr = &data[j];
				if (goal) {
					printresult(data[j].ptrvalue);
					data[j].ptrvalue->hops = 0xfffffffd;
				}
			}
		}
	}
}

void propagateoffsets() {
	for (size_t i = 0; i < numregions; i++) {
		location *data = regions[i].data;
		size_t numlocs = regions[i].size / sizeof(void *);
		for (size_t j = 0; j < numlocs - 1; j++) {
			if (data[j].hops >= 0xfffffff0) continue;
			if (data[j].offset + sizeof(void *) > maxoffset) continue;
			if (data[j + 1].hops > data[j].hops) {
				data[j + 1].offset = data[j].offset + sizeof(void *);
				data[j + 1].hops = data[j].hops;
			}
		}
	}
}

int main(int argc, char**argv)
{
	if (argc < 6) {
		printf("Usage: %s <pid> <startaddress> <goal address range> <max hops> <max offset>\n", argv[0]);
		return 0;
	}

	int pid = atoi(argv[1]);

	char *dash;
	dash = strchr(argv[2], '-');
	if (!dash) {
		start_min = strtoull(argv[2], NULL, 16);
		start_max = start_min + sizeof(void *);
	} else {
		start_min = strtoull(argv[2], NULL, 16);
		start_max = strtoull(dash + 1, NULL, 16);
	}

	dash = strchr(argv[3], '-');
	if (!dash) {
		goal_min = strtoull(argv[3], NULL, 16);
		goal_max = goal_min + sizeof(void *);
	}
	else {
		goal_min = strtoull(argv[3], NULL, 16);
		goal_max = strtoull(dash + 1, NULL, 16);
	}

	maxhops = atoi(argv[4]);
	maxoffset = atoi(argv[5]);

	resultbuf = (resultline *)malloc(maxoffset * sizeof(resultline));

	HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
	if (!proc) {
		printf("Error opening process\n");
		return 0;
	}

	MEMORY_BASIC_INFORMATION meminfobuf;
	size_t address = 0;

	numregions = 0;
	size_t regionbufsize = 1024;
	regions = (region *)malloc(regionbufsize * sizeof(region));

	DWORD readflags = PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_READWRITE |
		PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY;

	printf("Reading memory layout from process...");

	while (1) {
		size_t ret = VirtualQueryEx(proc, (LPCVOID)address, &meminfobuf, sizeof(MEMORY_BASIC_INFORMATION));
		if (!ret) break;

		if ((meminfobuf.State & MEM_COMMIT) && (meminfobuf.Protect & readflags) && !(meminfobuf.Protect & PAGE_GUARD)) {
			if (numregions >= regionbufsize) {
				regionbufsize += 1024;
				regions = (region *)realloc(regions, regionbufsize * sizeof(region));
			}

			regions[numregions].base_address = (size_t)meminfobuf.BaseAddress;
			regions[numregions].size = meminfobuf.RegionSize;
			numregions++;
		}

		address = (size_t)meminfobuf.BaseAddress + meminfobuf.RegionSize;
	}

	if (numregions == 0) {
		printf("Error reading memory layout\n");
		return 0;
	}

	printf("done\n");

	regions = (region *)realloc(regions, numregions * sizeof(region));

	printf("Reading data from process...");

	for (size_t i = 0; i < numregions; i++) {
		size_t *buf = (size_t *)malloc(regions[i].size);
		memset(buf, 0, regions[i].size);
		size_t numbytesread;

		if (!ReadProcessMemory(proc, (LPCVOID)regions[i].base_address, (LPVOID)buf, regions[i].size, &numbytesread)) {
			printf("Error reading process memory\n");
			return 0;
		}

		size_t numlocations = regions[i].size / sizeof(size_t);
		location *locations = (location *)malloc(numlocations * sizeof(location));
		for (size_t j = 0; j < numlocations; j++) {
			locations[j].original_value = buf[j];
			locations[j].original_address = regions[i].base_address + j * sizeof(void *);
		}
		regions[i].data = locations;

		free(buf);
	}

	minaddress = regions[0].base_address;
	maxaddress = regions[numregions - 1].base_address + regions[numregions - 1].size - 1;

	printf("done\n");

	printf("Preliminary analysis...");

	size_t numlocations=0, numpointers=0;

	for (size_t i = 0; i < numregions; i++) {
		location *data = regions[i].data;
		for (size_t j = 0; j < (regions[i].size / sizeof(void *)); j++) {
			data[j].hops = 0xffffffff;
			data[j].offset = 0xffffffff;
			data[j].reverseptr = NULL;
			numlocations++;
			if (data[j].original_value < minaddress || data[j].original_value > maxaddress) {
				data[j].ptrvalue = NULL;
				continue;
			}
			region *r = findregion(data[j].original_value);
			if (!r) {
				data[j].ptrvalue = NULL;
				continue;
			}
			data[j].ptrvalue = &(r->data[(data[j].original_value - r->base_address) / sizeof(void *)]);
			numpointers++;
		}
	}

	printf("done\n");

	printf("Scanned %lld memory locations, found %lld pointers\n", numlocations, numpointers);

	//mark start addresses
	if (!markaddressrange(start_min, start_max, 0, 0)) {
		printf("Error: Start address is not in readable memory\n");
		return 0;
	}

	//mark goal addresses
	if (!markaddressrange(goal_min, goal_max, 0xfffffffe, 0xfffffffe)) {
		printf("Error: Goal address is not in readable memory\n");
		return 0;
	}

	for (unsigned int i = 1; i < maxhops; i++) {
		printf("hop %d\n", i);
		propagateoffsets();
		propagatepointers();
	}

	return 0;
}

