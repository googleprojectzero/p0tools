/* 
Copyright 2025 Google LLC

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

#include "audit_token.h"

// Function to get the PID of a process by looking for "Safari.app/Contents/MacOS/Safari" in the path
pid_t get_pid_of_safari() {
    int num_pids;
    size_t len;

    // Determine the size of the buffer required to hold the list of PIDs
    if (sysctl((int[]){ CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 }, 4, NULL, &len, NULL, 0) == -1) {
        perror("sysctl");
        return -1;
    }

    pid_t *pids = (pid_t *)malloc(len);
    if (pids == NULL) {
        perror("malloc");
        return -1;
    }

    // Get the list of PIDs
    if (sysctl((int[]){ CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 }, 4, pids, &len, NULL, 0) == -1) {
        perror("sysctl");
        free(pids);
        return -1;
    }

    // Iterate over the list to find Safari
    num_pids = len / sizeof(pid_t);
    for (int i = 0; i < num_pids; i++) {
        pid_t pid = pids[i];
        if (pid == 0) {
            continue;
        }

        char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
        if (proc_pidpath(pid, pathbuf, sizeof(pathbuf)) > 0) {
            if (strstr(pathbuf, "Safari.app/Contents/MacOS/Safari") != NULL) {
                free(pids);
                return pid;
            }
        }
    }

    free(pids);
    return -1; // Return -1 if Safari was not found
}

// Function to get the audit token for the Safari process
audit_token_t get_safari_audit_token() {

    if (geteuid() != 0) {
        fprintf(stderr, "This program must be run as root! (To get the audit token of Safari)\n");
        exit(1);
    }

    pid_t pid = get_pid_of_safari();

    // If PID not found, return an empty audit_token_t
    if (pid == -1) {
        audit_token_t empty_token = { 0 };
        return empty_token;
    }

    // Get the audit token for the process
    task_t task;
    audit_token_t audit_token;
    if (task_for_pid(mach_task_self(), pid, &task) == KERN_SUCCESS) {
        mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
        if (task_info(task, TASK_AUDIT_TOKEN, (task_info_t)&audit_token, &count) != KERN_SUCCESS) {
            memset(&audit_token, 0, sizeof(audit_token)); // Return empty audit_token if failed
        }
        mach_port_deallocate(mach_task_self(), task);
    } else {
        memset(&audit_token, 0, sizeof(audit_token)); // Return empty audit_token if failed
    }

    return audit_token;
}