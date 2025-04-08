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

#include <stdio.h>
#include <stdlib.h>
#include <mach/mach.h>
#include <sys/sysctl.h>
#include <string.h>
#include <libproc.h>

// Define PROC_PIDPATHINFO_MAXSIZE if not defined
#ifndef PROC_PIDPATHINFO_MAXSIZE
#define PROC_PIDPATHINFO_MAXSIZE 4096
#endif

// Function to get the PID of Safari
pid_t get_safari_pid() {
    // Get the size of the buffer needed
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t len = 0;
    
    if (sysctl(mib, 4, NULL, &len, NULL, 0) < 0) {
        perror("sysctl");
        return -1;
    }
    
    // Allocate memory for the process list
    pid_t *pids = (pid_t *)malloc(len);
    if (pids == NULL) {
        perror("malloc");
        return -1;
    }
    
    // Get the list of processes
    if (sysctl(mib, 4, pids, &len, NULL, 0) < 0) {
        perror("sysctl");
        free(pids);
        return -1;
    }
    
    // Iterate over the list to find Safari
    int num_pids = len / sizeof(pid_t);
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
    return -1; // Safari not found
}

int main() {
    pid_t safari_pid = get_safari_pid();
    if (safari_pid == -1) {
        printf("Safari not found.\n");
        return 1;
    }
    
    printf("Safari PID: %d\n", safari_pid);
    
    // Obtain the audit token of Safari
    task_t task;
    kern_return_t kr = task_for_pid(mach_task_self(), safari_pid, &task);
    if (kr != KERN_SUCCESS) {
        printf("Error getting task for PID %d: %s\n", safari_pid, mach_error_string(kr));
        return 1;
    }
    
    audit_token_t token;
    mach_msg_type_number_t size = TASK_AUDIT_TOKEN_COUNT;
    kr = task_info(task, TASK_AUDIT_TOKEN, (task_info_t)&token, &size);
    if (kr != KERN_SUCCESS) {
        printf("Error getting task audit_token: %s\n", mach_error_string(kr));
        return 1;
    }
    
    printf("Audit token: %d\n", token.val); // The PID is in token.val[5]
    
    return 0;
}

