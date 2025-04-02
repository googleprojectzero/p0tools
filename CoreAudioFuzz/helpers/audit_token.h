#include "harness.h"
#include <libproc.h>
#include <sys/sysctl.h>
#include <unistd.h>

pid_t get_pid_of_safari();

audit_token_t get_safari_audit_token();