#!/bin/bash
# -hook_functions true to hook funcs

# Get the directory of the script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Set the dynamic library path relative to the script location
DYLIB_PATH="$SCRIPT_DIR/libmach-modify.dylib"

# Original command to run
original_command="./jackalope-modifications/build/Release/coreaudiofuzzer -hook_functions true -in corpus -out out -delivery file -instrument_module CoreAudio -target_module harness -target_method _fuzz -nargs 1 -iterations 1000 -persist -loop -dump_coverage -cmp_coverage -generate_unwind -target_env DYLD_INSERT_LIBRARIES=$DYLIB_PATH -nthreads 5 -- ./harness -f @@"

# Initialize command with the original command
command="$original_command"

# Loop to keep restarting the command if it stops
while true; do
  echo "Starting the fuzzing command..."
  eval $command

  # Check if the command exited with an error code
  if [ $? -ne 0 ]; then
    echo "Command stopped unexpectedly. Restarting..."
    
    # Replace the -in parameter value with '-'
    command=$(echo "$original_command" | sed 's/-in [^ ]*/-in -/')
  else
    echo "Command completed successfully. Exiting..."
    break
  fi

done
