#include "tinyinsthookinstrumentation.h"
#include "litecov.h"
#include "function_hooks.h"

void TinyInstHookInstrumentation::Init(int argc, char **argv) {
  instrumentation = new FunctionHookInst();
  instrumentation->Init(argc, argv);

  persist = GetBinaryOption("-persist", argc, argv, false);
  num_iterations = GetIntOption("-iterations", argc, argv, 1);
}
