#pragma once

#include "tinyinstinstrumentation.h"

class TinyInstHookInstrumentation : public TinyInstInstrumentation {
public:
  void Init(int argc, char **argv) override;
};
