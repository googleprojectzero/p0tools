#ifndef FUNCTIONHOOKS_H
#define FUNCTIONHOOKS_H

#include "TinyInst/hook.h"
#include "litecov.h"

class HALSWriteSettingHook : public HookBegin {
public:
  HALSWriteSettingHook() : HookBegin("CoreAudio", "__ZN11HALS_System13_WriteSettingEP11HALS_ClientPK10__CFStringPKv", 3, CALLCONV_DEFAULT) {}
protected:
  void OnFunctionEntered() override;
};

class FunctionHookInst : public LiteCov {
public:
  FunctionHookInst();
};

#endif
