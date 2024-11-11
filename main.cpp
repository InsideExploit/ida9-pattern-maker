#include "plugin/plugin.hpp"

plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_MULTI,
  pattern_maker::init,
  nullptr,
  nullptr,
  "Creates a unique pattern from selected address.",
  "Ported version of Pattern Maker to IDA 9",
  "Pattern Maker",
  "Ctrl+Alt+S"
};