// Minimal gtest entry point for the isolated Sovereign Bridge test executable
// (bridge_unit_tests). Kept separate from unit_tests/main.cpp, which pulls in
// p2p/net_node.inl and other heavy harness code that has pre-existing,
// bridge-unrelated compile breaks on some toolchains. This target compiles only
// the bridge test files so Phase A/B can be verified in isolation.

#include <gtest/gtest.h>

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
