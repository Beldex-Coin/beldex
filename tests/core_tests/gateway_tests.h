// Copyright (c) 2024, The Beldex Project
//
// Core tests for the HF22 gateway address feature (register / update descriptor
// ops, HF gating, reorg). Deposit/withdrawal balance-equation tests are added
// once gateway RCT tx construction lands in the harness.

#pragma once

#include "chaingen.h"

struct beldex_gateway_register                    : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct beldex_gateway_register_insufficient_fee   : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct beldex_gateway_register_duplicate          : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct beldex_gateway_register_pre_hf22           : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct beldex_gateway_update                       : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct beldex_gateway_update_wrong_key            : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct beldex_gateway_register_reorg              : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
