from pathlib import Path


def patch_wallet2():
    wallet = Path("/Users/apple/Documents/dhivakar/beldex-GW/src/wallet/wallet2.cpp")
    text = wallet.read_text()
    text = text.replace(
        '#include "crypto/crypto.h"\n',
        '#include "crypto/crypto.h"\n#include "crypto/eth_signature.h"\n#include "crypto/eddsa_signature.h"\n',
    )
    text = text.replace(
        "std::optional<bns::mapping_years> wallet2::bns_validate_years",
        """std::vector<wallet2::pending_tx> wallet2::create_gateway_register_tx(const crypto::public_key& gateway_id,
                                                                    const cryptonote::gateway_owner_key_v& owner_key,
                                                                    const std::string& meta_info,
                                                                    std::string *reason,
                                                                    uint32_t priority,
                                                                    uint32_t account_index,
                                                                    std::set<uint32_t> subaddr_indices)
{
  auto hf_version = get_hard_fork_version();
  if (!hf_version)
  {
    if (reason) *reason = ERR_MSG_NETWORK_VERSION_QUERY_FAILED;
    return {};
  }
  if (*hf_version < hf::hf22_gateway_addresses)
  {
    if (reason) *reason = "gateway addresses are only available from hardfork 22";
    return {};
  }

  if (!crypto::check_key(gateway_id))
  {
    if (reason) *reason = "invalid gateway id: not a valid public key";
    return {};
  }

  const bool owner_ok = std::visit([](const auto& k) -> bool {
    using T = std::decay_t<decltype(k)>;
    if constexpr (std::is_same_v<T, crypto::public_key>)          return crypto::check_key(k);
    else if constexpr (std::is_same_v<T, crypto::eth_public_key>) return crypto::check_eth_public_key(k);
    else                                                          return crypto::check_eddsa_public_key(k);
  }, owner_key);
  if (!owner_ok)
  {
    if (reason) *reason = "invalid gateway owner key for its type";
    return {};
  }

  cryptonote::tx_extra_gateway_descriptor_operation op{};
  op.op_type              = cryptonote::gateway_descriptor_op_type::register_address;
  op.address_id           = gateway_id;
  op.descriptor.owner_key = owner_key;
  op.descriptor.meta_info = meta_info;

  std::vector<uint8_t> extra;
  cryptonote::add_gateway_descriptor_operation_to_tx_extra(extra, op);

  beldex_construct_tx_params tx_params =
      wallet2::construct_params(*hf_version, txtype::register_gateway_address, priority, cryptonote::GATEWAY_ADDRESS_REGISTRATION_FEE);

  return create_transactions_2({} /*dsts*/,
                               cryptonote::TX_OUTPUT_DECOYS,
                               0 /*unlock_at_block*/,
                               priority,
                               extra,
                               account_index,
                               subaddr_indices,
                               tx_params);
}

std::optional<bns::mapping_years> wallet2::bns_validate_years""",
    )
    text = text.replace(
        "if (outputs < ((tx_params.tx_type == cryptonote::txtype::beldex_name_system || tx_params.tx_type == cryptonote::txtype::coin_burn) ? 1 : 2))",
        "if (outputs < ((tx_params.tx_type == cryptonote::txtype::beldex_name_system || tx_params.tx_type == cryptonote::txtype::coin_burn\n"
        "                    || tx_params.tx_type == cryptonote::txtype::register_gateway_address || tx_params.tx_type == cryptonote::txtype::update_gateway_address) ? 1 : 2))",
    )
    text = text.replace(
        "THROW_WALLET_EXCEPTION_IF(0 == dt.amount && tx_params.tx_type != txtype::beldex_name_system && tx_params.tx_type != txtype::coin_burn, error::zero_destination);",
        "THROW_WALLET_EXCEPTION_IF(0 == dt.amount && tx_params.tx_type != txtype::beldex_name_system && tx_params.tx_type != txtype::coin_burn\n"
        "                              && tx_params.tx_type != txtype::register_gateway_address && tx_params.tx_type != txtype::update_gateway_address, error::zero_destination);",
    )
    text = text.replace(
        "if (splitted_dsts.size() == 1 || tx.type == txtype::beldex_name_system || tx.type == txtype::coin_burn)",
        "if (splitted_dsts.size() == 1 || tx.type == txtype::beldex_name_system || tx.type == txtype::coin_burn\n"
        "        || tx.type == txtype::register_gateway_address || tx.type == txtype::update_gateway_address)",
    )
    text = text.replace(
        "if (tx_params.tx_type == txtype::beldex_name_system || tx_params.tx_type == txtype::coin_burn)",
        "if (tx_params.tx_type == txtype::beldex_name_system || tx_params.tx_type == txtype::coin_burn\n"
        "        || tx_params.tx_type == txtype::register_gateway_address || tx_params.tx_type == txtype::update_gateway_address)",
    )
    text = text.replace(
        """  bool const is_burn_tx = (tx_params.tx_type == txtype::coin_burn);
    LOG_PRINT_L0("is_burn_tx:" << is_burn_tx);  
  if (is_burn_tx)
  {
    THROW_WALLET_EXCEPTION_IF(dsts.size() != 0, error::wallet_internal_error, "Burn txs must not have any destinations set, has: " + std::to_string(dsts.size()));
    THROW_WALLET_EXCEPTION_IF(priority == 5, error::wallet_internal_error, "Can not request a flash TX for coin_burn transactions");
    dsts.emplace_back(0, account_public_address{} /*address*/, false /*is_subaddress*/); // NOTE: Create a dummy dest that gets repurposed into the change output.
  }
""",
        """  bool const is_burn_tx = (tx_params.tx_type == txtype::coin_burn);
    LOG_PRINT_L0("is_burn_tx:" << is_burn_tx);  
  if (is_burn_tx)
  {
    THROW_WALLET_EXCEPTION_IF(dsts.size() != 0, error::wallet_internal_error, "Burn txs must not have any destinations set, has: " + std::to_string(dsts.size()));
    THROW_WALLET_EXCEPTION_IF(priority == 5, error::wallet_internal_error, "Can not request a flash TX for coin_burn transactions");
    dsts.emplace_back(0, account_public_address{} /*address*/, false /*is_subaddress*/); // NOTE: Create a dummy dest that gets repurposed into the change output.
  }

  bool const is_gateway_op_tx = (tx_params.tx_type == txtype::register_gateway_address ||
                                 tx_params.tx_type == txtype::update_gateway_address);
  if (is_gateway_op_tx)
  {
    THROW_WALLET_EXCEPTION_IF(dsts.size() != 0, error::wallet_internal_error, "gateway register/update txs must not have any destinations set, has: " + std::to_string(dsts.size()));
    dsts.emplace_back(0, account_public_address{} /*address*/, false /*is_subaddress*/);
  }
""",
    )
    text = text.replace(
        "THROW_WALLET_EXCEPTION_IF(0 == dt.amount && !(is_bns_tx || is_burn_tx), error::zero_destination);",
        "THROW_WALLET_EXCEPTION_IF(0 == dt.amount && !(is_bns_tx || is_burn_tx || is_gateway_op_tx), error::zero_destination);",
    )
    text = text.replace(
        "THROW_WALLET_EXCEPTION_IF(needed_money == 0 && !(is_bns_tx || is_burn_tx), error::zero_destination);",
        "THROW_WALLET_EXCEPTION_IF(needed_money == 0 && !(is_bns_tx || is_burn_tx || is_gateway_op_tx), error::zero_destination);",
    )
    text = text.replace(
        "const uint64_t min_outputs = (tx_params.tx_type == cryptonote::txtype::beldex_name_system || tx_params.tx_type == cryptonote::txtype::coin_burn) ? 1 : 2; // if bns, only request the change output",
        "const uint64_t min_outputs = (is_bns_tx || is_burn_tx || is_gateway_op_tx) ? 1 : 2; // fee-only txs (bns/burn/gateway) request only the change output",
    )
    wallet.write_text(text)


def patch_simplewallet():
    sw = Path("/Users/apple/Documents/dhivakar/beldex-GW/src/simplewallet/simplewallet.cpp")
    text = sw.read_text()
    text = text.replace(
        '  const char* USAGE_SWEEP_UNBLIND("sweep_unblind [index=<N1>[,<N2>,...]] [<priority>] [<ring_size>] [outputs=<N>] [<address>]");\n',
        '  const char* USAGE_SWEEP_UNBLIND("sweep_unblind [index=<N1>[,<N2>,...]] [<priority>] [<ring_size>] [outputs=<N>] [<address>]");\n'
        '  const char* USAGE_REGISTER_GATEWAY_ADDRESS("register_gateway_address [index=<N1>[,<N2>,...]] [<priority>] <gateway_id_hex> <owner_type: schnorr|eth|eddsa> <owner_key_hex> [meta]");\n',
    )
    text = text.replace(
        '  m_cmd_binder.set_handler("print_locked_stakes",',
        '  m_cmd_binder.set_handler("register_gateway_address",\n'
        '                           [this](const auto& x) { return register_gateway_address(x); },\n'
        '                           tr("Register a gateway address (HF22). Burns the registration fee and stores the owner key on-chain. Args: <gateway_id_hex> <owner_type> <owner_key_hex> [meta]."));\n'
        '  m_cmd_binder.set_handler("print_locked_stakes",',
    )
    text = text.replace(
        "\n//----------------------------------------------------------------------------------------------------\nbool simple_wallet::unblackball",
        """
//----------------------------------------------------------------------------------------------------
bool simple_wallet::register_gateway_address(std::vector<std::string> args)
{
  uint32_t priority = 0;
  std::set<uint32_t> subaddr_indices = {};
  if (!parse_subaddr_indices_and_priority(*m_wallet, args, subaddr_indices, priority, m_current_subaddress_account)) return false;

  if (args.size() < 3 || args.size() > 4)
  {
    PRINT_USAGE(USAGE_REGISTER_GATEWAY_ADDRESS);
    return true;
  }

  crypto::public_key gateway_id;
  if (!tools::hex_to_type(args[0], gateway_id))
  {
    fail_msg_writer() << tr("Invalid gateway id (expected 64-char hex)");
    return true;
  }

  const std::string& owner_type = args[1];
  cryptonote::gateway_owner_key_v owner_key;
  if (owner_type == "schnorr" || owner_type == "ed25519")
  {
    crypto::public_key pk;
    if (!tools::hex_to_type(args[2], pk)) { fail_msg_writer() << tr("Invalid schnorr owner key (expected 64-char hex)"); return true; }
    owner_key = pk;
  }
  else if (owner_type == "eth")
  {
    crypto::eth_public_key pk;
    if (!tools::hex_to_type(args[2], pk)) { fail_msg_writer() << tr("Invalid eth owner key (expected 66-char hex / 33-byte compressed secp256k1)"); return true; }
    owner_key = pk;
  }
  else if (owner_type == "eddsa")
  {
    crypto::eddsa_public_key pk;
    if (!tools::hex_to_type(args[2], pk)) { fail_msg_writer() << tr("Invalid eddsa owner key (expected 64-char hex)"); return true; }
    owner_key = pk;
  }
  else
  {
    fail_msg_writer() << tr("owner_type must be one of: schnorr, eth, eddsa");
    return true;
  }
  const std::string meta = args.size() == 4 ? args[3] : std::string{};

  SCOPED_WALLET_UNLOCK();
  std::string reason;
  std::vector<tools::wallet2::pending_tx> ptx_vector;
  try
  {
    ptx_vector = m_wallet->create_gateway_register_tx(gateway_id, owner_key, meta, &reason, priority, m_current_subaddress_account, subaddr_indices);
    if (ptx_vector.empty())
    {
      fail_msg_writer() << reason;
      return true;
    }

    std::vector<cryptonote::address_parse_info> dsts;
    cryptonote::address_parse_info info = {};
    info.address       = m_wallet->get_subaddress({m_current_subaddress_account, 0});
    info.is_subaddress = m_current_subaddress_account != 0;
    dsts.push_back(info);

    const std::string gateway_address = cryptonote::get_gateway_address_as_str(m_wallet->nettype(), gateway_id);

    std::cout << std::endl << tr("Registering gateway address") << std::endl << std::endl;
    fmt::print(fmt::format(tr("Gateway addr: {}\\n"), gateway_address));
    fmt::print(fmt::format(tr("Gateway id  : {}\\n"), args[0]));
    fmt::print(fmt::format(tr("Owner type  : {}\\n"), owner_type));
    fmt::print(fmt::format(tr("Owner key   : {}\\n"), args[2]));
    fmt::print(fmt::format(tr("Meta        : {}\\n"), meta.empty() ? "(none)" : meta));
    fmt::print(fmt::format(tr("Fee burned  : {}\\n"), print_money(cryptonote::GATEWAY_ADDRESS_REGISTRATION_FEE)));
    if (!confirm_and_send_tx(dsts, ptx_vector, priority == tools::tx_priority_flash))
      return false;

    tools::success_msg_writer() << tr("Gateway address registered: ") << gateway_address;
  }
  catch (const std::exception &e)
  {
    handle_transfer_exception(std::current_exception(), m_wallet->is_trusted_daemon());
    return true;
  }
  catch (...)
  {
    LOG_ERROR("unknown error");
    fail_msg_writer() << tr("unknown error");
    return true;
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::unblackball""",
    )
    sw.write_text(text)


if __name__ == "__main__":
    patch_wallet2()
    patch_simplewallet()
