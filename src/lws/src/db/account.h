#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "crypto/crypto.h"  //beldex/src
#include "fwd.h"
#include "db/fwd.h"

namespace lws
{
class account
  {
    struct internal;

    std::shared_ptr<const internal> immutable_;
    std::vector<db::output_id> spendable_;
    std::vector<crypto::public_key> pubs_;
    std::vector<db::spend> spends_;
    std::vector<db::output> outputs_;
    db::block_id height_;

    explicit account(std::shared_ptr<const internal> immutable, db::block_id height, std::vector<db::output_id> spendable, std::vector<crypto::public_key> pubs) noexcept;
    void null_check() const;

  public:

    //! Construct an account from `source` and current `spendable` outputs.
    explicit account(db::account const& source, std::vector<db::output_id> spendable, std::vector<crypto::public_key> pubs);

    /*!
      \return False if this is a "moved-from" account (i.e. the internal memory
        has been moved to another object).
    */
    explicit operator bool() const noexcept { return immutable_ != nullptr; }

    account(const account&) = delete;
    account(account&&) = default;
    ~account() noexcept;
    account& operator=(const account&) = delete;
    account& operator=(account&&) = default;

    //! \return A copy of `this`.
    account clone() const;

    //! \post `height() == max(new_height, height())`, `outputs().empty()`, and `spends.empty()`.
    void updated(db::block_id new_height) noexcept;

    //! \return Unique ID from the account database, possibly `db::account_id::kInvalid`.
    db::account_id id() const noexcept;

    //! \return Monero base58 string for account.
    std::string const& address() const;

    //! \return Object used for lookup in LMDB.
    db::account_address const& db_address() const;

    //! \return Extracted view public key from `address()`
    crypto::public_key const& view_public() const;

    //! \return Extracted spend public key from `address()`.
    crypto::public_key const& spend_public() const;

    //! \return Secret view key for the account.
    crypto::secret_key const& view_key() const;

    //! \return Current scan height of `this`.
    db::block_id scan_height() const noexcept { return height_; }

    //! \return True iff `id` is spendable by `this`.
    bool has_spendable(db::output_id const& id) const noexcept;

    //! \return Outputs matched during the latest scan.
    std::vector<db::output> const& outputs() const noexcept { return outputs_; }

    //! \return Spends matched during the latest scan.
    std::vector<db::spend> const& spends() const noexcept { return spends_; }

    //! Track a newly received `out`, \return `false` if `out.pub` is duplicated.
    bool add_out(db::output const& out);

    //! Track a possible `spend`.
    void add_spend(db::spend const& spend);
  };

} //lws