// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <checkqueue.h>
#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/script.h>

#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <optional>
#include <utility>
#include <vector>

namespace {

CTransaction MakeTransaction(size_t input_count, const std::vector<CAmount>& output_amounts)
{
    CMutableTransaction tx;
    tx.vin.resize(input_count);
    for (const CAmount amount : output_amounts) {
        tx.vout.emplace_back(amount, CScript{});
    }
    return CTransaction{tx};
}

void CheckCcvFailure(const CTransaction& tx, const CcvTransactionExecutionData& ccv_data)
{
    const auto error{ValidateCcvTransaction(tx, ccv_data)};
    BOOST_REQUIRE(error.has_value());
    BOOST_CHECK_EQUAL(*error, SCRIPT_ERR_CHECKCONTRACTVERIFY_WRONG_AMOUNT);
}

struct ConstraintWriter
{
    CcvInputExecutionData* m_output;
    std::vector<CcvAmountConstraint> m_constraints;

    std::optional<int> operator()()
    {
        m_output->m_constraints = std::move(m_constraints);
        return std::nullopt;
    }
};

} // namespace

BOOST_AUTO_TEST_SUITE(checkcontractverify_tests)

BOOST_AUTO_TEST_CASE(zero_tweak_compares_serializations)
{
    const std::vector<unsigned char> invalid_bytes(32, 0xff);
    const XOnlyPubKey invalid_key{invalid_bytes};
    BOOST_REQUIRE(!invalid_key.IsFullyValid());

    // With no tweak requested, even invalid curve-point encodings are compared
    // directly. This is both the intended consensus behavior and the fast path.
    BOOST_CHECK(invalid_key.CheckDoubleTweak(invalid_key, {}, nullptr));

    std::vector<unsigned char> different_bytes{invalid_bytes};
    different_bytes.back() = 0xfe;
    BOOST_CHECK(!invalid_key.CheckDoubleTweak(XOnlyPubKey{different_bytes}, {}, nullptr));
}

// Aggregate constraints targeting the same output must be order-independent, and
// their sum must not exceed the output amount.
BOOST_AUTO_TEST_CASE(aggregate_constraints)
{
    const CTransaction exact_tx{MakeTransaction(/*input_count=*/3, {600})};
    CcvTransactionExecutionData ccv_data{exact_tx.vin.size()};
    ccv_data.m_inputs[0].m_constraints.push_back(CcvAmountConstraint::Aggregate(0, 100));
    ccv_data.m_inputs[1].m_constraints.push_back(CcvAmountConstraint::Aggregate(0, 200));
    ccv_data.m_inputs[2].m_constraints.push_back(CcvAmountConstraint::Aggregate(0, 300));

    BOOST_CHECK(!ValidateCcvTransaction(exact_tx, ccv_data).has_value());
    BOOST_CHECK(!ValidateCcvTransaction(MakeTransaction(3, {601}), ccv_data).has_value());
    CheckCcvFailure(MakeTransaction(3, {599}), ccv_data);

    CcvTransactionExecutionData reversed_data{exact_tx.vin.size()};
    reversed_data.m_inputs[0].m_constraints.push_back(CcvAmountConstraint::Aggregate(0, 300));
    reversed_data.m_inputs[1].m_constraints.push_back(CcvAmountConstraint::Aggregate(0, 200));
    reversed_data.m_inputs[2].m_constraints.push_back(CcvAmountConstraint::Aggregate(0, 100));
    BOOST_CHECK(!ValidateCcvTransaction(exact_tx, reversed_data).has_value());
}

// Exclusive constraints may appear once on their own, but must conflict with any
// aggregate constraint (including a zero-valued one) or another exclusive constraint.
BOOST_AUTO_TEST_CASE(exclusive_constraints)
{
    const CTransaction tx{MakeTransaction(/*input_count=*/2, {100})};

    CcvTransactionExecutionData exclusive_only{tx.vin.size()};
    exclusive_only.m_inputs[0].m_constraints.push_back(CcvAmountConstraint::Exclusive(0));
    BOOST_CHECK(!ValidateCcvTransaction(tx, exclusive_only).has_value());

    CcvTransactionExecutionData aggregate_then_exclusive{tx.vin.size()};
    aggregate_then_exclusive.m_inputs[0].m_constraints.push_back(CcvAmountConstraint::Aggregate(0, 0));
    aggregate_then_exclusive.m_inputs[1].m_constraints.push_back(CcvAmountConstraint::Exclusive(0));
    CheckCcvFailure(tx, aggregate_then_exclusive);

    CcvTransactionExecutionData exclusive_then_aggregate{tx.vin.size()};
    exclusive_then_aggregate.m_inputs[0].m_constraints.push_back(CcvAmountConstraint::Exclusive(0));
    exclusive_then_aggregate.m_inputs[1].m_constraints.push_back(CcvAmountConstraint::Aggregate(0, 0));
    CheckCcvFailure(tx, exclusive_then_aggregate);

    CcvTransactionExecutionData repeated_exclusive{tx.vin.size()};
    repeated_exclusive.m_inputs[0].m_constraints.push_back(CcvAmountConstraint::Exclusive(0));
    repeated_exclusive.m_inputs[1].m_constraints.push_back(CcvAmountConstraint::Exclusive(0));
    CheckCcvFailure(tx, repeated_exclusive);
}

// Reject malformed transaction-wide data, invalid output indices and amounts, and
// aggregate sums that would exceed the monetary range.
BOOST_AUTO_TEST_CASE(malformed_constraints)
{
    const CTransaction tx{MakeTransaction(/*input_count=*/2, {MAX_MONEY})};

    CcvTransactionExecutionData wrong_input_count{/*input_count=*/1};
    CheckCcvFailure(tx, wrong_input_count);

    CcvTransactionExecutionData bad_index{tx.vin.size()};
    bad_index.m_inputs[0].m_constraints.push_back(CcvAmountConstraint::Aggregate(1, 1));
    CheckCcvFailure(tx, bad_index);

    CcvTransactionExecutionData negative_amount{tx.vin.size()};
    negative_amount.m_inputs[0].m_constraints.push_back(CcvAmountConstraint::Aggregate(0, -1));
    CheckCcvFailure(tx, negative_amount);

    CcvTransactionExecutionData overflow{tx.vin.size()};
    overflow.m_inputs[0].m_constraints.push_back(CcvAmountConstraint::Aggregate(0, MAX_MONEY));
    overflow.m_inputs[1].m_constraints.push_back(CcvAmountConstraint::Aggregate(0, 1));
    CheckCcvFailure(tx, overflow);
}

// Each script-check worker may write its own input result concurrently; after the
// queue barrier, the transaction-wide reducer must observe and combine every result.
BOOST_AUTO_TEST_CASE(parallel_input_results)
{
    constexpr size_t INPUT_COUNT{8};
    const CTransaction tx{MakeTransaction(INPUT_COUNT, {36})};
    CcvTransactionExecutionData ccv_data{tx.vin.size()};

    CCheckQueue<ConstraintWriter> queue{/*batch_size=*/1, /*worker_threads_num=*/4};
    CCheckQueueControl<ConstraintWriter> control{&queue};
    std::vector<ConstraintWriter> writers;
    writers.reserve(INPUT_COUNT);
    for (size_t i = 0; i < INPUT_COUNT; ++i) {
        writers.push_back({&ccv_data.m_inputs[i], {CcvAmountConstraint::Aggregate(0, i + 1)}});
    }
    control.Add(std::move(writers));

    BOOST_CHECK(!control.Complete().has_value());
    BOOST_CHECK(!ValidateCcvTransaction(tx, ccv_data).has_value());
    CheckCcvFailure(MakeTransaction(INPUT_COUNT, {35}), ccv_data);
}

BOOST_AUTO_TEST_SUITE_END()
