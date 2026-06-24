# SPDX-License-Identifier: Apache-2.0
"""Tests for protocol invariant validators."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from nest_core.types import AgentId
from nest_core.validators import (
    VALIDATORS,
    ValidationResult,
    validate_auction_all_notified,
    validate_auction_single_winner,
    validate_auction_winner_highest,
    validate_consensus_agreement,
    validate_consensus_no_conflict,
    validate_consensus_validity,
    validate_events,
    validate_marketplace_no_double_sell,
    validate_marketplace_price_agreement,
    validate_marketplace_responses,
    validate_policy_approval_required,
    validate_policy_budget_cap,
    validate_policy_data_exposure,
    validate_policy_manifest_signatures,
    validate_policy_tool_allowlist,
    validate_reputation_scoring,
    validate_reputation_warnings,
    validate_supply_chain_no_lost,
    validate_supply_chain_pipeline,
    validate_trace,
    validate_voting_all_counted,
    validate_voting_no_double_vote,
    validate_voting_tally,
)

type Event = dict[str, Any]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _send(agent: str, to: str, msg: str, ts: float = 1.0) -> Event:
    return {"ts": ts, "agent": agent, "kind": "send", "to": to, "msg": msg}


def _broadcast(agent: str, msg: str, ts: float = 1.0) -> Event:
    return {"ts": ts, "agent": agent, "kind": "broadcast", "msg": msg}


# ===================================================================
# Marketplace
# ===================================================================


class TestMarketplaceNoDoubleSell:
    def test_pass_unique_sales(self) -> None:
        events = [
            _send("seller-0", "buyer-0", "sold:product-0:50"),
            _send("seller-0", "buyer-1", "sold:product-1:60"),
        ]
        results = validate_marketplace_no_double_sell(events)
        assert len(results) == 1
        assert results[0].passed is True

    def test_fail_double_sell(self) -> None:
        events = [
            _send("seller-0", "buyer-0", "sold:product-0:50"),
            _send("seller-0", "buyer-1", "sold:product-0:50"),
        ]
        results = validate_marketplace_no_double_sell(events)
        assert len(results) == 1
        assert results[0].passed is False
        assert "product-0" in results[0].detail

    def test_pass_different_sellers_same_product(self) -> None:
        events = [
            _send("seller-0", "buyer-0", "sold:product-0:50"),
            _send("seller-1", "buyer-1", "sold:product-0:60"),
        ]
        results = validate_marketplace_no_double_sell(events)
        assert results[0].passed is True

    def test_pass_no_sales(self) -> None:
        events = [
            _send("buyer-0", "seller-0", "buy:product-0:50"),
            _send("seller-0", "buyer-0", "reject:product-0:60"),
        ]
        results = validate_marketplace_no_double_sell(events)
        assert results[0].passed is True


class TestMarketplaceResponses:
    def test_pass_all_answered(self) -> None:
        events = [
            _send("buyer-0", "seller-0", "buy:product-0:50"),
            _send("seller-0", "buyer-0", "sold:product-0:50"),
            _send("buyer-1", "seller-0", "buy:product-1:30"),
            _send("seller-0", "buyer-1", "reject:product-1:40"),
        ]
        results = validate_marketplace_responses(events)
        assert results[0].passed is True

    def test_fail_unanswered_request(self) -> None:
        events = [
            _send("buyer-0", "seller-0", "buy:product-0:50"),
            _send("buyer-1", "seller-0", "buy:product-1:30"),
            _send("seller-0", "buyer-0", "sold:product-0:50"),
            # buyer-1's request for product-1 never answered
        ]
        results = validate_marketplace_responses(events)
        assert results[0].passed is False
        assert "1 unanswered" in results[0].detail

    def test_pass_no_requests(self) -> None:
        events = [
            {"ts": 0.0, "agent": "seller-0", "kind": "start"},
        ]
        results = validate_marketplace_responses(events)
        assert results[0].passed is True


class TestMarketplacePriceAgreement:
    def test_pass_price_matches_buy(self) -> None:
        events = [
            _send("buyer-0", "seller-0", "buy:product-0:50"),
            _send("seller-0", "buyer-0", "sold:product-0:50"),
        ]
        results = validate_marketplace_price_agreement(events)
        assert results[0].passed is True

    def test_pass_price_matches_counter(self) -> None:
        events = [
            _send("buyer-0", "seller-0", "buy:product-0:30"),
            _send("seller-0", "buyer-0", "reject:product-0:40"),
            _send("buyer-0", "seller-0", "buy:product-0:40"),
            _send("seller-0", "buyer-0", "sold:product-0:40"),
        ]
        results = validate_marketplace_price_agreement(events)
        assert results[0].passed is True

    def test_fail_price_mismatch(self) -> None:
        events = [
            _send("buyer-0", "seller-0", "buy:product-0:50"),
            _send("seller-0", "buyer-0", "sold:product-0:99"),
        ]
        results = validate_marketplace_price_agreement(events)
        assert results[0].passed is False
        assert "99" in results[0].detail

    def test_fail_signed_price_mismatch(self) -> None:
        events = [
            _send("buyer-0", "seller-0", "buy:product-0:50|sig:abc"),
            _send("seller-0", "buyer-0", "sold:product-0:99|sig:def"),
        ]
        results = validate_marketplace_price_agreement(events)
        assert results[0].passed is False
        assert "99" in results[0].detail

    def test_fail_sale_without_offer(self) -> None:
        events = [
            _send("seller-0", "buyer-0", "sold:product-0:50"),
        ]
        results = validate_marketplace_price_agreement(events)
        assert results[0].passed is False
        assert "without an offer" in results[0].detail


# ===================================================================
# Auction
# ===================================================================


class TestAuctionWinnerHighest:
    def test_pass_highest_wins(self) -> None:
        events = [
            _send("bidder-0", "auctioneer-0", "bid:item-1:100"),
            _send("bidder-1", "auctioneer-0", "bid:item-1:150"),
            _send("bidder-2", "auctioneer-0", "bid:item-1:120"),
            _send("auctioneer-0", "bidder-1", "won:item-1:150"),
        ]
        results = validate_auction_winner_highest(events)
        assert results[0].passed is True

    def test_fail_lower_bid_wins(self) -> None:
        events = [
            _send("bidder-0", "auctioneer-0", "bid:item-1:100"),
            _send("bidder-1", "auctioneer-0", "bid:item-1:200"),
            _send("auctioneer-0", "bidder-0", "won:item-1:100"),
        ]
        results = validate_auction_winner_highest(events)
        assert results[0].passed is False
        assert "200" in results[0].detail

    def test_pass_no_auctions(self) -> None:
        events = [{"ts": 0.0, "agent": "auctioneer-0", "kind": "start"}]
        results = validate_auction_winner_highest(events)
        assert results[0].passed is True


class TestAuctionSingleWinner:
    def test_pass_one_winner(self) -> None:
        events = [
            _send("auctioneer-0", "bidder-0", "won:item-1:100"),
            _send("auctioneer-0", "bidder-1", "lost:item-1:100"),
        ]
        results = validate_auction_single_winner(events)
        assert results[0].passed is True

    def test_fail_two_winners(self) -> None:
        events = [
            _send("auctioneer-0", "bidder-0", "won:item-1:100"),
            _send("auctioneer-0", "bidder-1", "won:item-1:100"),
        ]
        results = validate_auction_single_winner(events)
        assert results[0].passed is False
        assert "item-1" in results[0].detail

    def test_pass_different_items(self) -> None:
        events = [
            _send("auctioneer-0", "bidder-0", "won:item-1:100"),
            _send("auctioneer-0", "bidder-1", "won:item-2:150"),
        ]
        results = validate_auction_single_winner(events)
        assert results[0].passed is True


class TestAuctionAllNotified:
    def test_pass_all_notified(self) -> None:
        events = [
            _send("bidder-0", "auctioneer-0", "bid:item-1:100"),
            _send("bidder-1", "auctioneer-0", "bid:item-1:150"),
            _send("auctioneer-0", "bidder-0", "lost:item-1:150"),
            _send("auctioneer-0", "bidder-1", "won:item-1:150"),
        ]
        results = validate_auction_all_notified(events)
        assert results[0].passed is True

    def test_fail_missing_notification(self) -> None:
        events = [
            _send("bidder-0", "auctioneer-0", "bid:item-1:100"),
            _send("bidder-1", "auctioneer-0", "bid:item-1:150"),
            _send("auctioneer-0", "bidder-1", "won:item-1:150"),
            # bidder-0 never notified
        ]
        results = validate_auction_all_notified(events)
        assert results[0].passed is False
        assert "bidder-0" in results[0].detail


# ===================================================================
# Voting
# ===================================================================


class TestVotingTally:
    def test_pass_correct_tally(self) -> None:
        events = [
            _send("voter-0", "coordinator-0", "vote:1:yes:voter-0"),
            _send("voter-1", "coordinator-0", "vote:1:no:voter-1"),
            _send("voter-2", "coordinator-0", "vote:1:yes:voter-2"),
            _send("coordinator-0", "proposer-0", "result:1:passed:2/3"),
        ]
        results = validate_voting_tally(events)
        assert results[0].passed is True

    def test_fail_wrong_tally(self) -> None:
        events = [
            _send("voter-0", "coordinator-0", "vote:1:yes:voter-0"),
            _send("voter-1", "coordinator-0", "vote:1:no:voter-1"),
            _send("voter-2", "coordinator-0", "vote:1:yes:voter-2"),
            _send("coordinator-0", "proposer-0", "result:1:passed:3/3"),
        ]
        results = validate_voting_tally(events)
        assert results[0].passed is False
        assert "round 1" in results[0].detail


class TestVotingAllCounted:
    def test_pass_all_counted(self) -> None:
        events = [
            _send("voter-0", "coordinator-0", "vote:1:yes:voter-0"),
            _send("voter-1", "coordinator-0", "vote:1:no:voter-1"),
            _send("coordinator-0", "proposer-0", "result:1:passed:1/2"),
        ]
        results = validate_voting_all_counted(events)
        assert results[0].passed is True

    def test_fail_vote_not_counted(self) -> None:
        events = [
            _send("voter-0", "coordinator-0", "vote:1:yes:voter-0"),
            _send("voter-1", "coordinator-0", "vote:1:no:voter-1"),
            _send("voter-2", "coordinator-0", "vote:1:yes:voter-2"),
            # Tally says only 2 total but 3 voted
            _send("coordinator-0", "proposer-0", "result:1:passed:2/2"),
        ]
        results = validate_voting_all_counted(events)
        assert results[0].passed is False
        assert "round 1" in results[0].detail


class TestVotingNoDoubleVote:
    def test_pass_single_votes(self) -> None:
        events = [
            _send("voter-0", "coordinator-0", "vote:1:yes:voter-0"),
            _send("voter-1", "coordinator-0", "vote:1:no:voter-1"),
        ]
        results = validate_voting_no_double_vote(events)
        assert results[0].passed is True

    def test_fail_double_vote(self) -> None:
        events = [
            _send("voter-0", "coordinator-0", "vote:1:yes:voter-0"),
            _send("voter-0", "coordinator-0", "vote:1:no:voter-0"),
        ]
        results = validate_voting_no_double_vote(events)
        assert results[0].passed is False
        assert "voter-0" in results[0].detail

    def test_pass_same_voter_different_rounds(self) -> None:
        events = [
            _send("voter-0", "coordinator-0", "vote:1:yes:voter-0"),
            _send("voter-0", "coordinator-0", "vote:2:yes:voter-0"),
        ]
        results = validate_voting_no_double_vote(events)
        assert results[0].passed is True


# ===================================================================
# Consensus
# ===================================================================


class TestConsensusAgreement:
    def test_pass_quorum_met(self) -> None:
        events = [
            _send("follower-0", "leader-0", "vote:1:accept"),
            _send("follower-1", "leader-0", "vote:1:accept"),
            _send("follower-2", "leader-0", "vote:1:reject"),
            _send("leader-0", "follower-0", "result:1:committed:2/3"),
            _send("leader-0", "follower-1", "result:1:committed:2/3"),
            _send("leader-0", "follower-2", "result:1:committed:2/3"),
        ]
        results = validate_consensus_agreement(events)
        assert results[0].passed is True

    def test_fail_quorum_not_met(self) -> None:
        events = [
            _send("follower-0", "leader-0", "vote:1:accept"),
            _send("follower-1", "leader-0", "vote:1:reject"),
            _send("follower-2", "leader-0", "vote:1:reject"),
            # Committed with only 1/3 accepts
            _send("leader-0", "follower-0", "result:1:committed:1/3"),
        ]
        results = validate_consensus_agreement(events)
        assert results[0].passed is False
        assert "1/3" in results[0].detail

    def test_fail_reported_tally_disagrees_with_votes(self) -> None:
        events = [
            _send("follower-0", "leader-0", "vote:1:reject"),
            _send("follower-1", "leader-0", "vote:1:reject"),
            _send("follower-2", "leader-0", "vote:1:reject"),
            _send("leader-0", "follower-0", "result:1:committed:3/3"),
        ]
        results = validate_consensus_agreement(events)
        assert results[0].passed is False
        assert "reported 3/3 but actual 0/3" in results[0].detail

    def test_pass_aborted_no_quorum(self) -> None:
        """Aborted rounds are fine even without quorum."""
        events = [
            _send("follower-0", "leader-0", "vote:1:reject"),
            _send("follower-1", "leader-0", "vote:1:reject"),
            _send("leader-0", "follower-0", "result:1:aborted:0/2"),
        ]
        results = validate_consensus_agreement(events)
        assert results[0].passed is True


class TestConsensusValidity:
    def test_pass_proposed_value_committed(self) -> None:
        events = [
            _send("leader-0", "follower-0", "propose:1:42"),
            _send("leader-0", "follower-1", "propose:1:42"),
            _send("leader-0", "follower-0", "result:1:committed:2/2"),
        ]
        results = validate_consensus_validity(events)
        assert results[0].passed is True

    def test_fail_committed_without_proposal(self) -> None:
        events = [
            # No propose for round 1
            _send("leader-0", "follower-0", "result:1:committed:2/2"),
        ]
        results = validate_consensus_validity(events)
        assert results[0].passed is False
        assert "round 1" in results[0].detail

    def test_pass_no_commits(self) -> None:
        events = [
            _send("leader-0", "follower-0", "propose:1:42"),
            _send("leader-0", "follower-0", "result:1:aborted:0/2"),
        ]
        results = validate_consensus_validity(events)
        assert results[0].passed is True

    def test_fail_conflicting_proposals_same_round(self) -> None:
        events = [
            _send("leader-0", "follower-0", "propose:1:42"),
            _send("leader-0", "follower-1", "propose:1:99"),
            _send("leader-0", "follower-0", "result:1:committed:2/2:42"),
        ]
        results = validate_consensus_validity(events)
        assert results[0].passed is False
        assert "conflicting proposals" in results[0].detail


class TestConsensusNoConflict:
    def test_pass_single_commit_per_round(self) -> None:
        events = [
            _send("leader-0", "follower-0", "result:1:committed:2/3"),
            _send("leader-0", "follower-1", "result:1:committed:2/3"),
            _send("leader-0", "follower-2", "result:1:committed:2/3"),
        ]
        results = validate_consensus_no_conflict(events)
        assert results[0].passed is True

    def test_fail_conflicting_commits(self) -> None:
        events = [
            _send("leader-0", "follower-0", "result:1:committed:2/3"),
            _send("leader-0", "follower-1", "result:1:committed:3/3"),
        ]
        results = validate_consensus_no_conflict(events)
        assert results[0].passed is False
        assert "round 1" in results[0].detail

    def test_pass_different_rounds(self) -> None:
        events = [
            _send("leader-0", "follower-0", "result:1:committed:2/3"),
            _send("leader-0", "follower-0", "result:2:committed:3/3"),
        ]
        results = validate_consensus_no_conflict(events)
        assert results[0].passed is True


# ===================================================================
# Supply chain
# ===================================================================


class TestSupplyChainPipeline:
    def test_pass_full_pipeline(self) -> None:
        events = [
            _send("supplier-0", "manufacturer-0", "material:1:raw-0"),
            _send("manufacturer-0", "distributor-0", "product:1:good-0"),
            _send("distributor-0", "retailer-0", "shipment:1:good-0"),
            _send("retailer-0", "supplier-0", "delivered:1:good-0"),
        ]
        results = validate_supply_chain_pipeline(events)
        assert results[0].passed is True

    def test_fail_missing_hop(self) -> None:
        events = [
            _send("supplier-0", "manufacturer-0", "material:1:raw-0"),
            # Skip manufacturer and distributor
            _send("retailer-0", "supplier-0", "delivered:1:good-0"),
        ]
        results = validate_supply_chain_pipeline(events)
        assert results[0].passed is False
        assert "product" in results[0].detail
        assert "shipment" in results[0].detail

    def test_fail_unmatched_delivery(self) -> None:
        events = [
            _send("supplier-0", "manufacturer-0", "material:1:raw-0"),
            _send("manufacturer-0", "distributor-0", "product:2:good-0"),
            _send("distributor-0", "retailer-0", "shipment:3:good-0"),
            _send("retailer-0", "supplier-0", "delivered:4:good-0"),
        ]
        results = validate_supply_chain_pipeline(events)
        assert results[0].passed is False
        assert "4/good-0" in results[0].detail


class TestSupplyChainNoLost:
    def test_pass_all_delivered(self) -> None:
        events = [
            _send("supplier-0", "manufacturer-0", "material:1:raw-0"),
            _send("supplier-0", "manufacturer-0", "material:1:raw-1"),
            _send("retailer-0", "supplier-0", "delivered:1:good-0"),
            _send("retailer-0", "supplier-0", "delivered:1:good-1"),
        ]
        results = validate_supply_chain_no_lost(events)
        assert results[0].passed is True

    def test_fail_lost_goods(self) -> None:
        events = [
            _send("supplier-0", "manufacturer-0", "material:1:raw-0"),
            _send("supplier-0", "manufacturer-0", "material:1:raw-1"),
            _send("retailer-0", "supplier-0", "delivered:1:good-0"),
            # raw-1 never delivered
        ]
        results = validate_supply_chain_no_lost(events)
        assert results[0].passed is False
        assert "1 of 2" in results[0].detail

    def test_fail_nothing_delivered(self) -> None:
        events = [
            _send("supplier-0", "manufacturer-0", "material:1:raw-0"),
        ]
        results = validate_supply_chain_no_lost(events)
        assert results[0].passed is False

    def test_pass_no_materials(self) -> None:
        events = [{"ts": 0.0, "agent": "supplier-0", "kind": "start"}]
        results = validate_supply_chain_no_lost(events)
        assert results[0].passed is True


# ===================================================================
# Reputation
# ===================================================================


class TestReputationScoring:
    def test_pass_cheaters_reported(self) -> None:
        events = [
            _send("malicious-0", "honest-0", "cheat:1:malicious-0"),
            _send("honest-0", "observer-0", "report:1:malicious-0:bad"),
        ]
        results = validate_reputation_scoring(events)
        assert results[0].passed is True

    def test_fail_cheater_unreported(self) -> None:
        events = [
            _send("malicious-0", "honest-0", "cheat:1:malicious-0"),
            # No report:...:bad for malicious-0
        ]
        results = validate_reputation_scoring(events)
        assert results[0].passed is False
        assert "malicious-0" in results[0].detail

    def test_pass_no_cheating(self) -> None:
        events = [
            _send("honest-0", "honest-1", "deliver:1:honest-0"),
            _send("honest-1", "observer-0", "report:1:honest-0:good"),
        ]
        results = validate_reputation_scoring(events)
        assert results[0].passed is True


class TestReputationWarnings:
    def test_pass_warning_issued(self) -> None:
        events = [
            _send("honest-0", "observer-0", "report:1:malicious-0:bad"),
            _send("honest-1", "observer-0", "report:2:malicious-0:bad"),
            _broadcast("observer-0", "warning:2:malicious-0:untrusted"),
        ]
        results = validate_reputation_warnings(events)
        assert results[0].passed is True

    def test_fail_no_warning(self) -> None:
        events = [
            _send("honest-0", "observer-0", "report:1:malicious-0:bad"),
            _send("honest-1", "observer-0", "report:2:malicious-0:bad"),
            # Score is -4, should be warned but isn't
        ]
        results = validate_reputation_warnings(events)
        assert results[0].passed is False
        assert "malicious-0" in results[0].detail

    def test_pass_above_threshold(self) -> None:
        events = [
            _send("honest-0", "observer-0", "report:1:malicious-0:bad"),
            # Score is -2, above -3 threshold
        ]
        results = validate_reputation_warnings(events)
        assert results[0].passed is True


# ===================================================================
# Integration tests
# ===================================================================


class TestValidateEvents:
    def test_marketplace_pass(self) -> None:
        events = [
            _send("buyer-0", "seller-0", "buy:product-0:50"),
            _send("seller-0", "buyer-0", "sold:product-0:50"),
        ]
        results = validate_events(events, "marketplace")
        assert len(results) == 3
        assert all(r.passed for r in results)

    def test_unknown_scenario(self) -> None:
        events = [_send("a", "b", "hello")]
        results = validate_events(events, "unknown_scenario")
        assert results == []


class TestValidateTrace:
    def test_from_file(self, tmp_path: Path) -> None:
        events = [
            _send("buyer-0", "seller-0", "buy:product-0:50"),
            _send("seller-0", "buyer-0", "sold:product-0:50", ts=1.0),
        ]
        trace = tmp_path / "trace.jsonl"
        trace.write_text("\n".join(json.dumps(e) for e in events))
        results = validate_trace(trace, "marketplace")
        assert len(results) == 3
        assert all(r.passed for r in results)


class TestValidationResult:
    def test_repr_pass(self) -> None:
        r = ValidationResult("test", True, "ok")
        assert "PASS" in repr(r)

    def test_repr_fail(self) -> None:
        r = ValidationResult("test", False, "bad")
        assert "FAIL" in repr(r)


class TestStreamingValidators:
    """Tests for the three streaming payment validators."""

    def test_conservation_passes(self) -> None:
        """Conservation passes when debited == credited."""
        from nest_core.validators import validate_streaming_conservation

        events = [
            {"kind": "payment_debited", "agent": "payer", "amount": 100, "tick": 0},
            {"kind": "payment_credited", "agent": "payee", "amount": 100, "tick": 0},
            {"kind": "payment_debited", "agent": "payer", "amount": 50, "tick": 1},
            {"kind": "payment_credited", "agent": "payee", "amount": 50, "tick": 1},
        ]
        results = validate_streaming_conservation(events)
        assert len(results) == 1
        assert results[0].passed

    def test_conservation_fails_on_imbalance(self) -> None:
        """Conservation fails when debited != credited."""
        from nest_core.validators import validate_streaming_conservation

        events = [
            {"kind": "payment_debited", "agent": "payer", "amount": 100, "tick": 0},
            {"kind": "payment_credited", "agent": "payee", "amount": 50, "tick": 0},
        ]
        results = validate_streaming_conservation(events)
        assert len(results) == 1
        assert not results[0].passed
        assert "conservation violation" in results[0].detail

    def test_no_drain_after_close_passes(self) -> None:
        """No drain-after-close passes when debits stop before close."""
        from nest_core.validators import validate_streaming_no_drain_after_close

        events = [
            {"event_type": "stream_opened", "stream_ref": "s1", "tick": 0},
            {"kind": "payment_debited", "stream_ref": "s1", "tick": 1},
            {"kind": "payment_debited", "stream_ref": "s1", "tick": 2},
            {"event_type": "stream_closed", "stream_ref": "s1", "tick": 3},
        ]
        results = validate_streaming_no_drain_after_close(events)
        assert len(results) == 1
        assert results[0].passed

    def test_no_drain_after_close_fails(self) -> None:
        """Fails when debit occurs after close."""
        from nest_core.validators import validate_streaming_no_drain_after_close

        events = [
            {"event_type": "stream_opened", "stream_ref": "s1", "tick": 0},
            {"kind": "payment_debited", "stream_ref": "s1", "tick": 1},
            {"event_type": "stream_closed", "stream_ref": "s1", "tick": 2},
            {"kind": "payment_debited", "stream_ref": "s1", "tick": 5},  # AFTER close!
        ]
        results = validate_streaming_no_drain_after_close(events)
        assert len(results) == 1
        assert not results[0].passed
        assert "debited after close" in results[0].detail

    def test_no_overbill_on_partition_passes(self) -> None:
        """No over-bill passes when drops occur but no debits after."""
        from nest_core.validators import validate_streaming_no_overbill_on_partition

        events = [
            {
                "event_type": "stream_opened",
                "stream_ref": "s1",
                "agent": "payer",
                "to": "payee",
                "tick": 0,
            },
            {"kind": "payment_debited", "stream_ref": "s1", "tick": 1},
            {"kind": "dropped", "from": "payer", "agent": "payee", "tick": 2},
            # No payment_debited after the partition
        ]
        results = validate_streaming_no_overbill_on_partition(events)
        assert len(results) == 1
        assert results[0].passed

    def test_no_overbill_on_partition_fails(self) -> None:
        """Fails when debit occurs after partition between payer and payee."""
        from nest_core.validators import validate_streaming_no_overbill_on_partition

        events = [
            {
                "event_type": "stream_opened",
                "stream_ref": "s1",
                "agent": "payer",
                "to": "payee",
                "tick": 0,
            },
            {"kind": "payment_debited", "stream_ref": "s1", "tick": 1},
            {"kind": "dropped", "from": "payer", "agent": "payee", "tick": 3},
            {"kind": "payment_debited", "stream_ref": "s1", "tick": 5},  # OVER-BILL
        ]
        results = validate_streaming_no_overbill_on_partition(events)
        assert len(results) == 1
        assert not results[0].passed
        assert "partitioned" in results[0].detail

    def test_no_overbill_ignores_other_drops(self) -> None:
        """Drop between unrelated agents does not trigger a violation."""
        from nest_core.validators import validate_streaming_no_overbill_on_partition

        events = [
            {
                "event_type": "stream_opened",
                "stream_ref": "s1",
                "agent": "payer",
                "to": "payee",
                "tick": 0,
            },
            {"kind": "dropped", "from": "other-a", "agent": "other-b", "tick": 2},
            {"kind": "payment_debited", "stream_ref": "s1", "tick": 5},
        ]
        results = validate_streaming_no_overbill_on_partition(events)
        assert len(results) == 1
        assert results[0].passed  # unrelated drop, not a violation


class TestValidatorRegistry:
    def test_all_scenario_types_registered(self) -> None:
        expected = {
            "marketplace",
            "auction",
            "voting",
            "consensus",
            "supply_chain",
            "reputation",
            "identity_rotation",
            "memory_concurrent_writers",
            "streaming_payments",
            "comms_versioning",
            "receipt_reputation",
            "policy_governance",
        }
        assert set(VALIDATORS.keys()) == expected

    def test_each_scenario_has_validators(self) -> None:
        for scenario, validators in VALIDATORS.items():
            assert len(validators) >= 2, f"{scenario} needs at least 2 validators"


# ---------------------------------------------------------------------------
# Policy-governance: the single-toggle flip (the charter contract)
# ---------------------------------------------------------------------------


class TestPolicyGovernanceFlip:
    """Every policy validator PASSES under `enforced` and FAILS under `permissive`.

    Same scenario, same agents, one config switch — the FAIL-vs-default /
    PASS-vs-yours contract, driven end-to-end through the real PolicyEnforcer.
    """

    _YAML = Path(__file__).parent.parent.parent.parent / "scenarios" / "policy_governance.yaml"

    async def _results(self, tmp_path: Path, enforcement: str) -> list[ValidationResult]:
        from nest_core.runner import ScenarioRunner
        from nest_core.scenario import ScenarioConfig

        config = ScenarioConfig.from_yaml(self._YAML)
        config.task.config["enforcement"] = enforcement
        trace = tmp_path / f"{enforcement}.jsonl"
        config.output.trace = str(trace)
        result = await ScenarioRunner(config).run()
        return validate_trace(result, "policy_governance")

    async def test_enforced_all_pass(self, tmp_path: Path) -> None:
        results = await self._results(tmp_path, "enforced")
        assert len(results) == 5
        assert all(r.passed for r in results), [str(r) for r in results if not r.passed]

    async def test_permissive_all_fail(self, tmp_path: Path) -> None:
        results = await self._results(tmp_path, "permissive")
        assert len(results) == 5
        assert all(not r.passed for r in results), [str(r) for r in results if r.passed]

    async def test_every_validator_flips(self, tmp_path: Path) -> None:
        enforced = {r.name: r.passed for r in await self._results(tmp_path, "enforced")}
        permissive = {r.name: r.passed for r in await self._results(tmp_path, "permissive")}
        for name in enforced:
            assert enforced[name] is True, f"{name} should PASS enforced"
            assert permissive[name] is False, f"{name} should FAIL permissive"


# ---------------------------------------------------------------------------
# Policy-governance: per-validator synthetic-trace unit tests
# ---------------------------------------------------------------------------


def _pline(agent: str, kind: str, body: dict[str, Any]) -> Event:
    return {
        "ts": 1.0,
        "agent": agent,
        "kind": "send",
        "to": "coordinator-0",
        "msg": kind + ":" + json.dumps(body, sort_keys=True),
    }


def _announce(
    agent: str,
    *,
    tools: tuple[str, ...] = (),
    data: dict[str, list[str]] | None = None,
    cap: int | None = None,
    threshold: int | None = None,
    seed: bytes = b"seed",
    signer_seed: bytes | None = None,
    widen_tools: list[str] | None = None,
) -> Event:
    from nest_plugins_reference.identity.ed25519_rotating import Ed25519RotatingIdentity
    from nest_plugins_reference.policy.manifest import (
        Approval,
        Budget,
        PolicyManifest,
        sign_manifest,
    )

    announcer = Ed25519RotatingIdentity(AgentId(agent), seed=seed)
    signer = Ed25519RotatingIdentity(AgentId(agent), seed=signer_seed) if signer_seed else announcer
    manifest = PolicyManifest(
        agent_id=AgentId(agent),
        tools=list(tools),
        data=data or {},
        budget=Budget(cap=cap) if cap is not None else None,
        approvals=[Approval(op="pay", threshold=threshold)] if threshold is not None else [],
    )
    man_dict = sign_manifest(signer, manifest).model_dump(mode="json")
    if widen_tools is not None:
        man_dict["tools"] = widen_tools  # tamper AFTER signing -> signature mismatch
    return _pline(
        agent,
        "manifest",
        {"agent": agent, "manifest": man_dict, "pubkey": announcer.public_key.hex()},
    )


def _action(agent: str, **body: Any) -> Event:
    return _pline(agent, "action", {"agent": agent, **body})


def _approval(agent: str, amount: int) -> Event:
    return _pline(agent, "approval", {"agent": agent, "amount": amount})


class TestPolicyManifestSignatures:
    def test_valid_agent_acting_passes(self) -> None:
        events = [
            _announce("a", tools=("sell",)),
            _action("a", op="register", capabilities=["sell"]),
        ]
        assert validate_policy_manifest_signatures(events)[0].passed

    def test_invalid_manifest_without_action_passes(self) -> None:
        # mismatched signer -> invalid, but it never acts -> PASS
        events = [_announce("a", tools=("sell",), signer_seed=b"attacker")]
        assert validate_policy_manifest_signatures(events)[0].passed

    def test_invalid_manifest_acting_fails(self) -> None:
        events = [
            _announce("a", signer_seed=b"attacker"),
            _action("a", op="register", capabilities=[]),
        ]
        result = validate_policy_manifest_signatures(events)[0]
        assert not result.passed
        assert "a" in result.detail

    def test_tampered_manifest_acting_fails(self) -> None:
        events = [
            _announce("a", tools=("sell",), widen_tools=["sell", "admin"]),
            _action("a", op="register", capabilities=["admin"]),
        ]
        assert not validate_policy_manifest_signatures(events)[0].passed

    def test_self_consistent_impostor_passes_known_limitation(self) -> None:
        # Offline verify checks key<->signature consistency, not ownership: a
        # self-consistent (announced key == signing key) impostor reads as valid.
        events = [
            _announce("a", tools=("sell",), seed=b"impostor", signer_seed=b"impostor"),
            _action("a", op="register", capabilities=["sell"]),
        ]
        assert validate_policy_manifest_signatures(events)[0].passed


class TestPolicyToolAllowlist:
    def test_within_allowlist_passes(self) -> None:
        events = [
            _announce("a", tools=("sell",)),
            _action("a", op="register", capabilities=["sell"]),
        ]
        assert validate_policy_tool_allowlist(events)[0].passed

    def test_overclaim_fails(self) -> None:
        events = [
            _announce("a", tools=("sell",)),
            _action("a", op="register", capabilities=["sell", "admin"]),
        ]
        result = validate_policy_tool_allowlist(events)[0]
        assert not result.passed
        assert "admin" in result.detail

    def test_skips_invalid_manifest_agent(self) -> None:
        # An invalid-manifest agent is handled by the signature validator, not here.
        events = [
            _announce("a", tools=("sell",), signer_seed=b"attacker"),
            _action("a", op="register", capabilities=["admin"]),
        ]
        assert validate_policy_tool_allowlist(events)[0].passed


class TestPolicyDataExposure:
    def test_allowed_audience_passes(self) -> None:
        events = [
            _announce("a", data={"default": ["coordinator-0"]}),
            _action("a", op="expose", data_class="default", audience=["coordinator-0"]),
        ]
        assert validate_policy_data_exposure(events)[0].passed

    def test_disallowed_audience_fails(self) -> None:
        events = [
            _announce("a", data={"default": ["coordinator-0"]}),
            _action("a", op="expose", data_class="default", audience=["evil-corp"]),
        ]
        assert not validate_policy_data_exposure(events)[0].passed

    def test_wildcard_audience_passes(self) -> None:
        events = [
            _announce("a", data={"public": ["*"]}),
            _action("a", op="expose", data_class="public", audience=["anyone"]),
        ]
        assert validate_policy_data_exposure(events)[0].passed


class TestPolicyBudgetCap:
    def test_within_cap_passes(self) -> None:
        events = [
            _announce("a", cap=100),
            _action("a", op="pay", amount=40, currency="credits"),
            _action("a", op="pay", amount=50, currency="credits"),
        ]
        assert validate_policy_budget_cap(events)[0].passed

    def test_cumulative_over_cap_fails(self) -> None:
        events = [
            _announce("a", cap=100),
            _action("a", op="pay", amount=60, currency="credits"),
            _action("a", op="pay", amount=60, currency="credits"),
        ]
        result = validate_policy_budget_cap(events)[0]
        assert not result.passed
        assert "120>100" in result.detail


class TestPolicyApprovalRequired:
    def test_over_threshold_with_approval_passes(self) -> None:
        events = [
            _announce("a", cap=1000, threshold=50),
            _approval("a", 80),
            _action("a", op="pay", amount=80, currency="credits"),
        ]
        assert validate_policy_approval_required(events)[0].passed

    def test_over_threshold_without_approval_fails(self) -> None:
        events = [
            _announce("a", cap=1000, threshold=50),
            _action("a", op="pay", amount=80, currency="credits"),
        ]
        assert not validate_policy_approval_required(events)[0].passed

    def test_under_threshold_needs_no_approval(self) -> None:
        events = [
            _announce("a", cap=1000, threshold=50),
            _action("a", op="pay", amount=40, currency="credits"),
        ]
        assert validate_policy_approval_required(events)[0].passed


class TestPolicyValidatorsTotal:
    def test_never_raise_on_garbage(self) -> None:
        events: list[Event] = [
            {"ts": 1.0, "agent": "x", "kind": "send", "to": "y", "msg": "manifest:{not json"},
            {"ts": 1.0, "agent": "x", "kind": "send", "to": "y", "msg": "action:{bad"},
            {"ts": 1.0, "agent": "x", "kind": "receive", "to": "y", "msg": "action:{}"},
        ]
        for fn in (
            validate_policy_manifest_signatures,
            validate_policy_tool_allowlist,
            validate_policy_data_exposure,
            validate_policy_budget_cap,
            validate_policy_approval_required,
        ):
            results = fn(events)
            assert len(results) == 1
            assert isinstance(results[0].passed, bool)
