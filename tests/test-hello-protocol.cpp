/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2014-2026,  The University of Memphis,
 *                           Regents of the University of California,
 *                           Arizona Board of Regents.
 *
 * This file is part of NLSR (Named-data Link State Routing).
 * See AUTHORS.md for complete list of NLSR authors and contributors.
 *
 * NLSR is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * NLSR is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * NLSR, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "hello-protocol.hpp"
#include "nlsr.hpp"

#include "tests/io-key-chain-fixture.hpp"
#include "tests/test-common.hpp"

namespace nlsr::tests {

class HelloProtocolFixture : public IoKeyChainFixture
{
public:
  HelloProtocolFixture()
    : face(m_io, m_keyChain, {true, true})
    , conf(face, m_keyChain)
    , confProcessor(conf)
    , adjList(conf.getAdjacencyList())
    , nlsr(face, m_keyChain, conf)
    , helloProtocol(nlsr.m_helloProtocol)
  {
    ndn::FaceUri faceUri("udp4://10.0.0.1:6363");
    Adjacent adj1(ACTIVE_NEIGHBOR, faceUri, 10, Adjacent::STATUS_ACTIVE, 0, 300);
    adjList.insert(adj1);
  }

  int
  checkHelloInterests(ndn::Name name)
  {
    int sent = 0;
    for (const auto& i : face.sentInterests) {
      if (name == i.getName().getPrefix(4)) {
        sent++;
      }
    }
    return sent;
  }

  void
  checkHelloInterestTimeout()
  {
    helloProtocol.sendHelloInterest(ndn::Name(ACTIVE_NEIGHBOR));
    this->advanceClocks(10_ms);
    BOOST_CHECK_EQUAL(checkHelloInterests(ACTIVE_NEIGHBOR), 1);
    this->advanceClocks(4_s);
    BOOST_CHECK_EQUAL(checkHelloInterests(ACTIVE_NEIGHBOR), 2);
    this->advanceClocks(4_s);
    BOOST_CHECK_EQUAL(checkHelloInterests(ACTIVE_NEIGHBOR), 3);
    if (conf.getHyperbolicState() == HYPERBOLIC_STATE_ON) {
      BOOST_CHECK_EQUAL(nlsr.m_routingTable.m_isRouteCalculationScheduled, false);
    }
    else {
      BOOST_CHECK_EQUAL(nlsr.m_lsdb.m_isBuildAdjLsaScheduled, false);
    }
    BOOST_CHECK_EQUAL(adjList.findAdjacent(ndn::Name(ACTIVE_NEIGHBOR))->getStatus(),
                      Adjacent::STATUS_ACTIVE);

    this->advanceClocks(4_s);
    BOOST_CHECK_EQUAL(checkHelloInterests(ACTIVE_NEIGHBOR), 3);
    if (conf.getHyperbolicState() == HYPERBOLIC_STATE_ON) {
      BOOST_CHECK_EQUAL(nlsr.m_routingTable.m_isRouteCalculationScheduled, true);
    }
    else {
      BOOST_CHECK_EQUAL(nlsr.m_lsdb.m_isBuildAdjLsaScheduled, true);
    }
    BOOST_CHECK_EQUAL(adjList.findAdjacent(ndn::Name(ACTIVE_NEIGHBOR))->getStatus(),
                      Adjacent::STATUS_INACTIVE);
  }

  ndn::Interest
  makeHelloInterest(const ndn::Name& neighbor) const
  {
    ndn::Name interestName(neighbor);
    interestName.append(HelloProtocol::NLSR_COMPONENT);
    interestName.append(HelloProtocol::INFO_COMPONENT);
    interestName.append(ndn::tlv::GenericNameComponent, conf.getRouterPrefix().wireEncode());
    return ndn::Interest(interestName);
  }

  ndn::Data
  makeHelloData(const ndn::Name& neighbor) const
  {
    ndn::Name dataName(neighbor);
    dataName.append(HelloProtocol::NLSR_COMPONENT);
    dataName.append(HelloProtocol::INFO_COMPONENT);
    dataName.append(ndn::tlv::GenericNameComponent, conf.getRouterPrefix().wireEncode());
    dataName.appendVersion();
    return ndn::Data(dataName);
  }

public:
  ndn::DummyClientFace face;
  ConfParameter conf;
  DummyConfFileProcessor confProcessor;
  AdjacencyList& adjList;
  Nlsr nlsr;
  HelloProtocol& helloProtocol;
  const std::string ACTIVE_NEIGHBOR = "/ndn/site/%C1.Router/router-active";
};

BOOST_FIXTURE_TEST_SUITE(TestHelloProtocol, HelloProtocolFixture)

BOOST_AUTO_TEST_CASE(Basic)
{
  this->advanceClocks(10_s);
  checkPrefixRegistered(face, "/ndn/site/%C1.Router/this-router/nlsr/INFO");
  face.sentInterests.clear();
}

BOOST_AUTO_TEST_CASE(HelloInterestTimeoutLS) // #5139
{
  checkHelloInterestTimeout();
}

BOOST_AUTO_TEST_CASE(HelloInterestTimeoutHR) // #5139
{
  conf.setHyperbolicState(HYPERBOLIC_STATE_ON);
  checkHelloInterestTimeout();
}

BOOST_AUTO_TEST_CASE(CheckHelloDataValidatedSignal) // # 5157
{
  int numOnInitialHelloDataValidates = 0;
  helloProtocol.onInitialHelloDataValidated.connect(
    [&] (const ndn::Name& neighbor) {
      ++numOnInitialHelloDataValidates;
    }
  );

  ndn::FaceUri faceUri("udp4://10.0.0.2:6363");
  Adjacent adj1("/ndn/site/%C1.Router/router-other", faceUri, 10,
                Adjacent::STATUS_INACTIVE, 0, 300);
  adjList.insert(adj1);

  ndn::Name dataName = adj1.getName();
  dataName.append(HelloProtocol::NLSR_COMPONENT);
  dataName.append(HelloProtocol::INFO_COMPONENT);
  dataName.append(ndn::tlv::GenericNameComponent, conf.getRouterPrefix().wireEncode());

  ndn::Data data(ndn::Name(dataName).appendVersion());
  BOOST_CHECK_EQUAL(numOnInitialHelloDataValidates, 0);
  helloProtocol.onContentValidated(data);
  BOOST_CHECK_EQUAL(numOnInitialHelloDataValidates, 1);
  BOOST_CHECK_EQUAL(adjList.getStatusOfNeighbor(adj1.getName()), Adjacent::STATUS_ACTIVE);

  // No state change of neighbor so no signal:
  ndn::Data data2(ndn::Name(dataName).appendVersion());
  helloProtocol.onContentValidated(data2);
  BOOST_CHECK_EQUAL(numOnInitialHelloDataValidates, 1);
  BOOST_CHECK_EQUAL(adjList.getStatusOfNeighbor(adj1.getName()), Adjacent::STATUS_ACTIVE);
}

BOOST_AUTO_TEST_CASE(EventDrivenOffDoesNotStartSweep)
{
  BOOST_CHECK_EQUAL(conf.getEventDrivenAdjacencyVerification(), false);
  helloProtocol.onAttachmentChangeHint();
  BOOST_CHECK(!helloProtocol.m_sweep.has_value());
  BOOST_CHECK(!nlsr.m_lsdb.isAdjLsaBuildHeld());
}

BOOST_AUTO_TEST_CASE(VerifyNowFreshInterest)
{
  conf.setEventDrivenAdjacencyVerification(true);
  face.sentInterests.clear();
  helloProtocol.onAttachmentChangeHint();
  this->advanceClocks(10_ms);
  BOOST_REQUIRE(helloProtocol.m_sweep.has_value());
  BOOST_CHECK_EQUAL(checkHelloInterests(ACTIVE_NEIGHBOR), 1);
  BOOST_CHECK(nlsr.m_lsdb.isAdjLsaBuildHeld());
}

BOOST_AUTO_TEST_CASE(VerifyNowSupersedesInFlight)
{
  conf.setEventDrivenAdjacencyVerification(true);
  face.sentInterests.clear();
  helloProtocol.sendHelloInterest(ACTIVE_NEIGHBOR);
  this->advanceClocks(10_ms);
  BOOST_REQUIRE_EQUAL(checkHelloInterests(ACTIVE_NEIGHBOR), 1);
  const uint64_t oldToken = helloProtocol.m_adjHello[ACTIVE_NEIGHBOR].flowToken;

  helloProtocol.onAttachmentChangeHint();
  this->advanceClocks(10_ms);
  BOOST_CHECK(helloProtocol.m_adjHello[ACTIVE_NEIGHBOR].flowToken != oldToken);
  BOOST_CHECK_EQUAL(checkHelloInterests(ACTIVE_NEIGHBOR), 2);
}

BOOST_AUTO_TEST_CASE(StaleNackDoesNotScheduleOrMutate)
{
  conf.setEventDrivenAdjacencyVerification(true);
  conf.setInterestRetryNumber(3);
  helloProtocol.sendHelloInterest(ACTIVE_NEIGHBOR);
  this->advanceClocks(10_ms);
  const uint64_t staleToken = helloProtocol.m_adjHello[ACTIVE_NEIGHBOR].flowToken;
  helloProtocol.onAttachmentChangeHint();
  this->advanceClocks(10_ms);

  adjList.setTimedOutInterestCount(ACTIVE_NEIGHBOR, 0);
  face.sentInterests.clear();
  const uint32_t resend = conf.getInterestResendTime();
  helloProtocol.onNackOwned(ACTIVE_NEIGHBOR, makeHelloInterest(ACTIVE_NEIGHBOR),
                            resend, false, staleToken);
  this->advanceClocks(ndn::time::seconds(2 * resend + 1));
  BOOST_CHECK_EQUAL(adjList.getTimedOutInterestCount(ACTIVE_NEIGHBOR), 0);
  BOOST_CHECK_EQUAL(checkHelloInterests(ACTIVE_NEIGHBOR), 0);
}

BOOST_AUTO_TEST_CASE(StaleNackDoesNotOverwriteCurrentNackDelay)
{
  // DummyClientFace cannot reliably deliver a NACK after PendingInterestHandle::cancel
  // (async erase). This test invokes onNackOwned — the same production handler the
  // expressInterest NACK lambda calls — to prove schedule-time token gating:
  // F2 schedules nackDelay(T2); late F1 onNackOwned must not replace it.
  conf.setEventDrivenAdjacencyVerification(true);
  conf.setInterestRetryNumber(3);
  conf.setInterestResendTime(1);

  helloProtocol.sendHelloInterest(ACTIVE_NEIGHBOR);
  this->advanceClocks(10_ms);
  const uint64_t token1 = helloProtocol.m_adjHello[ACTIVE_NEIGHBOR].flowToken;

  helloProtocol.onAttachmentChangeHint();
  this->advanceClocks(10_ms);
  const uint64_t token2 = helloProtocol.m_adjHello[ACTIVE_NEIGHBOR].flowToken;
  BOOST_REQUIRE(token2 != token1);

  adjList.setTimedOutInterestCount(ACTIVE_NEIGHBOR, 0);
  face.sentInterests.clear();
  const auto interest = makeHelloInterest(ACTIVE_NEIGHBOR);

  helloProtocol.onNackOwned(ACTIVE_NEIGHBOR, interest, 1, false, token2);
  helloProtocol.onNackOwned(ACTIVE_NEIGHBOR, interest, 1, false, token1);

  this->advanceClocks(2_s + 10_ms);
  // Exactly one delayed timeout from T2: count advances once and one retry is sent.
  BOOST_CHECK_EQUAL(adjList.getTimedOutInterestCount(ACTIVE_NEIGHBOR), 1);
  BOOST_CHECK_EQUAL(helloProtocol.m_adjHello[ACTIVE_NEIGHBOR].flowToken, token2);
  BOOST_CHECK_EQUAL(checkHelloInterests(ACTIVE_NEIGHBOR), 1);
}

BOOST_AUTO_TEST_CASE(StaleDataIgnored)
{
  conf.setEventDrivenAdjacencyVerification(true);
  helloProtocol.sendHelloInterest(ACTIVE_NEIGHBOR);
  this->advanceClocks(10_ms);
  const uint64_t staleToken = helloProtocol.m_adjHello[ACTIVE_NEIGHBOR].flowToken;
  helloProtocol.onAttachmentChangeHint();
  this->advanceClocks(10_ms);

  adjList.setStatusOfNeighbor(ACTIVE_NEIGHBOR, Adjacent::STATUS_INACTIVE);
  helloProtocol.onContentValidated(makeHelloData(ACTIVE_NEIGHBOR), false, staleToken);
  BOOST_CHECK_EQUAL(adjList.getStatusOfNeighbor(ACTIVE_NEIGHBOR), Adjacent::STATUS_INACTIVE);
  BOOST_REQUIRE(helloProtocol.m_sweep.has_value());
  BOOST_CHECK_EQUAL(helloProtocol.m_sweep->results.count(ACTIVE_NEIGHBOR), 0);
}

BOOST_AUTO_TEST_CASE(CurrentTokenReachableIncludingActiveActive)
{
  conf.setEventDrivenAdjacencyVerification(true);
  helloProtocol.onAttachmentChangeHint();
  this->advanceClocks(10_ms);
  const uint64_t token = helloProtocol.m_adjHello[ACTIVE_NEIGHBOR].flowToken;
  BOOST_CHECK_EQUAL(adjList.getStatusOfNeighbor(ACTIVE_NEIGHBOR), Adjacent::STATUS_ACTIVE);

  helloProtocol.onContentValidated(makeHelloData(ACTIVE_NEIGHBOR), false, token);
  BOOST_CHECK_EQUAL(adjList.getStatusOfNeighbor(ACTIVE_NEIGHBOR), Adjacent::STATUS_ACTIVE);
  // Single-target sweep settles and clears.
  BOOST_CHECK(!helloProtocol.m_sweep.has_value());
  BOOST_CHECK(!nlsr.m_lsdb.isAdjLsaBuildHeld());
}

BOOST_AUTO_TEST_CASE(CurrentTokenExhaustionUnreachableIncludingInactiveInactive)
{
  conf.setEventDrivenAdjacencyVerification(true);
  conf.setInterestRetryNumber(1);
  adjList.setStatusOfNeighbor(ACTIVE_NEIGHBOR, Adjacent::STATUS_INACTIVE);
  adjList.setTimedOutInterestCount(ACTIVE_NEIGHBOR, 0);

  helloProtocol.onAttachmentChangeHint();
  this->advanceClocks(10_ms);
  const uint64_t token = helloProtocol.m_adjHello[ACTIVE_NEIGHBOR].flowToken;

  helloProtocol.processInterestTimedOut(makeHelloInterest(ACTIVE_NEIGHBOR), false, token);
  BOOST_CHECK_EQUAL(adjList.getStatusOfNeighbor(ACTIVE_NEIGHBOR), Adjacent::STATUS_INACTIVE);
  BOOST_CHECK(!helloProtocol.m_sweep.has_value());
}

BOOST_AUTO_TEST_CASE(RetryKeepsSameToken)
{
  conf.setEventDrivenAdjacencyVerification(true);
  conf.setInterestRetryNumber(3);
  helloProtocol.sendHelloInterest(ACTIVE_NEIGHBOR);
  this->advanceClocks(10_ms);
  const uint64_t token = helloProtocol.m_adjHello[ACTIVE_NEIGHBOR].flowToken;
  face.sentInterests.clear();

  helloProtocol.processInterestTimedOut(makeHelloInterest(ACTIVE_NEIGHBOR), false, token);
  this->advanceClocks(10_ms);
  BOOST_CHECK_EQUAL(helloProtocol.m_adjHello[ACTIVE_NEIGHBOR].flowToken, token);
  BOOST_CHECK_EQUAL(checkHelloInterests(ACTIVE_NEIGHBOR), 1);
}

BOOST_AUTO_TEST_CASE(SweepTargetSetActiveUnionFaceId)
{
  conf.setEventDrivenAdjacencyVerification(true);
  Adjacent inactiveWithFace("/ndn/site/%C1.Router/inactive-face",
                            ndn::FaceUri("udp4://10.0.0.2:6363"),
                            10, Adjacent::STATUS_INACTIVE, 0, 301);
  Adjacent inactiveNoFace("/ndn/site/%C1.Router/inactive-noface",
                          ndn::FaceUri("udp4://10.0.0.3:6363"),
                          10, Adjacent::STATUS_INACTIVE, 0, 0);
  adjList.insert(inactiveWithFace);
  adjList.insert(inactiveNoFace);

  helloProtocol.onAttachmentChangeHint();
  BOOST_REQUIRE(helloProtocol.m_sweep.has_value());
  BOOST_CHECK_EQUAL(helloProtocol.m_sweep->targets.count(ACTIVE_NEIGHBOR), 1);
  BOOST_CHECK_EQUAL(helloProtocol.m_sweep->targets.count(inactiveWithFace.getName()), 1);
  BOOST_CHECK_EQUAL(helloProtocol.m_sweep->targets.count(inactiveNoFace.getName()), 0);
}

BOOST_AUTO_TEST_CASE(SettleWithDirtyTriggersImmediateBuild)
{
  conf.setEventDrivenAdjacencyVerification(true);
  conf.setAdjLsaBuildInterval(5);
  conf.setInterestRetryNumber(1);

  // Pre-existing dirty debounce that must not fire during the hold.
  nlsr.m_lsdb.scheduleAdjLsaBuild();
  BOOST_CHECK(nlsr.m_lsdb.m_isBuildAdjLsaScheduled);
  const int64_t dirtyAtStart = nlsr.m_lsdb.m_adjBuildCount;

  helloProtocol.onAttachmentChangeHint();
  BOOST_CHECK(nlsr.m_lsdb.isAdjLsaBuildHeld());
  BOOST_CHECK(!nlsr.m_lsdb.m_isBuildAdjLsaScheduled);
  BOOST_CHECK_EQUAL(nlsr.m_lsdb.m_adjBuildCount, dirtyAtStart);

  this->advanceClocks(6_s);
  BOOST_CHECK(nlsr.m_lsdb.isAdjLsaBuildHeld());
  BOOST_CHECK_EQUAL(nlsr.m_lsdb.m_adjBuildCount, dirtyAtStart);

  // Status delta during sweep must preserve dirty without premature build.
  adjList.setStatusOfNeighbor(ACTIVE_NEIGHBOR, Adjacent::STATUS_INACTIVE);
  nlsr.m_lsdb.scheduleAdjLsaBuild();
  BOOST_CHECK_EQUAL(nlsr.m_lsdb.m_adjBuildCount, dirtyAtStart + 1);
  BOOST_CHECK(!nlsr.m_lsdb.m_isBuildAdjLsaScheduled);

  const uint64_t token = helloProtocol.m_adjHello[ACTIVE_NEIGHBOR].flowToken;
  helloProtocol.onContentValidated(makeHelloData(ACTIVE_NEIGHBOR), false, token);
  BOOST_CHECK(!helloProtocol.m_sweep.has_value());
  BOOST_CHECK(!nlsr.m_lsdb.isAdjLsaBuildHeld());
  // Immediate settle consumed outstanding dirty through ordinary build path.
  BOOST_CHECK_EQUAL(nlsr.m_lsdb.m_adjBuildCount, 0);
}

BOOST_AUTO_TEST_CASE(SettleWithoutDirtyNoBuild)
{
  conf.setEventDrivenAdjacencyVerification(true);
  BOOST_CHECK_EQUAL(nlsr.m_lsdb.m_adjBuildCount, 0);
  helloProtocol.onAttachmentChangeHint();
  const uint64_t token = helloProtocol.m_adjHello[ACTIVE_NEIGHBOR].flowToken;
  helloProtocol.onContentValidated(makeHelloData(ACTIVE_NEIGHBOR), false, token);
  BOOST_CHECK_EQUAL(nlsr.m_lsdb.m_adjBuildCount, 0);
  BOOST_CHECK(!nlsr.m_lsdb.m_isBuildAdjLsaScheduled);
}

BOOST_AUTO_TEST_CASE(IndeterminateAbortsToOrdinaryDebounce)
{
  conf.setEventDrivenAdjacencyVerification(true);
  conf.setAdjLsaBuildInterval(5);
  nlsr.m_lsdb.scheduleAdjLsaBuild();
  const int64_t dirty = nlsr.m_lsdb.m_adjBuildCount;

  // ACTIVE with faceId==0 cannot be freshly verified → INDETERMINATE.
  adjList.findAdjacent(ACTIVE_NEIGHBOR)->setFaceId(0);
  helloProtocol.onAttachmentChangeHint();
  BOOST_CHECK(!helloProtocol.m_sweep.has_value());
  BOOST_CHECK(!nlsr.m_lsdb.isAdjLsaBuildHeld());
  BOOST_CHECK_EQUAL(nlsr.m_lsdb.m_adjBuildCount, dirty);
  BOOST_CHECK(nlsr.m_lsdb.m_isBuildAdjLsaScheduled);
}

BOOST_AUTO_TEST_CASE(Commit1GatedDuringLocalSweep)
{
  conf.setEventDrivenAdjacencyVerification(true);
  conf.setResultDrivenAdjLsaBuild(true);
  conf.setAdjLsaBuildInterval(5);

  Adjacent inactive("/ndn/site/%C1.Router/reciprocal",
                    ndn::FaceUri("udp4://10.0.0.9:6363"),
                    10, Adjacent::STATUS_INACTIVE, 0, 309);
  adjList.insert(inactive);

  nlsr.m_lsdb.scheduleAdjLsaBuild();
  helloProtocol.onAttachmentChangeHint();
  BOOST_REQUIRE(helloProtocol.m_sweep.has_value());
  BOOST_REQUIRE_EQUAL(helloProtocol.m_sweep->targets.count(inactive.getName()), 1);

  const uint64_t useToken = helloProtocol.m_adjHello[inactive.getName()].flowToken;
  helloProtocol.onContentValidated(makeHelloData(inactive.getName()), true, useToken);

  // Local sweep still waiting on ACTIVE_NEIGHBOR; Commit1 must not clear hold.
  BOOST_CHECK(nlsr.m_lsdb.isAdjLsaBuildHeld());
  BOOST_CHECK(helloProtocol.m_sweep.has_value());
  BOOST_CHECK(nlsr.m_lsdb.m_adjBuildCount > 0);
}

BOOST_AUTO_TEST_CASE(Commit1ImmediateWithoutLocalSweep)
{
  conf.setEventDrivenAdjacencyVerification(true);
  conf.setResultDrivenAdjLsaBuild(true);

  Adjacent inactive("/ndn/site/%C1.Router/reciprocal-only",
                    ndn::FaceUri("udp4://10.0.0.8:6363"),
                    10, Adjacent::STATUS_INACTIVE, 0, 308);
  adjList.insert(inactive);
  nlsr.m_lsdb.scheduleAdjLsaBuild();
  BOOST_CHECK(nlsr.m_lsdb.m_adjBuildCount > 0);

  helloProtocol.onContentValidated(makeHelloData(inactive.getName()), true, 0);
  BOOST_CHECK_EQUAL(nlsr.m_lsdb.m_adjBuildCount, 0);
}

BOOST_AUTO_TEST_CASE(RapidSerialReplacementPreventsOldPublish)
{
  conf.setEventDrivenAdjacencyVerification(true);
  conf.setAdjLsaBuildInterval(5);
  nlsr.m_lsdb.scheduleAdjLsaBuild();

  helloProtocol.onAttachmentChangeHint();
  BOOST_REQUIRE(helloProtocol.m_sweep.has_value());
  const uint64_t serial1 = helloProtocol.m_sweep->serial;
  const uint64_t token1 = helloProtocol.m_adjHello[ACTIVE_NEIGHBOR].flowToken;

  helloProtocol.onAttachmentChangeHint();
  BOOST_REQUIRE(helloProtocol.m_sweep.has_value());
  BOOST_CHECK(helloProtocol.m_sweep->serial != serial1);
  BOOST_CHECK(helloProtocol.m_adjHello[ACTIVE_NEIGHBOR].flowToken != token1);

  // Late serial1 Data must not settle/publish.
  helloProtocol.onContentValidated(makeHelloData(ACTIVE_NEIGHBOR), false, token1);
  BOOST_REQUIRE(helloProtocol.m_sweep.has_value());
  BOOST_CHECK(helloProtocol.m_sweep->serial != serial1);
  BOOST_CHECK(nlsr.m_lsdb.isAdjLsaBuildHeld());
  BOOST_CHECK(nlsr.m_lsdb.m_adjBuildCount > 0);
}

BOOST_AUTO_TEST_CASE(FalseHintNoStatusDeltaNoPublication)
{
  conf.setEventDrivenAdjacencyVerification(true);
  BOOST_CHECK_EQUAL(nlsr.m_lsdb.m_adjBuildCount, 0);
  helloProtocol.onAttachmentChangeHint();
  const uint64_t token = helloProtocol.m_adjHello[ACTIVE_NEIGHBOR].flowToken;
  // ACTIVE→ACTIVE validated: REACHABLE, no status delta dirty.
  helloProtocol.onContentValidated(makeHelloData(ACTIVE_NEIGHBOR), false, token);
  BOOST_CHECK_EQUAL(nlsr.m_lsdb.m_adjBuildCount, 0);
  BOOST_CHECK(!nlsr.m_lsdb.m_isBuildAdjLsaScheduled);
}

BOOST_AUTO_TEST_CASE(DuplicateHintRestartsWithoutDuplicatePublish)
{
  conf.setEventDrivenAdjacencyVerification(true);
  nlsr.m_lsdb.scheduleAdjLsaBuild();
  helloProtocol.onAttachmentChangeHint();
  helloProtocol.onAttachmentChangeHint();
  BOOST_REQUIRE(helloProtocol.m_sweep.has_value());
  BOOST_CHECK(nlsr.m_lsdb.isAdjLsaBuildHeld());
  const uint64_t token = helloProtocol.m_adjHello[ACTIVE_NEIGHBOR].flowToken;
  helloProtocol.onContentValidated(makeHelloData(ACTIVE_NEIGHBOR), false, token);
  BOOST_CHECK(!helloProtocol.m_sweep.has_value());
  BOOST_CHECK_EQUAL(nlsr.m_lsdb.m_adjBuildCount, 0);
}

BOOST_AUTO_TEST_CASE(FaceDestroyMarksUnreachable)
{
  conf.setEventDrivenAdjacencyVerification(true);
  helloProtocol.onAttachmentChangeHint();
  BOOST_REQUIRE(helloProtocol.m_sweep.has_value());
  const uint64_t tokenBeforeDestroy = helloProtocol.m_adjHello[ACTIVE_NEIGHBOR].flowToken;

  adjList.setStatusOfNeighbor(ACTIVE_NEIGHBOR, Adjacent::STATUS_INACTIVE);
  adjList.findAdjacent(ACTIVE_NEIGHBOR)->setFaceId(0);
  adjList.findAdjacent(ACTIVE_NEIGHBOR)->setInterestTimedOutNo(conf.getInterestRetryNumber());
  nlsr.m_lsdb.scheduleAdjLsaBuild();
  helloProtocol.onAdjacentFaceDestroyed(ACTIVE_NEIGHBOR);

  BOOST_CHECK(!helloProtocol.m_sweep.has_value());
  BOOST_CHECK(!nlsr.m_lsdb.isAdjLsaBuildHeld());
  // Late Data for the pre-destroy flow must not revive ACTIVE.
  helloProtocol.onContentValidated(makeHelloData(ACTIVE_NEIGHBOR), false, tokenBeforeDestroy);
  BOOST_CHECK_EQUAL(adjList.getStatusOfNeighbor(ACTIVE_NEIGHBOR), Adjacent::STATUS_INACTIVE);
}

BOOST_AUTO_TEST_CASE(AbortStopsFurtherVerifyNow)
{
  conf.setEventDrivenAdjacencyVerification(true);
  conf.setAdjLsaBuildInterval(5);
  nlsr.m_lsdb.scheduleAdjLsaBuild();

  // First in set-order name with ACTIVE+faceId==0 → INDETERMINATE abort.
  // Second neighbour must not receive a post-abort verify-now Interest.
  Adjacent bad("/ndn/site/%C1.Router/aaa-bad",
               ndn::FaceUri("udp4://10.0.0.7:6363"),
               10, Adjacent::STATUS_ACTIVE, 0, 0);
  Adjacent good("/ndn/site/%C1.Router/zzz-good",
                ndn::FaceUri("udp4://10.0.0.8:6363"),
                10, Adjacent::STATUS_INACTIVE, 0, 308);
  adjList.insert(bad);
  adjList.insert(good);
  // Drop the fixture ACTIVE neighbour so the aborting target is first.
  adjList.getAdjList().remove_if([&] (const Adjacent& a) {
    return a.getName() == ACTIVE_NEIGHBOR;
  });

  face.sentInterests.clear();
  helloProtocol.onAttachmentChangeHint();
  this->advanceClocks(10_ms);

  BOOST_CHECK(!helloProtocol.m_sweep.has_value());
  BOOST_CHECK(!nlsr.m_lsdb.isAdjLsaBuildHeld());
  BOOST_CHECK(nlsr.m_lsdb.m_isBuildAdjLsaScheduled);
  BOOST_CHECK_EQUAL(checkHelloInterests(good.getName()), 0);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace nlsr::tests
