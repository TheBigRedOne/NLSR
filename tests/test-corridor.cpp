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

#include "corridor.hpp"
#include "nlsr.hpp"

#include "tests/io-key-chain-fixture.hpp"
#include "tests/test-common.hpp"

#include <ndn-cxx/lp/tags.hpp>

namespace nlsr::tests {

constexpr ndn::time::system_clock::time_point MAX_TIME = ndn::time::system_clock::time_point::max();
const ndn::Name PRODUCER("/ndn/site/%C1.Router/producer");
const ndn::Name AP2("/ndn/site/%C1.Router/ap2");
const ndn::Name AGG("/ndn/site/%C1.Router/agg");
const ndn::Name LIVE("/LiveStream");
const ndn::FaceUri PRODUCER_FACE("udp4://10.0.0.9:6363");
const ndn::FaceUri SELF_FACE("udp4://10.0.0.1:6363");
const ndn::FaceUri AP2_FACE("udp4://10.0.0.10:6363");
const ndn::FaceUri AGG_FACE("udp4://10.0.0.11:6363");

class CorridorFixture : public IoKeyChainFixture
{
public:
  CorridorFixture()
    : face(m_io, m_keyChain, {true, true})
    , conf(face, m_keyChain)
    , confProcessor(conf)
  {
    m_keyChain.createIdentity(conf.getRouterPrefix());
    conf.getValidator().load("trust-anchor\n{\n  type any\n}\n", "from-string");
    lsdb = std::make_unique<Lsdb>(face, m_keyChain, conf);
    corridor = std::make_unique<Corridor>(face, m_keyChain, conf, *lsdb);
    advanceClocks(10_ms);
    face.sentInterests.clear();
  }

  static AdjacencyList
  activeList(std::initializer_list<Adjacent> neighbors)
  {
    AdjacencyList list;
    for (const auto& adj : neighbors) {
      list.insert(adj);
    }
    return list;
  }

  void
  installAdj(const ndn::Name& origin, uint64_t seq, AdjacencyList list)
  {
    lsdb->installLsa(std::make_shared<AdjLsa>(origin, seq, MAX_TIME, list));
  }

  void
  installName(const ndn::Name& origin, uint64_t seq, std::initializer_list<ndn::Name> prefixes)
  {
    NamePrefixList npl;
    for (const auto& prefix : prefixes) {
      npl.insert(prefix);
    }
    lsdb->installLsa(std::make_shared<NameLsa>(origin, seq, MAX_TIME, npl));
  }

  ndn::Interest
  makeAvailability(const ndn::Name& origin, uint64_t seq, const ndn::Name& prefix, uint64_t ingressFace)
  {
    ndn::Interest interest(Corridor::encodeAvailabilityName(conf.getNetwork(), Lsa::Type::ADJACENCY,
                                                            seq, origin, prefix));
    interest.setCanBePrefix(false);
    interest.setMustBeFresh(true);
    interest.setInterestLifetime(1_s);
    interest.setTag(std::make_shared<ndn::lp::IncomingFaceIdTag>(ingressFace));
    return interest;
  }

  size_t
  countAvailability(const ndn::Name& origin, uint64_t seq, const ndn::Name& prefix) const
  {
    const ndn::Name expected = Corridor::encodeAvailabilityName(conf.getNetwork(),
                                                                Lsa::Type::ADJACENCY, seq, origin, prefix);
    size_t n = 0;
    for (const auto& interest : face.sentInterests) {
      if (interest.getName() == expected) {
        ++n;
      }
    }
    return n;
  }

  bool
  hasAvailabilityTo(const ndn::Name& origin, uint64_t seq, const ndn::Name& prefix,
                    uint64_t faceId) const
  {
    const ndn::Name expected = Corridor::encodeAvailabilityName(conf.getNetwork(),
                                                                Lsa::Type::ADJACENCY, seq, origin, prefix);
    for (const auto& interest : face.sentInterests) {
      if (interest.getName() != expected) {
        continue;
      }
      auto tag = interest.getTag<ndn::lp::NextHopFaceIdTag>();
      if (tag != nullptr && *tag == faceId) {
        return true;
      }
    }
    return false;
  }

  bool
  hasPinnedLsaFetch(const ndn::Name& origin, uint64_t seq, uint64_t faceId) const
  {
    ndn::Name name = conf.getLsaPrefix();
    name.append(origin.getSubName(conf.getNetwork().size()));
    name.append("ADJACENCY");
    name.appendNumber(seq);
    for (const auto& interest : face.sentInterests) {
      if (interest.getName() != name) {
        continue;
      }
      auto tag = interest.getTag<ndn::lp::NextHopFaceIdTag>();
      if (tag != nullptr && *tag == faceId) {
        return true;
      }
    }
    return false;
  }

  void
  waitForServiceBranchQuery()
  {
    // DummyClientFace does not answer NFD datasets; Controller fetch times out at 10 s.
    advanceClocks(1_s, 15);
  }

public:
  ndn::DummyClientFace face;
  ConfParameter conf;
  DummyConfFileProcessor confProcessor;
  std::unique_ptr<Lsdb> lsdb;
  std::unique_ptr<Corridor> corridor;
};

BOOST_FIXTURE_TEST_SUITE(TestCorridor, CorridorFixture)

BOOST_AUTO_TEST_CASE(EncodeDecodeAvailability)
{
  auto name = Corridor::encodeAvailabilityName(conf.getNetwork(), Lsa::Type::ADJACENCY,
                                               7, PRODUCER, LIVE);
  auto parsed = Corridor::parseAvailabilityName(name);
  BOOST_REQUIRE(parsed);
  BOOST_CHECK(parsed->type == Lsa::Type::ADJACENCY);
  BOOST_CHECK_EQUAL(parsed->seq, 7);
  BOOST_CHECK_EQUAL(parsed->origin, PRODUCER);
  BOOST_CHECK_EQUAL(parsed->prefix, LIVE);
  BOOST_CHECK(!Corridor::parseAvailabilityName("/localhop/ndn/nlsr/LSA/foo"));
}

BOOST_AUTO_TEST_CASE(OwnAdjInstallAdvertisesOnActiveAdjacency)
{
  Adjacent neighbor(PRODUCER, PRODUCER_FACE, 10, Adjacent::STATUS_ACTIVE, 0, 42);
  conf.getAdjacencyList().insert(neighbor);
  installName(conf.getRouterPrefix(), 2, {LIVE});
  installAdj(conf.getRouterPrefix(), 1, conf.getAdjacencyList());
  advanceClocks(10_ms);

  BOOST_CHECK(hasAvailabilityTo(conf.getRouterPrefix(), 1, LIVE, 42));
  BOOST_CHECK(corridor->hasAdvertisedFace(conf.getRouterPrefix(), Lsa::Type::ADJACENCY, LIVE, 42));
}

BOOST_AUTO_TEST_CASE(AvailabilityFetchesFromIngressFace)
{
  corridor->processAvailabilityInterest(makeAvailability(PRODUCER, 4, LIVE, 7));
  advanceClocks(10_ms);
  BOOST_CHECK(hasPinnedLsaFetch(PRODUCER, 4, 7));
  BOOST_CHECK_EQUAL(corridor->getAdvertisedSeq(PRODUCER, Lsa::Type::ADJACENCY, LIVE), 4);
}

BOOST_AUTO_TEST_CASE(InstallAfterAvailabilityPropagatesDownstream)
{
  corridor->noteServiceBranch(LIVE, 99);
  corridor->processAvailabilityInterest(makeAvailability(PRODUCER, 4, LIVE, 7));
  AdjacencyList producerAdj = activeList({
    Adjacent(conf.getRouterPrefix(), SELF_FACE, 5, Adjacent::STATUS_ACTIVE, 0, 0)
  });
  installAdj(PRODUCER, 4, producerAdj);
  advanceClocks(10_ms);
  BOOST_CHECK_EQUAL(countAvailability(PRODUCER, 4, LIVE), 0);
  waitForServiceBranchQuery();
  BOOST_CHECK(hasAvailabilityTo(PRODUCER, 4, LIVE, 99));
}

BOOST_AUTO_TEST_CASE(NoInstallMeansNoDownstreamAvailability)
{
  corridor->noteServiceBranch(LIVE, 99);
  corridor->processAvailabilityInterest(makeAvailability(PRODUCER, 4, LIVE, 7));
  advanceClocks(10_ms);
  BOOST_CHECK_EQUAL(countAvailability(PRODUCER, 4, LIVE), 0);
}

BOOST_AUTO_TEST_CASE(SameSeqAlreadyInstalledNoDuplicateFetch)
{
  AdjacencyList producerAdj = activeList({
    Adjacent(conf.getRouterPrefix(), SELF_FACE, 5, Adjacent::STATUS_ACTIVE, 0, 0)
  });
  installAdj(PRODUCER, 4, producerAdj);
  face.sentInterests.clear();
  corridor->noteServiceBranch(LIVE, 99);
  corridor->processAvailabilityInterest(makeAvailability(PRODUCER, 4, LIVE, 7));
  advanceClocks(10_ms);
  BOOST_CHECK(!hasPinnedLsaFetch(PRODUCER, 4, 7));
  BOOST_CHECK_EQUAL(countAvailability(PRODUCER, 4, LIVE), 0);
  waitForServiceBranchQuery();
  BOOST_CHECK(hasAvailabilityTo(PRODUCER, 4, LIVE, 99));

  face.sentInterests.clear();
  corridor->processAvailabilityInterest(makeAvailability(PRODUCER, 4, LIVE, 7));
  waitForServiceBranchQuery();
  BOOST_CHECK_EQUAL(countAvailability(PRODUCER, 4, LIVE), 0);
}

BOOST_AUTO_TEST_CASE(StaleAvailabilityIgnoredWhenLocalNewer)
{
  AdjacencyList producerAdj = activeList({
    Adjacent(conf.getRouterPrefix(), SELF_FACE, 5, Adjacent::STATUS_ACTIVE, 0, 0)
  });
  installAdj(PRODUCER, 5, producerAdj);
  face.sentInterests.clear();
  corridor->processAvailabilityInterest(makeAvailability(PRODUCER, 4, LIVE, 7));
  advanceClocks(10_ms);
  BOOST_CHECK_EQUAL(corridor->getAdvertisedSeq(PRODUCER, Lsa::Type::ADJACENCY, LIVE), 0);
  BOOST_CHECK(!hasPinnedLsaFetch(PRODUCER, 4, 7));
}

BOOST_AUTO_TEST_CASE(PsyncInstallsExactSeqThenPropagate)
{
  corridor->noteServiceBranch(LIVE, 99);
  corridor->processAvailabilityInterest(makeAvailability(PRODUCER, 4, LIVE, 7));
  AdjacencyList producerAdj = activeList({
    Adjacent(conf.getRouterPrefix(), SELF_FACE, 5, Adjacent::STATUS_ACTIVE, 0, 0)
  });
  installAdj(PRODUCER, 4, producerAdj);
  advanceClocks(10_ms);
  BOOST_CHECK_EQUAL(countAvailability(PRODUCER, 4, LIVE), 0);
  waitForServiceBranchQuery();
  BOOST_CHECK(hasAvailabilityTo(PRODUCER, 4, LIVE, 99));
}

BOOST_AUTO_TEST_CASE(PsyncNewerSeqDoesNotAutoBind)
{
  corridor->noteServiceBranch(LIVE, 99);
  corridor->processAvailabilityInterest(makeAvailability(PRODUCER, 4, LIVE, 7));
  AdjacencyList producerAdj = activeList({
    Adjacent(conf.getRouterPrefix(), SELF_FACE, 5, Adjacent::STATUS_ACTIVE, 0, 0)
  });
  installAdj(PRODUCER, 5, producerAdj);
  advanceClocks(10_ms);
  BOOST_CHECK_EQUAL(corridor->getAdvertisedSeq(PRODUCER, Lsa::Type::ADJACENCY, LIVE), 4);
  BOOST_CHECK_EQUAL(countAvailability(PRODUCER, 5, LIVE), 0);
}

BOOST_AUTO_TEST_CASE(NewerAvailabilitySupersedes)
{
  corridor->processAvailabilityInterest(makeAvailability(PRODUCER, 4, LIVE, 7));
  corridor->processAvailabilityInterest(makeAvailability(PRODUCER, 6, LIVE, 7));
  BOOST_CHECK_EQUAL(corridor->getAdvertisedSeq(PRODUCER, Lsa::Type::ADJACENCY, LIVE), 6);
}

BOOST_AUTO_TEST_CASE(SameSeqNewBranchOnlyNewFace)
{
  AdjacencyList producerAdj = activeList({
    Adjacent(conf.getRouterPrefix(), SELF_FACE, 5, Adjacent::STATUS_ACTIVE, 0, 0)
  });
  installAdj(PRODUCER, 4, producerAdj);
  corridor->noteServiceBranch(LIVE, 11);
  corridor->processAvailabilityInterest(makeAvailability(PRODUCER, 4, LIVE, 7));
  advanceClocks(10_ms);
  BOOST_CHECK_EQUAL(countAvailability(PRODUCER, 4, LIVE), 0);
  waitForServiceBranchQuery();
  BOOST_CHECK(hasAvailabilityTo(PRODUCER, 4, LIVE, 11));

  face.sentInterests.clear();
  corridor->noteServiceBranch(LIVE, 12);
  BOOST_CHECK(hasAvailabilityTo(PRODUCER, 4, LIVE, 12));
  BOOST_CHECK(!hasAvailabilityTo(PRODUCER, 4, LIVE, 11));
}

BOOST_AUTO_TEST_CASE(MultipleDownstreamFacesFanout)
{
  AdjacencyList producerAdj = activeList({
    Adjacent(conf.getRouterPrefix(), SELF_FACE, 5, Adjacent::STATUS_ACTIVE, 0, 0)
  });
  installAdj(PRODUCER, 4, producerAdj);
  corridor->noteServiceBranch(LIVE, 11);
  corridor->noteServiceBranch(LIVE, 12);
  corridor->processAvailabilityInterest(makeAvailability(PRODUCER, 4, LIVE, 7));
  advanceClocks(10_ms);
  BOOST_CHECK_EQUAL(countAvailability(PRODUCER, 4, LIVE), 0);
  waitForServiceBranchQuery();
  BOOST_CHECK(hasAvailabilityTo(PRODUCER, 4, LIVE, 11));
  BOOST_CHECK(hasAvailabilityTo(PRODUCER, 4, LIVE, 12));
  const ndn::Name expected = Corridor::encodeAvailabilityName(conf.getNetwork(),
                                                              Lsa::Type::ADJACENCY, 4, PRODUCER, LIVE);
  size_t nMustBeFresh = 0;
  for (const auto& interest : face.sentInterests) {
    if (interest.getName() == expected) {
      BOOST_CHECK(interest.getMustBeFresh());
      BOOST_CHECK(!interest.getCanBePrefix());
      ++nMustBeFresh;
    }
  }
  BOOST_CHECK_EQUAL(nMustBeFresh, 2);
}

BOOST_AUTO_TEST_CASE(NoBranchesStops)
{
  AdjacencyList producerAdj = activeList({
    Adjacent(conf.getRouterPrefix(), SELF_FACE, 5, Adjacent::STATUS_ACTIVE, 0, 0)
  });
  installAdj(PRODUCER, 4, producerAdj);
  corridor->processAvailabilityInterest(makeAvailability(PRODUCER, 4, LIVE, 7));
  BOOST_CHECK_EQUAL(countAvailability(PRODUCER, 4, LIVE), 0);
  waitForServiceBranchQuery();
  BOOST_CHECK_EQUAL(countAvailability(PRODUCER, 4, LIVE), 0);
}

BOOST_AUTO_TEST_CASE(QueryFailureDoesNotAffectVanilla)
{
  corridor->start();
  advanceClocks(10_ms);
  installName(PRODUCER, 1, {LIVE});
  BOOST_CHECK(lsdb->findLsa<NameLsa>(PRODUCER) != nullptr);
}

BOOST_AUTO_TEST_CASE(MalformedAvailabilityNoAction)
{
  ndn::Interest bad("/localhop/ndn/nlsr/optoflood/corridor/ADJACENCY/not-a-number");
  bad.setTag(std::make_shared<ndn::lp::IncomingFaceIdTag>(7));
  corridor->noteServiceBranch(LIVE, 99);
  corridor->processAvailabilityInterest(bad);
  BOOST_CHECK_EQUAL(corridor->getAdvertisedSeq(PRODUCER, Lsa::Type::ADJACENCY, LIVE), 0);
  BOOST_CHECK_EQUAL(countAvailability(PRODUCER, 4, LIVE), 0);
}

BOOST_AUTO_TEST_CASE(ProducerAdjFirstLocalEndpointLater)
{
  installName(PRODUCER, 1, {LIVE});
  AdjacencyList producerAdj = activeList({
    Adjacent(conf.getRouterPrefix(), SELF_FACE, 5, Adjacent::STATUS_ACTIVE, 0, 0)
  });
  installAdj(PRODUCER, 3, producerAdj);
  Adjacent producerLink(PRODUCER, PRODUCER_FACE, 10, Adjacent::STATUS_ACTIVE, 0, 42);
  conf.getAdjacencyList().insert(producerLink);
  BOOST_CHECK_EQUAL(countAvailability(conf.getRouterPrefix(), 1, LIVE), 0);

  installAdj(conf.getRouterPrefix(), 1, conf.getAdjacencyList());
  advanceClocks(10_ms);
  BOOST_CHECK(hasAvailabilityTo(PRODUCER, 3, LIVE, 42));
  BOOST_CHECK(hasAvailabilityTo(conf.getRouterPrefix(), 1, LIVE, 42));
}

BOOST_AUTO_TEST_CASE(LocalEndpointFirstProducerAdjLater)
{
  Adjacent producerLink(PRODUCER, PRODUCER_FACE, 10, Adjacent::STATUS_ACTIVE, 0, 42);
  conf.getAdjacencyList().insert(producerLink);
  installAdj(conf.getRouterPrefix(), 1, conf.getAdjacencyList());
  installName(PRODUCER, 1, {LIVE});
  face.sentInterests.clear();

  AdjacencyList producerAdj = activeList({
    Adjacent(conf.getRouterPrefix(), SELF_FACE, 5, Adjacent::STATUS_ACTIVE, 0, 0)
  });
  installAdj(PRODUCER, 3, producerAdj);
  advanceClocks(10_ms);
  BOOST_CHECK(hasAvailabilityTo(PRODUCER, 3, LIVE, 42));
  BOOST_CHECK(hasAvailabilityTo(conf.getRouterPrefix(), 1, LIVE, 42));
}

BOOST_AUTO_TEST_CASE(NameLsaInstalledLastBindsFromFullNpl)
{
  Adjacent producerLink(PRODUCER, PRODUCER_FACE, 10, Adjacent::STATUS_ACTIVE, 0, 42);
  conf.getAdjacencyList().insert(producerLink);
  installAdj(conf.getRouterPrefix(), 1, conf.getAdjacencyList());
  AdjacencyList producerAdj = activeList({
    Adjacent(conf.getRouterPrefix(), SELF_FACE, 5, Adjacent::STATUS_ACTIVE, 0, 0)
  });
  installAdj(PRODUCER, 3, producerAdj);
  face.sentInterests.clear();

  installName(PRODUCER, 1, {LIVE});
  advanceClocks(10_ms);
  BOOST_CHECK(hasAvailabilityTo(PRODUCER, 3, LIVE, 42));
  BOOST_CHECK(hasAvailabilityTo(conf.getRouterPrefix(), 1, LIVE, 42));
}

BOOST_AUTO_TEST_CASE(ProducerNoLongerDeclaresEndpointStopsNewPair)
{
  Adjacent producerLink(PRODUCER, PRODUCER_FACE, 10, Adjacent::STATUS_ACTIVE, 0, 42);
  conf.getAdjacencyList().insert(producerLink);
  installAdj(conf.getRouterPrefix(), 1, conf.getAdjacencyList());
  installName(PRODUCER, 1, {LIVE});
  AdjacencyList producerAdj = activeList({
    Adjacent(conf.getRouterPrefix(), SELF_FACE, 5, Adjacent::STATUS_ACTIVE, 0, 0)
  });
  installAdj(PRODUCER, 3, producerAdj);
  face.sentInterests.clear();

  AdjacencyList moved = activeList({
    Adjacent(AP2, AP2_FACE, 5, Adjacent::STATUS_ACTIVE, 0, 0)
  });
  installAdj(PRODUCER, 4, moved);
  advanceClocks(10_ms);
  BOOST_CHECK_EQUAL(countAvailability(PRODUCER, 4, LIVE), 0);
}

BOOST_AUTO_TEST_CASE(MultiHomedProducerAdvertisesLocalEndpointOnly)
{
  Adjacent producerLink(PRODUCER, PRODUCER_FACE, 10, Adjacent::STATUS_ACTIVE, 0, 42);
  conf.getAdjacencyList().insert(producerLink);
  installAdj(conf.getRouterPrefix(), 1, conf.getAdjacencyList());
  installName(PRODUCER, 1, {LIVE});
  AdjacencyList producerAdj = activeList({
    Adjacent(conf.getRouterPrefix(), SELF_FACE, 5, Adjacent::STATUS_ACTIVE, 0, 0),
    Adjacent(AP2, AP2_FACE, 5, Adjacent::STATUS_ACTIVE, 0, 0)
  });
  installAdj(PRODUCER, 3, producerAdj);
  AdjacencyList ap2Adj = activeList({
    Adjacent(PRODUCER, PRODUCER_FACE, 5, Adjacent::STATUS_ACTIVE, 0, 0)
  });
  installAdj(AP2, 1, ap2Adj);
  advanceClocks(10_ms);

  BOOST_CHECK(hasAvailabilityTo(PRODUCER, 3, LIVE, 42));
  BOOST_CHECK(hasAvailabilityTo(conf.getRouterPrefix(), 1, LIVE, 42));
  BOOST_CHECK_EQUAL(countAvailability(AP2, 1, LIVE), 0);
}

BOOST_AUTO_TEST_CASE(StaticAggNewApNotBoundToLiveStream)
{
  Adjacent aggLink(AGG, AGG_FACE, 10, Adjacent::STATUS_ACTIVE, 0, 55);
  conf.getAdjacencyList().insert(aggLink);
  installAdj(conf.getRouterPrefix(), 1, conf.getAdjacencyList());
  AdjacencyList aggAdj = activeList({
    Adjacent(conf.getRouterPrefix(), SELF_FACE, 10, Adjacent::STATUS_ACTIVE, 0, 0)
  });
  installAdj(AGG, 1, aggAdj);
  installName(AGG, 1, {ndn::Name("/agg")});
  installName(PRODUCER, 1, {LIVE});
  advanceClocks(10_ms);

  BOOST_CHECK_EQUAL(countAvailability(AGG, 1, LIVE), 0);
  BOOST_CHECK_EQUAL(countAvailability(conf.getRouterPrefix(), 1, LIVE), 0);
}

BOOST_AUTO_TEST_CASE(FaceDestroyedRemovesAdvertisedFace)
{
  Adjacent neighbor(PRODUCER, PRODUCER_FACE, 10, Adjacent::STATUS_ACTIVE, 0, 42);
  conf.getAdjacencyList().insert(neighbor);
  installName(conf.getRouterPrefix(), 2, {LIVE});
  installAdj(conf.getRouterPrefix(), 1, conf.getAdjacencyList());
  BOOST_CHECK(corridor->hasAdvertisedFace(conf.getRouterPrefix(), Lsa::Type::ADJACENCY, LIVE, 42));
  corridor->onFaceDestroyed(42);
  BOOST_CHECK(!corridor->hasAdvertisedFace(conf.getRouterPrefix(), Lsa::Type::ADJACENCY, LIVE, 42));
}

BOOST_AUTO_TEST_CASE(ExactQueryReplacesBranchCache)
{
  corridor->noteServiceBranch(LIVE, 11);
  corridor->noteServiceBranch(LIVE, 12);
  BOOST_CHECK_EQUAL(corridor->getBranchFaces(LIVE).size(), 2);

  corridor->replaceServiceBranchSnapshot(LIVE, {12, 13});
  auto replaced = corridor->getBranchFaces(LIVE);
  BOOST_CHECK_EQUAL(replaced.size(), 2);
  BOOST_CHECK_EQUAL(replaced.count(11), 0);
  BOOST_CHECK_EQUAL(replaced.count(12), 1);
  BOOST_CHECK_EQUAL(replaced.count(13), 1);

  AdjacencyList producerAdj = activeList({
    Adjacent(conf.getRouterPrefix(), SELF_FACE, 5, Adjacent::STATUS_ACTIVE, 0, 0)
  });
  installAdj(PRODUCER, 4, producerAdj);
  face.sentInterests.clear();
  corridor->processAvailabilityInterest(makeAvailability(PRODUCER, 4, LIVE, 7));
  advanceClocks(10_ms);
  BOOST_CHECK_EQUAL(countAvailability(PRODUCER, 4, LIVE), 0);
  waitForServiceBranchQuery();
  BOOST_CHECK(hasAvailabilityTo(PRODUCER, 4, LIVE, 12));
  BOOST_CHECK(hasAvailabilityTo(PRODUCER, 4, LIVE, 13));
  BOOST_CHECK(!hasAvailabilityTo(PRODUCER, 4, LIVE, 11));

  corridor->replaceServiceBranchSnapshot(LIVE, {});
  BOOST_CHECK(!corridor->hasCachedServiceBranch(LIVE));
  BOOST_CHECK(corridor->getBranchFaces(LIVE).empty());
}

BOOST_AUTO_TEST_CASE(FailedExactQueryDoesNotEraseCache)
{
  corridor->noteServiceBranch(LIVE, 11);
  corridor->noteServiceBranch(LIVE, 12);
  corridor->queryServiceBranches(LIVE);
  waitForServiceBranchQuery();
  BOOST_CHECK(corridor->hasCachedServiceBranch(LIVE));
  auto faces = corridor->getBranchFaces(LIVE);
  BOOST_CHECK_EQUAL(faces.count(11), 1);
  BOOST_CHECK_EQUAL(faces.count(12), 1);
}

BOOST_AUTO_TEST_CASE(NotificationAfterEmptySnapshot)
{
  corridor->replaceServiceBranchSnapshot(LIVE, {});
  BOOST_CHECK(!corridor->hasCachedServiceBranch(LIVE));
  corridor->noteServiceBranch(LIVE, 14);
  BOOST_CHECK(corridor->hasCachedServiceBranch(LIVE));
  BOOST_CHECK_EQUAL(corridor->getBranchFaces(LIVE).count(14), 1);

  corridor->replaceServiceBranchSnapshot(LIVE, {15});
  BOOST_CHECK_EQUAL(corridor->getBranchFaces(LIVE).count(14), 0);
  BOOST_CHECK_EQUAL(corridor->getBranchFaces(LIVE).count(15), 1);
}

BOOST_AUTO_TEST_CASE(AvailabilityReplyHasZeroFreshness)
{
  corridor->processAvailabilityInterest(makeAvailability(PRODUCER, 4, LIVE, 7));
  BOOST_REQUIRE(!face.sentData.empty());
  BOOST_CHECK_EQUAL(face.sentData.back().getFreshnessPeriod(), 0_ms);

  ndn::Interest interest(Corridor::encodeAvailabilityName(conf.getNetwork(), Lsa::Type::ADJACENCY,
                                                          4, PRODUCER, LIVE));
  interest.setCanBePrefix(false);
  interest.setMustBeFresh(true);
  interest.setInterestLifetime(1_s);
  interest.setTag(std::make_shared<ndn::lp::NextHopFaceIdTag>(11));
  BOOST_CHECK(interest.getMustBeFresh());
  BOOST_CHECK(!interest.getCanBePrefix());
}

BOOST_AUTO_TEST_CASE(FeatureOffDoesNotRegisterCorridor)
{
  ndn::DummyClientFace offFace(m_io, m_keyChain, {true, true});
  ConfParameter offConf(offFace, m_keyChain);
  DummyConfFileProcessor offProc(offConf);
  BOOST_CHECK_EQUAL(offConf.getCorridorPrioritisedRouting(), false);
  Nlsr nlsr(offFace, m_keyChain, offConf);
  advanceClocks(10_ms);

  const ndn::Name corridorPrefix = Corridor::makePrefix(offConf.getNetwork());
  for (const auto& interest : offFace.sentInterests) {
    BOOST_CHECK(!corridorPrefix.isPrefixOf(interest.getName()));
    const auto& name = interest.getName();
    if (name.size() > 4 && name[3] == ndn::name::Component("register")) {
      ndn::nfd::ControlParameters params(name[4].blockFromValue());
      if (params.hasName()) {
        BOOST_CHECK(!corridorPrefix.isPrefixOf(params.getName()));
        BOOST_CHECK(params.getName() != corridorPrefix);
      }
    }
  }
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace nlsr::tests
