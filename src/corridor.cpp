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

#include "adjacent.hpp"
#include "logger.hpp"

#include <ndn-cxx/lp/tags.hpp>
#include <ndn-cxx/mgmt/nfd/fib-entry.hpp>
#include <ndn-cxx/mgmt/nfd/status-dataset.hpp>

#include <boost/lexical_cast.hpp>

#include <sstream>

namespace nlsr {

INIT_LOGGER(Corridor);

namespace {

const ndn::Name SERVICE_BRANCH_EVENTS_PREFIX("/localhost/nfd/optoflood/service-branch-events");

class ServiceBranchDataset : public ndn::nfd::StatusDatasetBase
{
public:
  ServiceBranchDataset()
    : StatusDatasetBase("optoflood/service-branches")
  {
  }

  explicit
  ServiceBranchDataset(const ndn::Name& prefix)
    : StatusDatasetBase(ndn::Name("optoflood/service-branches").append(prefix))
  {
  }

  std::vector<ndn::nfd::FibEntry>
  parseResult(ndn::ConstBufferPtr payload) const
  {
    std::vector<ndn::nfd::FibEntry> result;
    size_t offset = 0;
    while (offset < payload->size()) {
      auto [isOk, block] = ndn::Block::fromBuffer(payload, offset);
      if (!isOk) {
        NDN_THROW(ndn::nfd::StatusDatasetParseError(
          "Cannot decode ServiceBranch dataset at offset " + std::to_string(offset)));
      }
      try {
        result.emplace_back(block);
      }
      catch (const ndn::tlv::Error& e) {
        NDN_THROW_NESTED(ndn::nfd::StatusDatasetParseError(e.what()));
      }
      offset += block.size();
    }
    return result;
  }
};

ndn::span<const uint8_t>
asSpan(const ndn::Block& wire)
{
  return {wire.data(), wire.size()};
}

std::shared_ptr<Lsa>
findInstalledLsa(Lsdb& lsdb, const ndn::Name& origin, Lsa::Type type)
{
  if (type == Lsa::Type::ADJACENCY) {
    return lsdb.findLsa<AdjLsa>(origin);
  }
  if (type == Lsa::Type::NAME) {
    return lsdb.findLsa<NameLsa>(origin);
  }
  return nullptr;
}

} // namespace

ndn::Name
Corridor::makePrefix(const ndn::Name& network)
{
  ndn::Name prefix;
  prefix.append("localhop");
  prefix.append(network);
  prefix.append("nlsr");
  prefix.append("optoflood");
  prefix.append("corridor");
  return prefix;
}

ndn::Name
Corridor::encodeAvailabilityName(const ndn::Name& network, Lsa::Type type, uint64_t seq,
                                 const ndn::Name& origin, const ndn::Name& prefix)
{
  ndn::Name name = makePrefix(network);
  name.append(boost::lexical_cast<std::string>(type));
  name.appendNumber(seq);
  const ndn::Block& originWire = origin.wireEncode();
  name.append(asSpan(originWire));
  const ndn::Block& prefixWire = prefix.wireEncode();
  name.append(asSpan(prefixWire));
  return name;
}

std::optional<CorridorAvailability>
Corridor::parseAvailabilityName(const ndn::Name& name)
{
  ssize_t corridorPos = -1;
  for (ssize_t i = 0; i < static_cast<ssize_t>(name.size()); ++i) {
    if (name[i].toUri() == "corridor") {
      corridorPos = i;
      break;
    }
  }
  if (corridorPos < 2 ||
      name.size() != static_cast<size_t>(corridorPos) + 5 ||
      name[corridorPos - 1].toUri() != "optoflood" ||
      name[corridorPos - 2].toUri() != "nlsr") {
    return std::nullopt;
  }

  CorridorAvailability av;
  std::istringstream(name[corridorPos + 1].toUri()) >> av.type;
  if (av.type != Lsa::Type::ADJACENCY) {
    return std::nullopt;
  }
  if (!name[corridorPos + 2].isNumber()) {
    return std::nullopt;
  }
  av.seq = name[corridorPos + 2].toNumber();
  try {
    av.origin.wireDecode(name[corridorPos + 3].blockFromValue());
    av.prefix.wireDecode(name[corridorPos + 4].blockFromValue());
  }
  catch (const ndn::tlv::Error&) {
    return std::nullopt;
  }
  if (av.origin.empty() || av.prefix.empty()) {
    return std::nullopt;
  }
  return av;
}

Corridor::Corridor(ndn::Face& face, ndn::KeyChain& keyChain, ConfParameter& confParam, Lsdb& lsdb)
  : m_face(face)
  , m_keyChain(keyChain)
  , m_confParam(confParam)
  , m_lsdb(lsdb)
  , m_controller(face, keyChain)
  , m_branchEvents(face, SERVICE_BRANCH_EVENTS_PREFIX)
  , m_lsdbConnection(lsdb.onLsdbModified.connect(
      [this] (const auto& lsa, auto updateType, const auto& namesToAdd, const auto& namesToRemove) {
        onLsdbModified(lsa, updateType, namesToAdd, namesToRemove);
      }))
{
}

void
Corridor::start()
{
  const ndn::Name prefix = makePrefix(m_confParam.getNetwork());
  NLSR_LOG_DEBUG("Setting corridor availability filter: " << prefix);

  m_face.setInterestFilter(ndn::InterestFilter(prefix).allowLoopback(false),
    [this] (const auto&, const auto& interest) { processAvailabilityInterest(interest); },
    [] (const auto& name) { NLSR_LOG_DEBUG("Successfully registered prefix: " << name); },
    [] (const auto& name, const auto& reason) {
      NLSR_LOG_ERROR("Failed to register corridor prefix " << name << " reason=" << reason);
    },
    m_confParam.getSigningInfo(), ndn::nfd::ROUTE_FLAG_CAPTURE);

  m_branchNotificationConnection = m_branchEvents.onNotification.connect(
    [this] (const ndn::nfd::ControlParameters& params) {
      if (!params.hasName() || !params.hasFaceId()) {
        return;
      }
      noteServiceBranch(params.getName(), params.getFaceId());
    });
  m_branchEvents.start();
  // Startup-only catch-up into an empty cache. Exact queries later REPLACE per prefix.
  queryAllServiceBranches();
}

void
Corridor::onFaceDestroyed(uint64_t faceId)
{
  for (auto& [prefix, faces] : m_branches) {
    faces.erase(faceId);
  }
  for (auto& [key, state] : m_state) {
    state.advertisedFaces.erase(faceId);
  }
}

void
Corridor::onLsdbModified(const std::shared_ptr<Lsa>& lsa, LsdbUpdate updateType,
                         const std::list<ndn::Name>&, const std::list<ndn::Name>&)
{
  if (updateType == LsdbUpdate::REMOVED) {
    for (auto it = m_state.begin(); it != m_state.end(); ) {
      if (it->first.origin == lsa->getOriginRouter() && it->first.type == lsa->getType()) {
        it = m_state.erase(it);
      }
      else {
        ++it;
      }
    }
    return;
  }

  if (updateType != LsdbUpdate::INSTALLED && updateType != LsdbUpdate::UPDATED) {
    return;
  }

  if (lsa->getType() == Lsa::Type::ADJACENCY || lsa->getType() == Lsa::Type::NAME) {
    maybeAdvertiseServiceAttachment();
  }

  if (lsa->getType() == Lsa::Type::ADJACENCY &&
      lsa->getOriginRouter() == m_confParam.getRouterPrefix()) {
    advertiseOwnAdjFirstHop();
  }

  if (lsa->getType() == Lsa::Type::ADJACENCY) {
    propagateIfAssociated(*lsa);
  }
}

void
Corridor::processAvailabilityInterest(const ndn::Interest& interest)
{
  auto parsed = parseAvailabilityName(interest.getName());
  if (!parsed) {
    NLSR_LOG_DEBUG("Ignoring malformed corridor availability " << interest.getName());
    return;
  }

  replyAvailability(interest);

  const auto& av = *parsed;
  auto incoming = interest.getTag<ndn::lp::IncomingFaceIdTag>();
  const uint64_t faceId = incoming == nullptr ? 0 : *incoming;

  auto local = findInstalledLsa(m_lsdb, av.origin, av.type);
  const uint64_t localSeq = local == nullptr ? 0 : local->getSeqNo();

  if (local != nullptr && localSeq > av.seq) {
    NLSR_LOG_DEBUG("Ignoring stale corridor availability seq=" << av.seq
                   << " local=" << localSeq << " origin=" << av.origin);
    return;
  }

  recordAssociation(av.origin, av.type, av.seq, av.prefix);

  if (local == nullptr || localSeq < av.seq) {
    if (faceId != 0) {
      m_lsdb.fetchLsaFromFace(av.origin, av.type, av.seq, faceId);
    }
    return;
  }

  // local seq == N: already validated/installed; refresh ServiceBranch then fan out
  queryServiceBranches(av.prefix);
}

void
Corridor::noteServiceBranch(const ndn::Name& prefix, uint64_t faceId)
{
  if (faceId == 0) {
    return;
  }
  m_branches[prefix].insert(faceId);

  for (auto& [key, state] : m_state) {
    if (key.prefix != prefix) {
      continue;
    }
    auto lsa = findInstalledLsa(m_lsdb, key.origin, key.type);
    if (lsa != nullptr && lsa->getSeqNo() == state.seq) {
      advertise(key.origin, key.type, state.seq, key.prefix, {faceId});
    }
  }
}

void
Corridor::maybeAdvertiseServiceAttachment()
{
  const ndn::Name& self = m_confParam.getRouterPrefix();
  auto selfAdj = m_lsdb.findLsa<AdjLsa>(self);
  if (selfAdj == nullptr) {
    return;
  }

  auto range = m_lsdb.getLsdbIterator<NameLsa>();
  for (auto it = range.first; it != range.second; ++it) {
    auto nameLsa = std::static_pointer_cast<NameLsa>(*it);
    const ndn::Name& originR = nameLsa->getOriginRouter();
    if (originR == self) {
      continue;
    }
    auto remoteAdj = m_lsdb.findLsa<AdjLsa>(originR);
    if (remoteAdj == nullptr) {
      continue;
    }
    if (!remoteAdj->getAdl().isNeighbor(self) || !selfAdj->getAdl().isNeighbor(originR)) {
      continue;
    }

    auto faces = getActiveAdjacencyFaces();
    for (const auto& prefix : nameLsa->getNpl().getNames()) {
      advertise(originR, Lsa::Type::ADJACENCY, remoteAdj->getSeqNo(), prefix, faces);
      advertise(self, Lsa::Type::ADJACENCY, selfAdj->getSeqNo(), prefix, faces);
      queryServiceBranches(prefix);
    }
  }
}

void
Corridor::advertiseOwnAdjFirstHop()
{
  const ndn::Name& self = m_confParam.getRouterPrefix();
  auto ownAdj = m_lsdb.findLsa<AdjLsa>(self);
  auto ownName = m_lsdb.findLsa<NameLsa>(self);
  if (ownAdj == nullptr || ownName == nullptr) {
    return;
  }

  const auto faces = getActiveAdjacencyFaces();
  for (const auto& prefix : ownName->getNpl().getNames()) {
    advertise(self, Lsa::Type::ADJACENCY, ownAdj->getSeqNo(), prefix, faces);
  }
}

void
Corridor::propagateIfAssociated(const Lsa& lsa)
{
  for (auto& [key, state] : m_state) {
    if (key.origin != lsa.getOriginRouter() || key.type != lsa.getType()) {
      continue;
    }
    if (state.seq != lsa.getSeqNo()) {
      continue;
    }
    queryServiceBranches(key.prefix);
  }
}

void
Corridor::advertise(const ndn::Name& origin, Lsa::Type type, uint64_t seq, const ndn::Name& prefix,
                    const std::set<uint64_t>& faces)
{
  if (seq == 0) {
    return;
  }

  AdvertisementKey key{origin, type, prefix};
  auto& state = m_state[key];
  if (seq < state.seq) {
    return;
  }
  if (seq > state.seq) {
    state.seq = seq;
    state.advertisedFaces.clear();
  }

  for (uint64_t faceId : faces) {
    if (faceId == 0 || state.advertisedFaces.count(faceId) > 0) {
      continue;
    }
    sendAvailability(origin, type, seq, prefix, faceId);
    state.advertisedFaces.insert(faceId);
  }
}

void
Corridor::sendAvailability(const ndn::Name& origin, Lsa::Type type, uint64_t seq,
                           const ndn::Name& prefix, uint64_t faceId)
{
  ndn::Interest interest(encodeAvailabilityName(m_confParam.getNetwork(), type, seq, origin, prefix));
  interest.setCanBePrefix(false);
  interest.setMustBeFresh(true);
  interest.setInterestLifetime(AVAILABILITY_LIFETIME);
  interest.setTag(std::make_shared<ndn::lp::NextHopFaceIdTag>(faceId));
  NLSR_LOG_DEBUG("Corridor availability origin=" << origin << " seq=" << seq
                 << " prefix=" << prefix << " face=" << faceId);
  m_face.expressInterest(interest, nullptr, nullptr, nullptr);
}

void
Corridor::replyAvailability(const ndn::Interest& interest)
{
  auto data = std::make_shared<ndn::Data>(interest.getName());
  data->setFreshnessPeriod(0_ms);
  m_keyChain.sign(*data, m_confParam.getSigningInfo());
  m_face.put(*data);
}

void
Corridor::replaceServiceBranchSnapshot(const ndn::Name& prefix, const std::set<uint64_t>& faces)
{
  if (faces.empty()) {
    m_branches.erase(prefix);
    return;
  }
  m_branches[prefix] = faces;
}

void
Corridor::advertiseAssociated(const ndn::Name& prefix)
{
  const auto faces = getBranchFaces(prefix);
  for (auto& [key, state] : m_state) {
    if (key.prefix != prefix) {
      continue;
    }
    auto lsa = findInstalledLsa(m_lsdb, key.origin, key.type);
    if (lsa != nullptr && lsa->getSeqNo() == state.seq) {
      advertise(key.origin, key.type, state.seq, key.prefix, faces);
    }
  }
}

void
Corridor::queryServiceBranches(const ndn::Name& prefix)
{
  m_controller.fetch<ServiceBranchDataset>(
    prefix,
    [this, prefix] (const std::vector<ndn::nfd::FibEntry>& entries) {
      std::set<uint64_t> snapshot;
      for (const auto& entry : entries) {
        const ndn::Name& branchPrefix = entry.getPrefix().empty() ? prefix : entry.getPrefix();
        if (branchPrefix != prefix) {
          continue;
        }
        for (const auto& nh : entry.getNextHopRecords()) {
          if (nh.getFaceId() != 0) {
            snapshot.insert(nh.getFaceId());
          }
        }
      }
      replaceServiceBranchSnapshot(prefix, snapshot);
      advertiseAssociated(prefix);
    },
    [this, prefix] (uint32_t code, const std::string& reason) {
      NLSR_LOG_DEBUG("ServiceBranch query failed code=" << code << " reason=" << reason);
      advertiseAssociated(prefix);
    });
}

void
Corridor::queryAllServiceBranches()
{
  // Startup only: the cache is empty. Later exact queries REPLACE one prefix.
  m_controller.fetch<ServiceBranchDataset>(
    [this] (const std::vector<ndn::nfd::FibEntry>& entries) {
      for (const auto& entry : entries) {
        for (const auto& nh : entry.getNextHopRecords()) {
          noteServiceBranch(entry.getPrefix(), nh.getFaceId());
        }
      }
    },
    [] (uint32_t code, const std::string& reason) {
      NLSR_LOG_DEBUG("ServiceBranch list query failed code=" << code << " reason=" << reason);
    });
}

std::set<uint64_t>
Corridor::getActiveAdjacencyFaces() const
{
  std::set<uint64_t> faces;
  for (const auto& adj : m_confParam.getAdjacencyList().getAdjList()) {
    if (adj.getStatus() == Adjacent::STATUS_ACTIVE && adj.getFaceId() != 0) {
      faces.insert(adj.getFaceId());
    }
  }
  return faces;
}

std::set<uint64_t>
Corridor::getBranchFaces(const ndn::Name& prefix) const
{
  auto it = m_branches.find(prefix);
  if (it == m_branches.end()) {
    return {};
  }
  return it->second;
}

bool
Corridor::hasCachedServiceBranch(const ndn::Name& prefix) const
{
  return m_branches.find(prefix) != m_branches.end();
}

Corridor::AdvertisementState*
Corridor::findState(const ndn::Name& origin, Lsa::Type type, const ndn::Name& prefix)
{
  AdvertisementKey key{origin, type, prefix};
  auto it = m_state.find(key);
  return it == m_state.end() ? nullptr : &it->second;
}

const Corridor::AdvertisementState*
Corridor::findState(const ndn::Name& origin, Lsa::Type type, const ndn::Name& prefix) const
{
  AdvertisementKey key{origin, type, prefix};
  auto it = m_state.find(key);
  return it == m_state.end() ? nullptr : &it->second;
}

void
Corridor::recordAssociation(const ndn::Name& origin, Lsa::Type type, uint64_t seq,
                            const ndn::Name& prefix)
{
  AdvertisementKey key{origin, type, prefix};
  auto& state = m_state[key];
  if (seq < state.seq) {
    return;
  }
  if (seq > state.seq) {
    state.seq = seq;
    state.advertisedFaces.clear();
  }
}

uint64_t
Corridor::getAdvertisedSeq(const ndn::Name& origin, Lsa::Type type, const ndn::Name& prefix) const
{
  auto* state = findState(origin, type, prefix);
  return state == nullptr ? 0 : state->seq;
}

size_t
Corridor::countAdvertisedFaces(const ndn::Name& origin, Lsa::Type type, const ndn::Name& prefix) const
{
  auto* state = findState(origin, type, prefix);
  return state == nullptr ? 0 : state->advertisedFaces.size();
}

bool
Corridor::hasAdvertisedFace(const ndn::Name& origin, Lsa::Type type, const ndn::Name& prefix,
                            uint64_t faceId) const
{
  auto* state = findState(origin, type, prefix);
  return state != nullptr && state->advertisedFaces.count(faceId) > 0;
}

} // namespace nlsr
