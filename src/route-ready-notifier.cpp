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

#include "route-ready-notifier.hpp"
#include "logger.hpp"

#include <ndn-cxx/lp/nack.hpp>

namespace nlsr {

INIT_LOGGER(RouteReadyNotifier);

namespace {

/*! Local signal prefix consumed by the forwarder's OptoFlood module:
 *  /localhost/nfd/optoflood/route-ready/<prefix>. The forwarder consumes the
 *  Interest without answering it, so it is expressed fire-and-forget with a short
 *  lifetime.
 */
const ndn::Name ROUTE_READY_PREFIX("/localhost/nfd/optoflood/route-ready");
constexpr ndn::time::milliseconds ROUTE_READY_LIFETIME = 1_s;

} // namespace

RouteReadyNotifier::RouteReadyNotifier(ndn::Face& face, Lsdb& lsdb)
  : m_face(face)
  , m_lsdb(lsdb)
  , m_lsdbConnection(lsdb.onLsdbModified.connect(
      [this] (std::shared_ptr<Lsa> lsa, LsdbUpdate updateType,
              const auto& /*namesToAdd*/, const auto& /*namesToRemove*/) {
        this->onLsdbModified(lsa, updateType);
      }))
{
}

void
RouteReadyNotifier::onLsdbModified(const std::shared_ptr<Lsa>& lsa, LsdbUpdate updateType)
{
  if (lsa->getType() != Lsa::Type::ADJACENCY) {
    // A Name LSA carries the prefix-to-router mapping, which is read on demand in
    // announce(); it does not by itself change the topology.
    return;
  }

  const ndn::Name& originRouter = lsa->getOriginRouter();

  if (updateType == LsdbUpdate::REMOVED) {
    // A router without an Adjacency LSA is isolated, so no readiness can follow.
    // The record is emptied rather than erased, so that a later LSA is recognised
    // as a change instead of as a first sighting.
    m_adjacencies[originRouter].clear();
    return;
  }

  // Read the installed LSA rather than the argument: on an update the database holds
  // the merged content, which is what the routing calculation will use.
  auto installed = m_lsdb.findLsa<AdjLsa>(originRouter);
  if (installed == nullptr) {
    return;
  }

  if (recordAdjacencies(*installed)) {
    NLSR_LOG_DEBUG("Adjacency set of " << originRouter << " changed, awaiting a "
                   "bidirectionally consistent adjacency");
    m_pending.insert(originRouter);
  }

  evaluatePending();
}

bool
RouteReadyNotifier::recordAdjacencies(const AdjLsa& lsa)
{
  std::set<ndn::Name> current;
  for (const auto& adjacent : lsa.getAdl().getAdjList()) {
    current.insert(adjacent.getName());
  }

  auto [it, inserted] = m_adjacencies.try_emplace(lsa.getOriginRouter(), current);
  if (inserted) {
    // First sighting of this router: its position is not a change we must track.
    return false;
  }
  if (it->second == current) {
    return false;
  }
  it->second = std::move(current);
  return true;
}

bool
RouteReadyNotifier::hasBidirectionalAdjacency(const ndn::Name& router) const
{
  auto lsa = m_lsdb.findLsa<AdjLsa>(router);
  if (lsa == nullptr) {
    return false;
  }

  for (const auto& adjacent : lsa->getAdl().getAdjList()) {
    auto neighbourLsa = m_lsdb.findLsa<AdjLsa>(adjacent.getName());
    if (neighbourLsa != nullptr && neighbourLsa->getAdl().isNeighbor(router)) {
      return true;
    }
  }
  return false;
}

void
RouteReadyNotifier::evaluatePending()
{
  for (auto it = m_pending.begin(); it != m_pending.end(); ) {
    if (hasBidirectionalAdjacency(*it)) {
      announce(*it);
      it = m_pending.erase(it);
    }
    else {
      ++it;
    }
  }
}

void
RouteReadyNotifier::announce(const ndn::Name& router)
{
  auto nameLsa = m_lsdb.findLsa<NameLsa>(router);
  if (nameLsa == nullptr) {
    return;
  }

  for (const auto& prefix : nameLsa->getNpl().getNames()) {
    ndn::Name signalName(ROUTE_READY_PREFIX);
    signalName.append(prefix);

    ndn::Interest interest(signalName);
    interest.setCanBePrefix(false);
    interest.setMustBeFresh(true);
    interest.setInterestLifetime(ROUTE_READY_LIFETIME);
    m_face.expressInterest(interest,
                           [] (const ndn::Interest&, const ndn::Data&) {},
                           [] (const ndn::Interest&, const ndn::lp::Nack&) {},
                           [] (const ndn::Interest&) {});

    NLSR_LOG_DEBUG("Announced route-ready for " << prefix << " of router " << router);
  }
}

} // namespace nlsr
