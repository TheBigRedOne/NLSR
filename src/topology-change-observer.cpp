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

#include "topology-change-observer.hpp"
#include "logger.hpp"

#include <algorithm>
#include <iterator>
#include <utility>
#include <vector>

namespace nlsr {

INIT_LOGGER(TopologyChangeObserver);

TopologyChangeObserver::TopologyChangeObserver(Lsdb& lsdb)
  : m_lsdb(lsdb)
  , m_lsdbConnection(lsdb.onLsdbModified.connect(
      [this] (std::shared_ptr<Lsa> lsa, LsdbUpdate updateType,
              const auto& /*namesToAdd*/, const auto& /*namesToRemove*/) {
        this->onLsdbModified(lsa, updateType);
      }))
{
}

void
TopologyChangeObserver::onLsdbModified(const std::shared_ptr<Lsa>& lsa, LsdbUpdate updateType)
{
  if (lsa->getType() != Lsa::Type::ADJACENCY) {
    // A Name LSA carries the prefix-to-router mapping, which consumers read on
    // demand; it does not by itself change the topology.
    return;
  }

  const ndn::Name& originRouter = lsa->getOriginRouter();

  if (updateType == LsdbUpdate::REMOVED) {
    // A router without an Adjacency LSA declares nothing, so no adjacency of its can
    // be reciprocal. The record is emptied rather than erased, so that a later LSA is
    // recognised as a change instead of as a first sighting. Any change still awaiting
    // confirmation is moot once the LSA it belongs to is gone.
    m_adjacencies[originRouter].clear();
    m_pending.erase(originRouter);
    return;
  }

  // Read the installed LSA rather than the argument: on an update the database holds
  // the merged content, which is what the routing calculation will use.
  auto installed = m_lsdb.findLsa<AdjLsa>(originRouter);
  if (installed == nullptr) {
    return;
  }

  bool isChanged = false;
  auto added = recordAdjacencies(*installed, isChanged);
  if (isChanged) {
    NLSR_LOG_DEBUG("Adjacency set of " << originRouter << " changed, "
                   << added.size() << " adjacency(ies) added");
    // A later change supersedes an earlier one, including whether reachability has
    // been reported: forwarding state installed for the later change needs its own
    // report.
    auto& pending = m_pending[originRouter];
    pending.added = std::move(added);
    pending.reachableReported = false;
  }

  evaluatePending();
}

std::set<ndn::Name>
TopologyChangeObserver::recordAdjacencies(const AdjLsa& lsa, bool& isChanged)
{
  std::set<ndn::Name> current;
  for (const auto& adjacent : lsa.getAdl().getAdjList()) {
    current.insert(adjacent.getName());
  }

  isChanged = false;
  auto [it, inserted] = m_adjacencies.try_emplace(lsa.getOriginRouter(), current);
  if (inserted || it->second == current) {
    // A first sighting is the starting point rather than a change.
    return {};
  }

  std::set<ndn::Name> added;
  std::set_difference(current.begin(), current.end(), it->second.begin(), it->second.end(),
                      std::inserter(added, added.end()));
  it->second = std::move(current);
  isChanged = true;
  return added;
}

bool
TopologyChangeObserver::declaresBack(const ndn::Name& neighbour, const ndn::Name& router) const
{
  auto neighbourLsa = m_lsdb.findLsa<AdjLsa>(neighbour);
  return neighbourLsa != nullptr && neighbourLsa->getAdl().isNeighbor(router);
}

bool
TopologyChangeObserver::hasReciprocalAdjacency(const ndn::Name& router) const
{
  auto lsa = m_lsdb.findLsa<AdjLsa>(router);
  if (lsa == nullptr) {
    return false;
  }

  // Only the adjacencies the router currently declares are considered, so a former
  // neighbour that still declares the router cannot make it appear reachable.
  for (const auto& adjacent : lsa->getAdl().getAdjList()) {
    if (declaresBack(adjacent.getName(), router)) {
      return true;
    }
  }
  return false;
}

bool
TopologyChangeObserver::areAllReciprocal(const ndn::Name& router,
                                         const std::set<ndn::Name>& added) const
{
  // A change that only removes adjacencies leaves nothing to confirm: the router's
  // own new LSA already invalidates the links it no longer declares.
  return std::all_of(added.begin(), added.end(),
                     [&] (const ndn::Name& neighbour) { return declaresBack(neighbour, router); });
}

void
TopologyChangeObserver::evaluatePending()
{
  // The facts are collected first and reported afterwards, so that a consumer is free
  // to act in ways that reach back into this observer without invalidating the walk.
  std::vector<ndn::Name> reachable;
  std::vector<std::pair<ndn::Name, bool>> settled;

  for (auto it = m_pending.begin(); it != m_pending.end(); ) {
    const ndn::Name& router = it->first;

    if (!it->second.reachableReported && hasReciprocalAdjacency(router)) {
      it->second.reachableReported = true;
      reachable.push_back(router);
    }

    if (areAllReciprocal(router, it->second.added)) {
      settled.emplace_back(router, !it->second.added.empty());
      it = m_pending.erase(it);
    }
    else {
      ++it;
    }
  }

  for (const auto& router : reachable) {
    NLSR_LOG_DEBUG("Router " << router << " is reachable through a reciprocal adjacency");
    originReachable(router);
  }
  for (const auto& [router, hasAdded] : settled) {
    if (hasAdded) {
      NLSR_LOG_DEBUG("Every adjacency added by " << router
                     << " is reciprocal (new-path candidate)");
    }
    else {
      NLSR_LOG_DEBUG("Adjacency removals by " << router
                     << " are reflected (removal-only; not a new-path candidate)");
    }
    originSettled(router, hasAdded);
  }
}

} // namespace nlsr
