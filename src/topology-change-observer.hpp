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

#ifndef NLSR_TOPOLOGY_CHANGE_OBSERVER_HPP
#define NLSR_TOPOLOGY_CHANGE_OBSERVER_HPP

#include "lsdb.hpp"
#include "test-access-control.hpp"

#include <ndn-cxx/name.hpp>
#include <ndn-cxx/util/signal.hpp>

#include <map>
#include <set>

namespace nlsr {

/*! \brief Reports how far this router's own database has absorbed a change in some
 *         other router's adjacencies.
 *
 *  The observer keeps, per origin router, the adjacency set most recently seen. When
 *  that set changes it records the newly added adjacencies and then re-evaluates, on
 *  every subsequent LSA update, how much of the change the database can already
 *  account for. Two facts are reported, because they answer different questions and
 *  a consumer that needs one is harmed by waiting for the other.
 *
 *  An adjacency counts only when both endpoints declare it. The routing calculation
 *  discards links that the two endpoints do not both report, so a router whose
 *  adjacencies are all one-sided is isolated in the local topology graph even though
 *  its LSA is present.
 *
 *  Re-evaluation is repeated rather than performed once when the adjacency set
 *  changes, because a router's own LSA and its new neighbour's LSA may arrive in
 *  either order. It is also not driven by the reported facts changing value, because
 *  a stale but internally consistent database reports a relocated router as reachable
 *  through its former neighbour, so those facts may hold throughout the change.
 *
 *  The facts are local: they state what this router's database supports. No node in a
 *  link-state protocol can establish that the network has converged.
 */
class TopologyChangeObserver
{
public:
  explicit
  TopologyChangeObserver(Lsdb& lsdb);

public:
  /*! \brief The origin router declares an adjacency that the neighbour declares in
   *         return, so the routing calculation will find a path to it.
   *
   *  Sufficient for releasing forwarding state that exists to cover the change.
   */
  ndn::signal::Signal<TopologyChangeObserver, ndn::Name> originReachable;

  /*! \brief Every adjacency added by the change is declared by both endpoints, so a
   *         calculation run now yields the result the change leads to.
   *
   *  Stronger than originReachable, which one pre-existing adjacency can satisfy.
   */
  ndn::signal::Signal<TopologyChangeObserver, ndn::Name> originSettled;

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  void
  onLsdbModified(const std::shared_ptr<Lsa>& lsa, LsdbUpdate updateType);

  /*! \brief Stores the adjacency set of \p lsa and returns the adjacencies it gained.
   *  \param isChanged set to true when the set differs from the one previously
   *         recorded for this origin router, which includes losing adjacencies
   *         without gaining any.
   */
  std::set<ndn::Name>
  recordAdjacencies(const AdjLsa& lsa, bool& isChanged);

  /*! \brief Whether \p neighbour declares \p router in its own Adjacency LSA. */
  bool
  declaresBack(const ndn::Name& neighbour, const ndn::Name& router) const;

  /*! \brief Whether \p router declares any adjacency that is declared in return. */
  bool
  hasReciprocalAdjacency(const ndn::Name& router) const;

  /*! \brief Whether every adjacency in \p added is declared in return. */
  bool
  areAllReciprocal(const ndn::Name& router, const std::set<ndn::Name>& added) const;

  void
  evaluatePending();

private:
  struct PendingChange
  {
    std::set<ndn::Name> added;
    bool reachableReported = false;
  };

  Lsdb& m_lsdb;
  /// Adjacency set most recently seen for each origin router.
  std::map<ndn::Name, std::set<ndn::Name>> m_adjacencies;
  /// Routers whose adjacency set changed and whose change is not yet fully accounted for.
  std::map<ndn::Name, PendingChange> m_pending;

  ndn::signal::ScopedConnection m_lsdbConnection;
};

} // namespace nlsr

#endif // NLSR_TOPOLOGY_CHANGE_OBSERVER_HPP
