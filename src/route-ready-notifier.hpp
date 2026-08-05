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

#ifndef NLSR_ROUTE_READY_NOTIFIER_HPP
#define NLSR_ROUTE_READY_NOTIFIER_HPP

#include "lsdb.hpp"
#include "test-access-control.hpp"

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/name.hpp>
#include <ndn-cxx/util/signal.hpp>

#include <map>
#include <set>

namespace nlsr {

/*! \brief Reports to the local forwarder that this router's LSDB has absorbed a
 *         topology change affecting the prefixes of a relocated router.
 *
 *  The notifier observes Adjacency LSA updates and retains, per origin router, the
 *  adjacency set most recently seen. When that set changes, the router is marked
 *  pending. Each subsequent LSA update re-evaluates whether a pending router
 *  declares at least one adjacency that the neighbour declares in return. A
 *  one-sided adjacency is not sufficient: the routing calculation discards any link
 *  that the two endpoints do not both report, so a router whose adjacencies are all
 *  one-sided is isolated in the local topology graph even though its LSA is present.
 *
 *  Re-evaluation is repeated rather than performed once when the adjacency set
 *  changes, because the router's own LSA and its new neighbour's LSA may arrive in
 *  either order; a single check would miss the case where the neighbour's LSA
 *  arrives last. It is also not driven by the readiness value alone, because a stale
 *  but internally consistent LSDB reports the relocated router as reachable through
 *  its former neighbour, so readiness need never change value across the event.
 *
 *  The announcement states a local fact only: this router now holds control-plane
 *  information sufficient for the relocated router to be reachable. It is not a
 *  claim that the network has converged, which no node in a link-state protocol can
 *  establish. It authorises the forwarder to release temporary forwarding state; it
 *  neither installs nor withdraws a route, and it never leaves the local host.
 *
 *  Known limitation: the announcement identifies a prefix but not the relocation it
 *  refers to. If a router relocates twice within one LSA propagation delay, an
 *  announcement derived from the earlier relocation can authorise release of state
 *  installed for the later one. The consequence is an early release, that is, the
 *  behaviour obtained without this notifier, not a new failure mode.
 */
class RouteReadyNotifier
{
public:
  /*!
   * \param face  face used to express the local announcement
   * \param lsdb  link-state database observed for adjacency changes
   */
  RouteReadyNotifier(ndn::Face& face, Lsdb& lsdb);

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  void
  onLsdbModified(const std::shared_ptr<Lsa>& lsa, LsdbUpdate updateType);

  /*! \brief Stores the adjacency set of \p lsa.
   *  \return true if it differs from the set previously recorded for its origin
   *          router, including the case where none was recorded.
   */
  bool
  recordAdjacencies(const AdjLsa& lsa);

  /*! \brief Whether \p router declares an adjacency whose neighbour declares
   *         \p router in return.
   */
  bool
  hasBidirectionalAdjacency(const ndn::Name& router) const;

  /*! \brief Announces every pending router that has become bidirectionally
   *         adjacent, and clears it.
   */
  void
  evaluatePending();

  /*! \brief Announces the prefixes originated by \p router to the local forwarder. */
  void
  announce(const ndn::Name& router);

private:
  ndn::Face& m_face;
  Lsdb& m_lsdb;

  /// Adjacency set most recently seen for each origin router.
  std::map<ndn::Name, std::set<ndn::Name>> m_adjacencies;
  /// Routers whose adjacency set changed and that are not yet bidirectionally adjacent.
  std::set<ndn::Name> m_pending;

  ndn::signal::ScopedConnection m_lsdbConnection;
};

} // namespace nlsr

#endif // NLSR_ROUTE_READY_NOTIFIER_HPP
