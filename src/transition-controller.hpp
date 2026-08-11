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

#ifndef NLSR_TRANSITION_CONTROLLER_HPP
#define NLSR_TRANSITION_CONTROLLER_HPP

#include "test-access-control.hpp"

#include <ndn-cxx/name.hpp>
#include <ndn-cxx/util/signal.hpp>

#include <cstdint>
#include <set>

namespace nlsr {

/*! \brief Groups adjacency facts for one topology change and owns result-driven
 *         Adj-LSA publication authority for that change.
 *
 *  Unresolved facts (`m_pending`) and publication authority are distinct: authority is
 *  acquired when a transition is opened with publication holding enabled, retained through
 *  successful completion handling, and released only after that handler finishes or after
 *  generation-wide abort cleanup. An empty pending set alone does not mean authority is
 *  free.
 *
 *  A hint that arrives while authority is held joins the same generation and re-opens the
 *  neighbour's pending fact, even if pending had already become empty for a success
 *  attempt. That invalidates the prior completion attempt via the completion serial.
 *
 *  REACHABLE / UNREACHABLE facts come only from authoritative Hello outcomes. Validation
 *  failure is not recorded here; the caller must abort the generation instead.
 */
class TransitionController
{
public:
  /*! \brief Opens a transition covering \p neighbour, or joins the one that still holds
   *         lifecycle ownership.
   *  \param neighbour adjacency whose fact is unresolved
   *  \param holdPublicationAuthority when true, the transition acquires (or keeps)
   *         Adj-LSA publication authority for result-driven builds
   *  \return the generation the verification of \p neighbour belongs to; never zero
   */
  uint64_t
  beginTransition(const ndn::Name& neighbour, bool holdPublicationAuthority);

  /*! \brief Records a REACHABLE or UNREACHABLE outcome for \p neighbour.
   *
   *  Ignored when \p generation is not current, or \p neighbour is not pending. When the
   *  last pending fact resolves, emits onTransitionResolved while publication authority
   *  is still held.
   */
  void
  recordResult(uint64_t generation, const ndn::Name& neighbour, bool isReachable);

  /*! \brief Generation-wide abort: clears facts and releases publication authority.
   *
   *  The caller must first revoke every authoritative Hello flow of this generation.
   *  Emits onTransitionAborted when \p generation is current.
   */
  void
  abort(uint64_t generation);

  uint64_t
  getGeneration() const
  {
    return m_generation;
  }

  /*! \brief Whether any adjacency fact is still unresolved. */
  bool
  hasUnresolvedFacts() const
  {
    return !m_pending.empty();
  }

  bool
  holdsPublicationAuthority() const
  {
    return m_holdsPublicationAuthority;
  }

  uint64_t
  getCompletionSerial() const
  {
    return m_completionSerial;
  }

  /*! \brief Whether \p generation may run result-driven success completion now. */
  bool
  canCompleteSuccess(uint64_t generation) const;

  /*! \brief Releases publication authority after a validated success completion.
   *
   *  No-op when the generation no longer owns authority (re-join, abort, or mismatch).
   */
  void
  releasePublicationAuthorityAfterSuccess(uint64_t generation);

  /*! \brief Every REACHABLE/UNREACHABLE fact of the generation has been resolved.
   *  \note Argument is the generation. Authority is still held until success handling ends.
   */
  ndn::signal::Signal<TransitionController, uint64_t> onTransitionResolved;

  /*! \brief The generation was aborted; publication authority is already released. */
  ndn::signal::Signal<TransitionController, uint64_t> onTransitionAborted;

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  uint64_t m_generation = 0;
  uint64_t m_completionSerial = 0;
  bool m_holdsPublicationAuthority = false;
  /// Neighbours covered by the open transition, whether or not their fact is resolved.
  std::set<ndn::Name> m_affected;
  /// Neighbours of the open transition whose state is not yet resolved.
  std::set<ndn::Name> m_pending;
};

} // namespace nlsr

#endif // NLSR_TRANSITION_CONTROLLER_HPP
