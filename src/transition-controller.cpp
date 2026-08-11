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

#include "transition-controller.hpp"
#include "logger.hpp"

namespace nlsr {

INIT_LOGGER(TransitionController);

uint64_t
TransitionController::beginTransition(const ndn::Name& neighbour, bool holdPublicationAuthority)
{
  // Join while facts remain unresolved OR publication authority is still held (including
  // the window after pending cleared but before success completion releases authority).
  const bool joinExisting = !m_pending.empty() || m_holdsPublicationAuthority;
  if (joinExisting) {
    ++m_completionSerial;
    NLSR_LOG_DEBUG("Adding " << neighbour << " to transition generation=" << m_generation
                   << " (completionSerial=" << m_completionSerial << ")");
  }
  else {
    ++m_generation;
    m_affected.clear();
    m_completionSerial = 0;
    NLSR_LOG_DEBUG("Opening transition generation=" << m_generation << " on " << neighbour);
  }

  if (holdPublicationAuthority) {
    m_holdsPublicationAuthority = true;
  }

  m_affected.insert(neighbour);
  m_pending.insert(neighbour);
  return m_generation;
}

void
TransitionController::recordResult(uint64_t generation, const ndn::Name& neighbour,
                                   bool isReachable)
{
  if (generation != m_generation) {
    NLSR_LOG_DEBUG("Discarding outcome for " << neighbour << " of superseded generation="
                   << generation);
    return;
  }

  if (m_pending.erase(neighbour) == 0) {
    NLSR_LOG_DEBUG("Outcome for " << neighbour << " is not an unresolved fact of generation="
                   << generation);
    return;
  }

  NLSR_LOG_DEBUG("Generation=" << generation << ": " << neighbour << " resolved as "
                 << (isReachable ? "reachable" : "unreachable") << ", "
                 << m_pending.size() << " fact(s) unresolved");

  if (m_pending.empty()) {
    NLSR_LOG_DEBUG("Generation=" << generation << " resolved over "
                   << m_affected.size() << " adjacency(ies); success completion may run");
    onTransitionResolved(generation);
  }
}

void
TransitionController::abort(uint64_t generation)
{
  if (generation != m_generation) {
    NLSR_LOG_DEBUG("Ignoring abort for superseded generation=" << generation);
    return;
  }

  NLSR_LOG_DEBUG("Aborting transition generation=" << generation << " with "
                 << m_pending.size() << " unresolved fact(s)");
  m_pending.clear();
  m_affected.clear();
  ++m_completionSerial;
  m_holdsPublicationAuthority = false;
  onTransitionAborted(generation);
}

bool
TransitionController::canCompleteSuccess(uint64_t generation) const
{
  return generation == m_generation
         && m_holdsPublicationAuthority
         && m_pending.empty();
}

void
TransitionController::releasePublicationAuthorityAfterSuccess(uint64_t generation)
{
  if (!canCompleteSuccess(generation)) {
    NLSR_LOG_DEBUG("Not releasing publication authority for generation=" << generation
                   << " (re-joined, aborted, or mismatched)");
    return;
  }

  NLSR_LOG_DEBUG("Releasing publication authority after success for generation="
                 << generation);
  m_holdsPublicationAuthority = false;
  m_affected.clear();
}

} // namespace nlsr
