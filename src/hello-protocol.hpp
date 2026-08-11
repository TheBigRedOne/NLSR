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

#ifndef NLSR_HELLO_PROTOCOL_HPP
#define NLSR_HELLO_PROTOCOL_HPP

#include "conf-parameter.hpp"
#include "lsdb.hpp"
#include "route/routing-table.hpp"
#include "statistics.hpp"
#include "test-access-control.hpp"
#include "transition-controller.hpp"

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/validation-error.hpp>
#include <ndn-cxx/util/scheduler.hpp>
#include <ndn-cxx/util/signal.hpp>

#include <map>

namespace nlsr {

class HelloProtocol
{
public:
  HelloProtocol(ndn::Face& face, ndn::KeyChain& keyChain, ConfParameter& confParam,
                RoutingTable& routingTable, Lsdb& lsdb);

  /*! \brief Sends a Hello Interest packet.
   *
   * \param interestNamePrefix The name of the router that has published the
   * update we want. Here that should be: \<router name\>/NLSR/INFO
   *
   * \param seconds The lifetime of the Interest we construct, in seconds
   *
   * \param flowId identifies the Hello flow this Interest and its retries belong to.
   * It is carried into every callback, so that an outcome can be attributed to the flow
   * that asked for it. Zero means an unattributed flow.
   *
   * This function attempts to contact neighboring routers to
   * determine their status (which currently is one of: ACTIVE,
   * INACTIVE, or UNKNOWN)
   */
  void
  expressInterest(const ndn::Name& interestNamePrefix, uint32_t seconds, uint64_t flowId = 0);

  /*! \brief Sends Hello Interests to all neighbors
   *
   * This function is called as part of a schedule to regularly
   * determine the adjacency status of neighbors. This function
   * creates and sends a Hello Interest to the given adjacent.
   *
   * \param neighbor the name of the neighbor
   */
  void
  sendHelloInterest(const ndn::Name& neighbor);

  /*! \brief Expresses a single Hello Interest to \p neighbour, without arming the
   *         periodic round for it.
   *
   * \param neighbour the name of the neighbor
   * \param generation the transition whose verification of \p neighbour this flow
   * carries out, or zero to express a Hello that claims no such role
   *
   * With a non-zero \p generation the flow becomes the authoritative one for the
   * adjacency: it alone may update the retry count and ACTIVE/INACTIVE decision until
   * it ends, and the per-adjacency timeout counter is reset so the verification starts
   * with a clean retry budget. Does nothing when the neighbour has no Face.
   */
  void
  expressHelloOnce(const ndn::Name& neighbour, uint64_t generation);

  /*! \brief Installs the controller that groups adjacency verifications into transitions.
   *
   * Passing nullptr, or leaving it uninstalled, leaves every Hello flow with the
   * unmodified behaviour.
   */
  void
  setTransitionController(TransitionController* controller)
  {
    m_transitionController = controller;
  }

  /*! \brief Processes a Hello Interest from a neighbor.
   *
   * \param name (ignored)
   *
   * \param interest The Interest object that we have received and need to
   * process.
   *
   * Processes a Hello Interest that this router receives from one of
   * its neighbors. If the neighbor that sent the Interest does not
   * have a Face, NLSR will attempt to create one. Also, if the
   * neighbor that sent the Interest was previously marked as
   * INACTIVE, NLSR will attempt to contact it with its own Hello
   * Interest.
   */
  void
  processInterest(const ndn::Name& name, const ndn::Interest& interest);

  ndn::signal::Signal<HelloProtocol, Statistics::PacketType> hpIncrementSignal;

private:
  /*! \brief Try to contact a neighbor via Hello protocol again
   *
   * This function will re-send Hello Interests a configured number
   * of times. After that many failures, HelloProtocol will mark the neighbor as
   * inactive and will not attempt to contact them until the next time
   * HelloProtocol::sendScheduledInterest is called.
   *
   * \sa nlsr::ConfParameter::getInterestRetryNumber
   */
  void
  processInterestTimedOut(const ndn::Interest& interest, uint64_t flowId);

  /*! \brief Verify signatures and validate incoming Hello data.
   */
  void
  onContent(const ndn::Interest& interest, const ndn::Data& data, uint64_t flowId);

PUBLIC_WITH_TESTS_ELSE_PRIVATE:

  /*! \brief Change a neighbor's status
   *
   * Whenever incoming Hello data is verified and validated, change
   * the status of this neighbor and then schedule an adjacency LSA
   * build for us. This also resets the number of times we've failed
   * to contact this neighbor so that we will retry later.
   */
  void
  onContentValidated(const ndn::Data& data, uint64_t flowId = 0);

private:
  /*! \brief Log validation failure and abort the accelerated transition if this was an
   *         authoritative flow.
   *
   *  Leaves adjacency status untouched. Does not record UNREACHABLE: validation failure
   *  is indeterminate relative to native Hello semantics.
   */
  void
  onContentValidationFailed(const ndn::Data& data,
                            const ndn::security::ValidationError& ve,
                            uint64_t flowId);

  /*! \brief Builds the Hello Interest name for \p neighbour:
   *         /\<neighbour\>/NLSR/INFO/\<router\>
   */
  ndn::Name
  makeHelloInterestName(const ndn::Name& neighbour) const;

  /*! \brief Whether \p flowId may update retry accounting or ACTIVE/INACTIVE for
   *         \p neighbour.
   *
   *  While an authoritative flow is installed, only that flowId may mutate. After the
   *  authoritative overlap window ends, every flowId at or below the retire watermark is
   *  permanently stale, including overlapping vanilla flows issued during the window.
   */
  bool
  canMutateAdjacency(const ndn::Name& neighbour, uint64_t flowId) const;

  /*! \brief Ends authoritative ownership for \p neighbour and advances its retire watermark
   *         across the overlap window.
   */
  void
  endAuthoritativeOwnership(const ndn::Name& neighbour, uint64_t flowId);

  /*! \brief Reports a REACHABLE/UNREACHABLE outcome and ends authority for \p neighbour.
   */
  void
  reportVerificationResult(const ndn::Name& neighbour, uint64_t flowId, bool isReachable);

  /*! \brief Generation-wide abort: retire all authoritative flows of \p generation, hand
   *         back retry counters, then abort the transition controller.
   */
  void
  abortAcceleratedTransition(uint64_t generation);

public:
  static inline const std::string INFO_COMPONENT{"INFO"};
  static inline const std::string NLSR_COMPONENT{"nlsr"};

  ndn::signal::Signal<HelloProtocol, const ndn::Name&> onInitialHelloDataValidated;

private:
  /*! \brief The Hello flow that currently verifies one adjacency, and the transition it
   *         verifies it for.
   */
  struct VerificationFlow
  {
    uint64_t flowId;
    uint64_t generation;
  };

  ndn::Face& m_face;
  ndn::Scheduler m_scheduler;
  ndn::security::KeyChain& m_keyChain;
  const ndn::security::SigningInfo& m_signingInfo;
  ConfParameter& m_confParam;
  RoutingTable& m_routingTable;
  Lsdb& m_lsdb;
  AdjacencyList& m_adjacencyList;

  TransitionController* m_transitionController = nullptr;
  /*! \brief Authoritative verification flow per neighbour. */
  std::map<ndn::Name, VerificationFlow> m_authoritativeFlows;
  /*! \brief Per-neighbour retire watermark: flowId <= watermark cannot mutate after the
   *         authoritative overlap window for that neighbour has ended.
   */
  std::map<ndn::Name, uint64_t> m_retireWatermark;
  uint64_t m_lastFlowId = 0;
};

} // namespace nlsr

#endif // NLSR_HELLO_PROTOCOL_HPP
