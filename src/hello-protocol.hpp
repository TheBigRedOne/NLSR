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
 * PURPOSE.  See the GNU Lesser General Public License for more details.
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

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/validation-error.hpp>
#include <ndn-cxx/util/scheduler.hpp>
#include <ndn-cxx/util/signal.hpp>

#include <map>
#include <optional>
#include <set>

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
   * \param isReciprocal true when this Interest (and its retries) was started by
   * an incoming Hello Interest on a configured INACTIVE neighbour. The flag is
   * fixed for the lifetime of the physical Hello flow and is used only to decide
   * whether a validated success may request an immediate Adj-LSA build.
   */
  void
  expressInterest(const ndn::Name& interestNamePrefix, uint32_t seconds,
                  bool isReciprocal = false);

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

  /*! \brief Processes a Hello Interest from a neighbor.
   */
  void
  processInterest(const ndn::Name& name, const ndn::Interest& interest);

  /*! \brief Local attachment-change hint: start/restart a mobility verification sweep.
   *
   *  No-op when event-driven-adjacency-verification is off. Does not mutate
   *  adjacency status or LSDB by itself.
   */
  void
  onAttachmentChangeHint();

  /*! \brief Face destroy for a configured neighbour while a sweep may be active.
   *
   *  Vanilla INACTIVE / dirty bookkeeping is performed by the caller. When the
   *  neighbour is a current sweep target, records UNREACHABLE for that target.
   */
  void
  onAdjacentFaceDestroyed(const ndn::Name& neighbor);

  ndn::signal::Signal<HelloProtocol, Statistics::PacketType> hpIncrementSignal;

private:
  void
  onContent(const ndn::Interest& interest, const ndn::Data& data, bool isReciprocal,
            uint64_t flowToken);

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  enum class VerifyResult {
    REACHABLE,
    UNREACHABLE,
    INDETERMINATE,
  };

  struct AdjHelloControl
  {
    ndn::scheduler::ScopedEventId periodicEvent;
    ndn::ScopedPendingInterestHandle pendingInterest;
    ndn::scheduler::ScopedEventId nackDelayEvent;
    uint64_t flowToken = 0;
  };

  struct MobilitySweep
  {
    uint64_t serial = 0;
    std::set<ndn::Name> targets;
    std::map<ndn::Name, VerifyResult> results;
  };

  void
  onContentValidated(const ndn::Data& data, bool isReciprocal = false, uint64_t flowToken = 0);

  void
  processInterestTimedOut(const ndn::Interest& interest, bool isReciprocal, uint64_t flowToken);

  /*! \brief Owned-path NACK handler: token-gates before scheduling delayed timeout.
   *
   *  Exposed for tests that simulate a late NACK after async PendingInterest cancel.
   */
  void
  onNackOwned(const ndn::Name& neighbor, const ndn::Interest& interest,
              uint32_t seconds, bool isReciprocal, uint64_t flowToken);

  std::map<ndn::Name, AdjHelloControl> m_adjHello;
  std::optional<MobilitySweep> m_sweep;

private:
  void
  onContentValidationFailed(const ndn::Data& data, const ndn::security::ValidationError& ve,
                            uint64_t flowToken);

  ndn::Name
  makeHelloInterestName(const ndn::Name& neighbour) const;

  bool
  isEventDrivenOn() const
  {
    return m_confParam.getEventDrivenAdjacencyVerification();
  }

  AdjHelloControl&
  getAdjControl(const ndn::Name& neighbor);

  void
  expressInterestVanilla(const ndn::Name& interestName, uint32_t seconds, bool isReciprocal);

  void
  expressInterestOwned(const ndn::Name& neighbor, const ndn::Name& interestName,
                       uint32_t seconds, bool isReciprocal, uint64_t flowToken);

  void
  sendHelloInterestVanilla(const ndn::Name& neighbor);

  void
  sendHelloInterestOwned(const ndn::Name& neighbor);

  void
  requestVerificationNow(const ndn::Name& neighbor);

  void
  beginMobilitySweep();

  void
  abortMobilitySweep(const std::string& reason);

  void
  noteSweepResult(const ndn::Name& neighbor, VerifyResult result);

  void
  checkSweepCompletion();

  std::set<ndn::Name>
  buildSweepTargets() const;

  ndn::Name
  neighborFromHelloInterest(const ndn::Interest& interest) const;

public:
  static inline const std::string INFO_COMPONENT{"INFO"};
  static inline const std::string NLSR_COMPONENT{"nlsr"};
  static inline const ndn::Name VERIFY_NOW_PREFIX{"/localhost/nlsr/optoflood/verify-now"};

  ndn::signal::Signal<HelloProtocol, const ndn::Name&> onInitialHelloDataValidated;

private:
  ndn::Face& m_face;
  ndn::Scheduler m_scheduler;
  ndn::security::KeyChain& m_keyChain;
  const ndn::security::SigningInfo& m_signingInfo;
  ConfParameter& m_confParam;
  RoutingTable& m_routingTable;
  Lsdb& m_lsdb;
  AdjacencyList& m_adjacencyList;

  uint64_t m_nextSweepSerial = 1;
};

} // namespace nlsr

#endif // NLSR_HELLO_PROTOCOL_HPP
