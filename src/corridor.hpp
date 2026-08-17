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

#ifndef NLSR_CORRIDOR_HPP
#define NLSR_CORRIDOR_HPP

#include "conf-parameter.hpp"
#include "lsdb.hpp"
#include "test-access-control.hpp"

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/mgmt/nfd/control-parameters.hpp>
#include <ndn-cxx/mgmt/nfd/controller.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/util/notification-subscriber.hpp>
#include <ndn-cxx/util/signal.hpp>

#include <map>
#include <optional>
#include <set>

namespace nlsr {

/*! \brief One-hop hint that an ordinary LSA is available on an upstream face.
 *
 *  Availability is not routing truth. Only a later validated ordinary LSA install is.
 */
struct CorridorAvailability
{
  Lsa::Type type = Lsa::Type::BASE;
  uint64_t seq = 0;
  ndn::Name origin;
  ndn::Name prefix;
};

/*! \brief Prioritised propagation of ordinary verified LSAs along service-relevant faces.
 *
 *  Not a routing controller. Does not create a corridor LSDB, sequence namespace,
 *  or mobility generation.
 */
class Corridor
{
public:
  static ndn::Name
  makePrefix(const ndn::Name& network);

  static ndn::Name
  encodeAvailabilityName(const ndn::Name& network, Lsa::Type type, uint64_t seq,
                         const ndn::Name& origin, const ndn::Name& prefix);

  static std::optional<CorridorAvailability>
  parseAvailabilityName(const ndn::Name& name);

  Corridor(ndn::Face& face, ndn::KeyChain& keyChain, ConfParameter& confParam, Lsdb& lsdb);

  /*! \brief Register the local corridor filter and subscribe to ServiceBranch events.
   *
   *  Call only when corridor-prioritised-routing is on.
   */
  void
  start();

  void
  onFaceDestroyed(uint64_t faceId);

public:
  static constexpr ndn::time::milliseconds AVAILABILITY_LIFETIME = 1_s;

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  void
  onLsdbModified(const std::shared_ptr<Lsa>& lsa, LsdbUpdate updateType,
                 const std::list<ndn::Name>& namesToAdd,
                 const std::list<ndn::Name>& namesToRemove);

  void
  processAvailabilityInterest(const ndn::Interest& interest);

  void
  noteServiceBranch(const ndn::Name& prefix, uint64_t faceId);

  /*! \brief Replace the cached ServiceBranch face set for \p prefix.
   *
   *  Empty \p faces erases the prefix. Used by a successful exact query.
   *  A failed query must not call this.
   */
  void
  replaceServiceBranchSnapshot(const ndn::Name& prefix, const std::set<uint64_t>& faces);

  std::set<uint64_t>
  getBranchFaces(const ndn::Name& prefix) const;

  bool
  hasCachedServiceBranch(const ndn::Name& prefix) const;

  void
  queryServiceBranches(const ndn::Name& prefix);

  void
  maybeAdvertiseServiceAttachment();

  uint64_t
  getAdvertisedSeq(const ndn::Name& origin, Lsa::Type type, const ndn::Name& prefix) const;

  size_t
  countAdvertisedFaces(const ndn::Name& origin, Lsa::Type type, const ndn::Name& prefix) const;

  bool
  hasAdvertisedFace(const ndn::Name& origin, Lsa::Type type, const ndn::Name& prefix,
                    uint64_t faceId) const;

private:
  struct AdvertisementKey
  {
    ndn::Name origin;
    Lsa::Type type;
    ndn::Name prefix;

    bool
    operator<(const AdvertisementKey& other) const
    {
      if (origin != other.origin) {
        return origin < other.origin;
      }
      if (type != other.type) {
        return static_cast<int>(type) < static_cast<int>(other.type);
      }
      return prefix < other.prefix;
    }
  };

  struct AdvertisementState
  {
    uint64_t seq = 0;
    std::set<uint64_t> advertisedFaces;
  };

  void
  advertiseOwnAdjFirstHop();

  void
  propagateIfAssociated(const Lsa& lsa);

  void
  advertise(const ndn::Name& origin, Lsa::Type type, uint64_t seq, const ndn::Name& prefix,
            const std::set<uint64_t>& faces);

  void
  sendAvailability(const ndn::Name& origin, Lsa::Type type, uint64_t seq,
                   const ndn::Name& prefix, uint64_t faceId);

  void
  replyAvailability(const ndn::Interest& interest);

  void
  queryAllServiceBranches();

  void
  advertiseAssociated(const ndn::Name& prefix);

  std::set<uint64_t>
  getActiveAdjacencyFaces() const;

  AdvertisementState*
  findState(const ndn::Name& origin, Lsa::Type type, const ndn::Name& prefix);

  const AdvertisementState*
  findState(const ndn::Name& origin, Lsa::Type type, const ndn::Name& prefix) const;

  void
  recordAssociation(const ndn::Name& origin, Lsa::Type type, uint64_t seq, const ndn::Name& prefix);

private:
  ndn::Face& m_face;
  ndn::KeyChain& m_keyChain;
  ConfParameter& m_confParam;
  Lsdb& m_lsdb;
  ndn::nfd::Controller m_controller;
  ndn::util::NotificationSubscriber<ndn::nfd::ControlParameters> m_branchEvents;
  ndn::signal::ScopedConnection m_lsdbConnection;
  ndn::signal::ScopedConnection m_branchNotificationConnection;
  std::map<AdvertisementKey, AdvertisementState> m_state;
  std::map<ndn::Name, std::set<uint64_t>> m_branches;
};

} // namespace nlsr

#endif // NLSR_CORRIDOR_HPP
