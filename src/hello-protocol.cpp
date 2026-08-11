/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2014-2026,  The University of Memphis,
 *                           Regents of the University of California
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

#include "hello-protocol.hpp"
#include "nlsr.hpp"
#include "lsdb.hpp"
#include "logger.hpp"
#include "utility/name-helper.hpp"

#include <ndn-cxx/encoding/nfd-constants.hpp>

#include <vector>

namespace nlsr {

INIT_LOGGER(HelloProtocol);

HelloProtocol::HelloProtocol(ndn::Face& face, ndn::KeyChain& keyChain,
                             ConfParameter& confParam, RoutingTable& routingTable,
                             Lsdb& lsdb)
  : m_face(face)
  , m_scheduler(m_face.getIoContext())
  , m_keyChain(keyChain)
  , m_signingInfo(confParam.getSigningInfo())
  , m_confParam(confParam)
  , m_routingTable(routingTable)
  , m_lsdb(lsdb)
  , m_adjacencyList(m_confParam.getAdjacencyList())
{
  ndn::Name name(m_confParam.getRouterPrefix());
  name.append(NLSR_COMPONENT);
  name.append(INFO_COMPONENT);

  NLSR_LOG_DEBUG("Setting interest filter for Hello interest: " << name);

  m_face.setInterestFilter(ndn::InterestFilter(name).allowLoopback(false),
    [this] (const auto& name, const auto& interest) {
      processInterest(name, interest);
    },
    [] (const auto& name) {
      NLSR_LOG_DEBUG("Successfully registered prefix: " << name);
    },
    [] (const auto& name, const auto& resp) {
      NLSR_LOG_ERROR("Failed to register prefix " << name);
      NDN_THROW(std::runtime_error("Failed to register hello prefix: " + resp));
    },
    m_signingInfo, ndn::nfd::ROUTE_FLAG_CAPTURE);
}

ndn::Name
HelloProtocol::makeHelloInterestName(const ndn::Name& neighbour) const
{
  // interest name: /<neighbor>/NLSR/INFO/<router>
  ndn::Name interestName(neighbour);
  interestName.append(NLSR_COMPONENT);
  interestName.append(INFO_COMPONENT);
  interestName.append(ndn::tlv::GenericNameComponent, m_confParam.getRouterPrefix().wireEncode());
  return interestName;
}

void
HelloProtocol::expressInterest(const ndn::Name& interestName, uint32_t seconds, uint64_t flowId)
{
  NLSR_LOG_DEBUG("Expressing Interest: " << interestName << " (flow " << flowId << ")");
  ndn::Interest interest(interestName);
  interest.setInterestLifetime(ndn::time::seconds(seconds));
  interest.setMustBeFresh(true);
  interest.setCanBePrefix(true);
  m_face.expressInterest(interest,
    [this, flowId] (const auto& interest, const auto& data) {
      onContent(interest, data, flowId);
    },
    [this, seconds, flowId] (const auto& interest, const auto& nack) {
      NDN_LOG_TRACE("Received Nack with reason: " << nack.getReason());
      NDN_LOG_TRACE("Will treat as timeout in " << 2 * seconds << " seconds");
      m_scheduler.schedule(ndn::time::seconds(2 * seconds),
        [this, interest, flowId] { processInterestTimedOut(interest, flowId); });
    },
    [this, flowId] (const auto& interest) {
      processInterestTimedOut(interest, flowId);
    });

  // increment SENT_HELLO_INTEREST
  hpIncrementSignal(Statistics::PacketType::SENT_HELLO_INTEREST);
}

void
HelloProtocol::sendHelloInterest(const ndn::Name& neighbor)
{
  auto adjacent = m_adjacencyList.findAdjacent(neighbor);
  if (adjacent == m_adjacencyList.end()) {
    return;
  }

  // If this adjacency has a Face, just proceed as usual.
  if(adjacent->getFaceId() != 0) {
    auto interestName = makeHelloInterestName(adjacent->getName());
    expressInterest(interestName, m_confParam.getInterestResendTime(), ++m_lastFlowId);
    NLSR_LOG_DEBUG("Sending HELLO interest: " << interestName);
  }

  m_scheduler.schedule(ndn::time::seconds(m_confParam.getInfoInterestInterval()),
                       [this, neighbor] { sendHelloInterest(neighbor); });
}

void
HelloProtocol::expressHelloOnce(const ndn::Name& neighbour, uint64_t generation)
{
  auto adjacent = m_adjacencyList.findAdjacent(neighbour);
  if (adjacent == m_adjacencyList.end() || adjacent->getFaceId() == 0) {
    return;
  }

  uint64_t flowId = ++m_lastFlowId;
  if (generation != 0) {
    m_authoritativeFlows[neighbour] = VerificationFlow{flowId, generation};
    // Entering accelerated authority starts a clean retry budget for this verification.
    m_adjacencyList.setTimedOutInterestCount(neighbour, 0);
    NLSR_LOG_DEBUG("Flow " << flowId << " verifies " << neighbour
                   << " for generation=" << generation);
  }

  expressInterest(makeHelloInterestName(neighbour), m_confParam.getInterestResendTime(), flowId);
}

bool
HelloProtocol::canMutateAdjacency(const ndn::Name& neighbour, uint64_t flowId) const
{
  auto authIt = m_authoritativeFlows.find(neighbour);
  if (authIt != m_authoritativeFlows.end()) {
    return authIt->second.flowId == flowId;
  }

  auto retireIt = m_retireWatermark.find(neighbour);
  if (retireIt != m_retireWatermark.end() && flowId <= retireIt->second) {
    return false;
  }

  return true;
}

void
HelloProtocol::endAuthoritativeOwnership(const ndn::Name& neighbour, uint64_t flowId)
{
  auto it = m_authoritativeFlows.find(neighbour);
  if (it == m_authoritativeFlows.end() || it->second.flowId != flowId) {
    return;
  }

  m_authoritativeFlows.erase(it);
  // Cover the whole overlap window, including vanilla flows issued during authority
  // with flowIds greater than the authoritative flowId.
  m_retireWatermark[neighbour] = m_lastFlowId;
  NLSR_LOG_DEBUG("Retired Hello flows for " << neighbour
                 << " through flow " << m_lastFlowId);
}

void
HelloProtocol::reportVerificationResult(const ndn::Name& neighbour, uint64_t flowId,
                                        bool isReachable)
{
  auto it = m_authoritativeFlows.find(neighbour);
  if (it == m_authoritativeFlows.end() || it->second.flowId != flowId) {
    return;
  }

  uint64_t generation = it->second.generation;
  endAuthoritativeOwnership(neighbour, flowId);

  NLSR_LOG_DEBUG("Flow " << flowId << " found " << neighbour << " "
                 << (isReachable ? "reachable" : "unreachable")
                 << " for generation=" << generation);

  if (m_transitionController != nullptr) {
    m_transitionController->recordResult(generation, neighbour, isReachable);
  }
}

void
HelloProtocol::abortAcceleratedTransition(uint64_t generation)
{
  std::vector<ndn::Name> toRevoke;
  for (const auto& [neighbour, flow] : m_authoritativeFlows) {
    if (flow.generation == generation) {
      toRevoke.push_back(neighbour);
    }
  }

  for (const auto& neighbour : toRevoke) {
    auto it = m_authoritativeFlows.find(neighbour);
    if (it == m_authoritativeFlows.end()) {
      continue;
    }
    NLSR_LOG_DEBUG("Revoking authoritative flow " << it->second.flowId
                   << " for " << neighbour << " on abort of generation=" << generation);
    m_authoritativeFlows.erase(it);
    m_retireWatermark[neighbour] = m_lastFlowId;
    // Indeterminate / abort handback: return a clean counter to vanilla Hello.
    m_adjacencyList.setTimedOutInterestCount(neighbour, 0);
  }

  if (m_transitionController != nullptr) {
    m_transitionController->abort(generation);
  }
}

void
HelloProtocol::processInterest(const ndn::Name& name,
                               const ndn::Interest& interest)
{
  // interest name: /<neighbor>/NLSR/INFO/<router>
  const ndn::Name interestName = interest.getName();

  // increment RCV_HELLO_INTEREST
  hpIncrementSignal(Statistics::PacketType::RCV_HELLO_INTEREST);

  NLSR_LOG_DEBUG("Interest received for Name: " << interestName);
  if (interestName.get(-2).toUri() != INFO_COMPONENT) {
    NLSR_LOG_DEBUG("INFO_COMPONENT not found or Interest Name " << interestName
                   << " does not match expression");
    return;
  }

  ndn::Name neighbor(interestName.get(-1).blockFromValue());
  NLSR_LOG_DEBUG("Neighbor: " << neighbor);
  if (m_adjacencyList.isNeighbor(neighbor)) {
    auto data = std::make_shared<ndn::Data>();
    data->setName(ndn::Name(interest.getName()).appendVersion());
    // A Hello reply being cached longer than is needed to fufill an Interest
    // can cause counterintuitive behavior. Consequently, we use the default
    // minimum of 0 ms.
    data->setFreshnessPeriod(0_ms);
    data->setContent(ndn::make_span(reinterpret_cast<const uint8_t*>(INFO_COMPONENT.data()),
                                    INFO_COMPONENT.size()));

    m_keyChain.sign(*data, m_signingInfo);

    NLSR_LOG_DEBUG("Sending out data for name: " << interest.getName());
    m_face.put(*data);
    // increment SENT_HELLO_DATA
    hpIncrementSignal(Statistics::PacketType::SENT_HELLO_DATA);

    auto adjacent = m_adjacencyList.findAdjacent(neighbor);
    // If this neighbor was previously inactive, send our own hello interest, too.
    // We can only do that if the neighbor currently has a face.
    if (adjacent->getStatus() == Adjacent::STATUS_INACTIVE && adjacent->getFaceId() != 0) {
      // The Interest arrived in a configured neighbour's namespace, but only the Hello
      // Data this router fetches itself is validated. It is therefore a reachability
      // hint: it says a verification is worth running now, not that the neighbour is
      // reachable. The probe that would be sent here anyway carries out that
      // verification, so opening a transition adds no second Hello flow.
      uint64_t generation = 0;
      if (m_transitionController != nullptr &&
          m_confParam.getEventDrivenAdjacencyVerification()) {
        const bool holdPublicationAuthority = m_confParam.getResultDrivenAdjLsaBuild();
        generation = m_transitionController->beginTransition(neighbor, holdPublicationAuthority);
        if (m_transitionController->holdsPublicationAuthority()) {
          m_lsdb.setOrdinaryAdjLsaPublishSuppressed(true);
        }
      }
      expressHelloOnce(neighbor, generation);
    }
  }
}

void
HelloProtocol::processInterestTimedOut(const ndn::Interest& interest, uint64_t flowId)
{
  // interest name: /<neighbor>/NLSR/INFO/<router>
  const ndn::Name interestName(interest.getName());
  NLSR_LOG_DEBUG("Interest timed out for Name: " << interestName);
  if (interestName.get(-2).toUri() != INFO_COMPONENT) {
    return;
  }
  ndn::Name neighbor = interestName.getPrefix(-3);
  NLSR_LOG_DEBUG("Neighbor: " << neighbor);

  if (!canMutateAdjacency(neighbor, flowId)) {
    NLSR_LOG_DEBUG("Flow " << flowId << " is stale for " << neighbor
                   << "; its timeout neither counts nor retries");
    return;
  }

  m_adjacencyList.incrementTimedOutInterestCount(neighbor);

  Adjacent::Status status = m_adjacencyList.getStatusOfNeighbor(neighbor);

  uint32_t infoIntTimedOutCount = m_adjacencyList.getTimedOutInterestCount(neighbor);
  NLSR_LOG_DEBUG("Status: " << status);
  NLSR_LOG_DEBUG("Info Interest Timed out: " << infoIntTimedOutCount);
  if (infoIntTimedOutCount < m_confParam.getInterestRetryNumber()) {
    // The retry asks the same question about the same adjacency, so it continues the
    // same flow.
    auto retryName = makeHelloInterestName(neighbor);
    NLSR_LOG_DEBUG("Resending interest: " << retryName);
    expressInterest(retryName, m_confParam.getInterestResendTime(), flowId);
    return;
  }

  if (status == Adjacent::STATUS_ACTIVE) {
    m_adjacencyList.setStatusOfNeighbor(neighbor, Adjacent::STATUS_INACTIVE);

    NLSR_LOG_DEBUG("Neighbor: " << neighbor << " status changed to INACTIVE");

    if (m_confParam.getHyperbolicState() == HYPERBOLIC_STATE_ON) {
      m_routingTable.scheduleRoutingTableCalculation();
    }
    else {
      m_lsdb.scheduleAdjLsaBuild();
    }
  }

  // The retries are exhausted, so the adjacency is decided whether or not its status
  // changed here.
  reportVerificationResult(neighbor, flowId, false);
}

// This is the first function that incoming Hello data will
// see. This checks if the data appears to be signed, and passes it
// on to validate the content of the data.
void
HelloProtocol::onContent(const ndn::Interest& interest, const ndn::Data& data, uint64_t flowId)
{
  NLSR_LOG_DEBUG("Received data for INFO(name): " << data.getName());
  auto kl = data.getKeyLocator();
  if (kl && kl->getType() == ndn::tlv::Name) {
    NLSR_LOG_DEBUG("Data signed with: " << kl->getName());
  }
  m_confParam.getValidator().validate(data,
                                      [this, flowId] (const auto& validatedData) {
                                        onContentValidated(validatedData, flowId);
                                      },
                                      [this, flowId] (const auto& rejectedData, const auto& ve) {
                                        onContentValidationFailed(rejectedData, ve, flowId);
                                      });
}

void
HelloProtocol::onContentValidated(const ndn::Data& data, uint64_t flowId)
{
  // data name: /<neighbor>/NLSR/INFO/<router>/<version>
  ndn::Name dataName = data.getName();
  NLSR_LOG_DEBUG("Data validation successful for INFO(name): " << dataName);

  if (dataName.get(-3).toUri() == INFO_COMPONENT) {
    ndn::Name neighbor = dataName.getPrefix(-4);

    if (!canMutateAdjacency(neighbor, flowId)) {
      NLSR_LOG_DEBUG("Flow " << flowId << " is stale for " << neighbor
                     << "; leaving its status to a live flow");
    }
    else {
      Adjacent::Status oldStatus = m_adjacencyList.getStatusOfNeighbor(neighbor);
      m_adjacencyList.setStatusOfNeighbor(neighbor, Adjacent::STATUS_ACTIVE);
      m_adjacencyList.setTimedOutInterestCount(neighbor, 0);
      Adjacent::Status newStatus = m_adjacencyList.getStatusOfNeighbor(neighbor);

      NLSR_LOG_DEBUG("Neighbor: " << neighbor);
      NLSR_LOG_DEBUG("Old Status: " << oldStatus << ", New Status: " << newStatus);
      // change in Adjacency list
      if ((oldStatus - newStatus) != 0) {
        if (m_confParam.getHyperbolicState() == HYPERBOLIC_STATE_ON) {
          m_routingTable.scheduleRoutingTableCalculation();
        }
        else {
          m_lsdb.scheduleAdjLsaBuild();
        }
        onInitialHelloDataValidated(neighbor);
      }

      // Validated Hello Data settles the adjacency whether or not the status changed, so
      // a verification that confirms an already ACTIVE neighbour completes here as well.
      reportVerificationResult(neighbor, flowId, true);
    }
  }
  // increment RCV_HELLO_DATA
  hpIncrementSignal(Statistics::PacketType::RCV_HELLO_DATA);
}

void
HelloProtocol::onContentValidationFailed(const ndn::Data& data,
                                         const ndn::security::ValidationError& ve,
                                         uint64_t flowId)
{
  NLSR_LOG_DEBUG("Validation error: " << ve);

  // data name: /<neighbor>/NLSR/INFO/<router>/<version>
  const ndn::Name& dataName = data.getName();
  if (dataName.size() < 4 || dataName.get(-3).toUri() != INFO_COMPONENT) {
    return;
  }

  ndn::Name neighbor = dataName.getPrefix(-4);
  auto it = m_authoritativeFlows.find(neighbor);
  if (it == m_authoritativeFlows.end()) {
    // Vanilla Hello: validation failure leaves adjacency untouched and does not abort.
    return;
  }
  if (it->second.flowId != flowId) {
    NLSR_LOG_DEBUG("Ignoring validation failure from stale flow " << flowId
                   << " for " << neighbor);
    return;
  }

  // Indeterminate: do not recordResult as unreachable; abort the whole generation.
  NLSR_LOG_DEBUG("Authoritative validation failure for " << neighbor
                 << "; aborting generation=" << it->second.generation);
  abortAcceleratedTransition(it->second.generation);
}

} // namespace nlsr
