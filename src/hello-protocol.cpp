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
HelloProtocol::expressInterest(const ndn::Name& interestName, uint32_t seconds,
                               bool isReciprocal)
{
  NLSR_LOG_DEBUG("Expressing Interest: " << interestName
                 << (isReciprocal ? " (reciprocal)" : ""));
  ndn::Interest interest(interestName);
  interest.setInterestLifetime(ndn::time::seconds(seconds));
  interest.setMustBeFresh(true);
  interest.setCanBePrefix(true);
  m_face.expressInterest(interest,
    [this, isReciprocal] (const auto& interest, const auto& data) {
      onContent(interest, data, isReciprocal);
    },
    [this, seconds, isReciprocal] (const auto& interest, const auto& nack) {
      NDN_LOG_TRACE("Received Nack with reason: " << nack.getReason());
      NDN_LOG_TRACE("Will treat as timeout in " << 2 * seconds << " seconds");
      m_scheduler.schedule(ndn::time::seconds(2 * seconds),
        [this, interest, isReciprocal] { processInterestTimedOut(interest, isReciprocal); });
    },
    [this, isReciprocal] (const auto& interest) {
      processInterestTimedOut(interest, isReciprocal);
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
    // Periodic Hello: not reciprocal; must not request immediate Adj-LSA build.
    expressInterest(interestName, m_confParam.getInterestResendTime(), false);
    NLSR_LOG_DEBUG("Sending HELLO interest: " << interestName);
  }

  m_scheduler.schedule(ndn::time::seconds(m_confParam.getInfoInterestInterval()),
                       [this, neighbor] { sendHelloInterest(neighbor); });
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
    // If this neighbor was previously inactive, send our own hello interest, too
    if (adjacent->getStatus() == Adjacent::STATUS_INACTIVE) {
      // We can only do that if the neighbor currently has a face.
      if (adjacent->getFaceId() != 0) {
        // Incoming Hello is only a reachability hint; this reciprocal Interest
        // performs the ordinary verification. Mark the flow so a validated
        // success may skip adj-lsa-build-interval when result-driven build is on.
        expressInterest(makeHelloInterestName(neighbor),
                        m_confParam.getInterestResendTime(), true);
      }
    }
  }
}

void
HelloProtocol::processInterestTimedOut(const ndn::Interest& interest, bool isReciprocal)
{
  // interest name: /<neighbor>/NLSR/INFO/<router>
  const ndn::Name interestName(interest.getName());
  NLSR_LOG_DEBUG("Interest timed out for Name: " << interestName);
  if (interestName.get(-2).toUri() != INFO_COMPONENT) {
    return;
  }
  ndn::Name neighbor = interestName.getPrefix(-3);
  NLSR_LOG_DEBUG("Neighbor: " << neighbor);
  m_adjacencyList.incrementTimedOutInterestCount(neighbor);

  Adjacent::Status status = m_adjacencyList.getStatusOfNeighbor(neighbor);

  uint32_t infoIntTimedOutCount = m_adjacencyList.getTimedOutInterestCount(neighbor);
  NLSR_LOG_DEBUG("Status: " << status);
  NLSR_LOG_DEBUG("Info Interest Timed out: " << infoIntTimedOutCount);
  if (infoIntTimedOutCount < m_confParam.getInterestRetryNumber()) {
    // The retry continues the same physical Hello flow, so it keeps isReciprocal.
    auto retryName = makeHelloInterestName(neighbor);
    NLSR_LOG_DEBUG("Resending interest: " << retryName);
    expressInterest(retryName, m_confParam.getInterestResendTime(), isReciprocal);
  }
  else if (status == Adjacent::STATUS_ACTIVE) {
    m_adjacencyList.setStatusOfNeighbor(neighbor, Adjacent::STATUS_INACTIVE);

    NLSR_LOG_DEBUG("Neighbor: " << neighbor << " status changed to INACTIVE");

    if (m_confParam.getHyperbolicState() == HYPERBOLIC_STATE_ON) {
      m_routingTable.scheduleRoutingTableCalculation();
    }
    else {
      m_lsdb.scheduleAdjLsaBuild();
    }
  }
}

// This is the first function that incoming Hello data will
// see. This checks if the data appears to be signed, and passes it
// on to validate the content of the data.
void
HelloProtocol::onContent(const ndn::Interest& interest, const ndn::Data& data,
                         bool isReciprocal)
{
  NLSR_LOG_DEBUG("Received data for INFO(name): " << data.getName());
  auto kl = data.getKeyLocator();
  if (kl && kl->getType() == ndn::tlv::Name) {
    NLSR_LOG_DEBUG("Data signed with: " << kl->getName());
  }
  m_confParam.getValidator().validate(data,
                                      [this, isReciprocal] (const auto& validatedData) {
                                        onContentValidated(validatedData, isReciprocal);
                                      },
                                      [this] (const auto& rejectedData, const auto& ve) {
                                        onContentValidationFailed(rejectedData, ve);
                                      });
}

void
HelloProtocol::onContentValidated(const ndn::Data& data, bool isReciprocal)
{
  // data name: /<neighbor>/NLSR/INFO/<router>/<version>
  ndn::Name dataName = data.getName();
  NLSR_LOG_DEBUG("Data validation successful for INFO(name): " << dataName);

  if (dataName.get(-3).toUri() == INFO_COMPONENT) {
    ndn::Name neighbor = dataName.getPrefix(-4);

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

    // Only an incoming-Hello-triggered reciprocal success may replace the fixed
    // adj-lsa-build-interval wait. Periodic Hello successes never take this path.
    // Call after the vanilla status update so a concurrent periodic Hello that
    // already dirtied the Adj-LSA can still be upgraded to an immediate build when
    // the reciprocal Data arrives with no further status delta.
    if (isReciprocal &&
        m_confParam.getResultDrivenAdjLsaBuild() &&
        m_confParam.getHyperbolicState() != HYPERBOLIC_STATE_ON) {
      NLSR_LOG_DEBUG("Reciprocal Hello validated for " << neighbor
                     << "; requesting immediate Adjacency LSA build if dirty");
      m_lsdb.requestImmediateAdjLsaBuild();
    }
  }
  // increment RCV_HELLO_DATA
  hpIncrementSignal(Statistics::PacketType::RCV_HELLO_DATA);
}

void
HelloProtocol::onContentValidationFailed(const ndn::Data& data,
                                         const ndn::security::ValidationError& ve)
{
  NLSR_LOG_DEBUG("Validation error: " << ve);
}

} // namespace nlsr
